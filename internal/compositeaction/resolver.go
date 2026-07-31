// Package compositeaction resolves repository-local composite-action
// references found in already-parsed workflow steps against the
// repository's filesystem. It owns all filesystem access and action-metadata
// parsing this resolution requires; the caller (internal/ingest) attaches
// its immutable result to domain.ParsedRepository, and every downstream
// consumer (internal/analysis, internal/graph) never touches the filesystem
// itself.
//
// Resolve never recurses into a resolved composite action's own
// runs.steps[*].uses references — nested composite-action resolution is an
// explicitly later phase.
package compositeaction

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Bavlik/CredScope/internal/discovery"
	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/parsers/githubactions"
)

var driveLetterPattern = regexp.MustCompile(`^[A-Za-z]:`)

// pendingLocal defers the actual filesystem work for one call site until
// after every call has been classified, so each unique canonical directory
// can be resolved (and its metadata parsed) exactly once, regardless of how
// many call sites reference it.
type pendingLocal struct {
	callIndex int
	directory string
}

// Resolve resolves every workflow-step `uses:` action reference in workflows
// against the repository confined by finder, using parser to parse any
// resolved local composite action's metadata. It reads workflows and never
// mutates them, and returns a wholly independent, freshly allocated result on
// every call: two separate Resolve invocations never share backing arrays or
// a canonical ActionMetadata's nested slices.
//
// Resolve returns a non-nil error only for a fatal condition unrelated to any
// individual reference's outcome: context cancellation, or an unexpected
// infrastructure failure. Every per-reference problem (an unsafe path,
// missing metadata, malformed YAML, and so on) is recorded as a
// CompositeActionCall status, never as a returned error, so one malformed
// reference never prevents any other reference from resolving.
func Resolve(ctx context.Context, finder *discovery.Finder, parser *githubactions.Parser, workflows []domain.Workflow) (domain.CompositeActionResolution, error) {
	if err := ctx.Err(); err != nil {
		return domain.CompositeActionResolution{}, err
	}

	var calls []domain.CompositeActionCall
	var pending []pendingLocal

	for _, wf := range workflows {
		for _, job := range wf.Jobs {
			for stepIndex, step := range job.Steps {
				if err := ctx.Err(); err != nil {
					return domain.CompositeActionResolution{}, err
				}
				if step.Action == nil {
					continue
				}
				call := domain.CompositeActionCall{
					CallerWorkflow:  wf.File,
					CallerJobID:     job.ID,
					CallerStepIndex: stepIndex,
					CallerStepID:    step.ID,
					RawReference:    step.Action.Reference,
					Evidence:        step.Action.Evidence,
				}
				raw := step.Action.Reference
				switch {
				case strings.Contains(raw, "${{"):
					// Expression classification runs before any other
					// classification: a raw value cannot be reliably judged
					// docker, local, or external while it still contains an
					// unresolved GitHub expression.
					call.Status = domain.CompositeActionUnsupportedExpression
				case strings.HasPrefix(raw, "docker://"):
					call.Status = domain.CompositeActionOpaqueDocker
				case isLocalAttempt(raw):
					normalized, reason, ok := validateLocalPath(raw)
					if !ok {
						call.Status = domain.CompositeActionRejectedPath
						call.Reason = reason
						break
					}
					call.CanonicalDirectory = normalized
					calls = append(calls, call)
					pending = append(pending, pendingLocal{callIndex: len(calls) - 1, directory: normalized})
					continue
				default:
					call.Status = domain.CompositeActionOpaqueExternal
				}
				calls = append(calls, call)
			}
		}
	}

	directories := uniqueSortedDirectories(pending)
	outcomes := make(map[string]directoryOutcome, len(directories))
	for _, dir := range directories {
		if err := ctx.Err(); err != nil {
			return domain.CompositeActionResolution{}, err
		}
		outcomes[dir] = resolveDirectory(ctx, finder, parser, dir)
	}

	for _, p := range pending {
		outcome := outcomes[p.directory]
		calls[p.callIndex].Status = outcome.status
		calls[p.callIndex].Reason = outcome.reason
		calls[p.callIndex].MetadataFile = outcome.metadataFile
	}

	var actions []domain.ActionMetadata
	for _, dir := range directories {
		if outcome := outcomes[dir]; outcome.status == domain.CompositeActionResolvedLocalComposite {
			actions = append(actions, outcome.action)
		}
	}

	sort.Slice(calls, func(i, j int) bool { return lessCall(calls[i], calls[j]) })
	sort.Slice(actions, func(i, j int) bool { return actions[i].Directory < actions[j].Directory })

	return domain.CompositeActionResolution{Actions: actions, Calls: calls}, nil
}

func uniqueSortedDirectories(pending []pendingLocal) []string {
	seen := make(map[string]bool, len(pending))
	directories := make([]string, 0, len(pending))
	for _, p := range pending {
		if !seen[p.directory] {
			seen[p.directory] = true
			directories = append(directories, p.directory)
		}
	}
	sort.Strings(directories)
	return directories
}

// directoryOutcome is the once-computed resolution outcome for one unique
// canonical directory, shared read-only across every call site that
// references it.
type directoryOutcome struct {
	status       domain.CompositeActionResolutionStatus
	reason       string
	metadataFile string
	action       domain.ActionMetadata
}

// resolveDirectory performs the actual filesystem work for one canonical
// directory: confined directory resolution, safe metadata-file selection,
// and (for exactly one safe candidate) parsing. It is invoked at most once
// per unique canonical directory per Resolve call.
func resolveDirectory(ctx context.Context, finder *discovery.Finder, parser *githubactions.Parser, directory string) directoryOutcome {
	resolvedDir, err := finder.ResolveDirectory(directory)
	if err != nil {
		// A syntactically valid, confined reference whose target simply does
		// not exist (including a directory-component case mismatch on a
		// case-insensitive host filesystem, which Finder.ResolveDirectory
		// itself now reports as fs.ErrNotExist) is metadata_missing, not
		// rejected_path: the path shape was fine, the repository just does
		// not contain that directory under that exact name. Every other
		// ResolveDirectory failure (a symlink/reparse-point component, an
		// escape outside the repository root, or a non-directory target)
		// does not satisfy fs.ErrNotExist and remains rejected_path.
		if errors.Is(err, fs.ErrNotExist) {
			return directoryOutcome{status: domain.CompositeActionMetadataMissing, reason: "directory_not_found"}
		}
		return directoryOutcome{status: domain.CompositeActionRejectedPath, reason: "directory_resolution_failed: " + err.Error()}
	}

	ymlState, err := finder.StatMetadataCandidate(resolvedDir, "action.yml")
	if err != nil {
		return directoryOutcome{status: domain.CompositeActionRejectedPath, reason: "inspect_action_yml_failed: " + err.Error()}
	}
	yamlState, err := finder.StatMetadataCandidate(resolvedDir, "action.yaml")
	if err != nil {
		return directoryOutcome{status: domain.CompositeActionRejectedPath, reason: "inspect_action_yaml_failed: " + err.Error()}
	}

	switch {
	case ymlState == discovery.CandidateUnsafe || yamlState == discovery.CandidateUnsafe:
		// A symlink/reparse-point/non-regular candidate is rejected even
		// when the other filename is a safe, regular file: the unsafe
		// sibling is never silently ignored.
		return directoryOutcome{status: domain.CompositeActionRejectedPath, reason: "unsafe_metadata_candidate"}
	case ymlState == discovery.CandidateSafeRegular && yamlState == discovery.CandidateSafeRegular:
		return directoryOutcome{status: domain.CompositeActionMetadataAmbiguous}
	case ymlState == discovery.CandidateAbsent && yamlState == discovery.CandidateAbsent:
		return directoryOutcome{status: domain.CompositeActionMetadataMissing}
	}

	filename := "action.yml"
	if yamlState == discovery.CandidateSafeRegular {
		filename = "action.yaml"
	}
	relFile := path.Join(directory, filename)
	metadata, err := parser.ParseActionMetadata(ctx, finder.Root(), relFile)
	if err != nil {
		return directoryOutcome{status: domain.CompositeActionMalformedMetadata, metadataFile: filename, reason: err.Error()}
	}
	if metadata.Runs.Using != "composite" {
		return directoryOutcome{status: domain.CompositeActionTargetNotComposite, metadataFile: filename}
	}
	return directoryOutcome{status: domain.CompositeActionResolvedLocalComposite, metadataFile: filename, action: metadata}
}

// isLocalAttempt reports whether raw could only ever be intended as a local
// filesystem-shaped reference, as opposed to an owner/repository external
// reference, so it must be strictly validated by validateLocalPath rather
// than treated as opaque_external. It deliberately does not rely on
// domain.ActionReference.Local, which the workflow parser's classifyAction
// sets only for a strict "./" prefix: an unsafe local-looking value such as
// "../action" or a Windows-style path must still be routed here, not
// silently treated as an external owner/repository reference.
func isLocalAttempt(raw string) bool {
	switch {
	case strings.HasPrefix(raw, "./"):
		return true
	case strings.HasPrefix(raw, "../"):
		return true
	case strings.HasPrefix(raw, "/"):
		return true
	case strings.HasPrefix(raw, "//"):
		return true
	case strings.Contains(raw, "\\"):
		return true
	case driveLetterPattern.MatchString(raw):
		return true
	}
	return false
}

// validateLocalPath accepts only a "./"-prefixed, repository-relative
// directory reference: no parent traversal, no absolute/drive-letter/UNC
// form, no backslash, no NUL byte, no query or fragment suffix, and no
// direct action.yml/action.yaml reference. On success it returns the
// normalized, case-preserved, forward-slash canonical directory — "." for
// the repository root itself ("./"). Repeated separators and a trailing
// slash are normalized away; case is never folded.
func validateLocalPath(raw string) (normalized, reason string, ok bool) {
	switch {
	case strings.ContainsRune(raw, 0):
		return "", "nul_byte", false
	case strings.Contains(raw, "\\"):
		return "", "backslash_in_path", false
	case strings.HasPrefix(raw, "//"):
		return "", "unc_path", false
	case driveLetterPattern.MatchString(raw):
		return "", "drive_letter_path", false
	case strings.HasPrefix(raw, "/"):
		return "", "absolute_path", false
	case strings.ContainsAny(raw, "?#"):
		return "", "query_or_fragment_suffix", false
	case !strings.HasPrefix(raw, "./"):
		return "", "not_relative_local_path", false
	}

	rest := raw[len("./"):]
	if rest == "" {
		return ".", "", true
	}
	// Traversal rejection is component-based, not a substring match: a
	// component must equal ".." exactly to be traversal. A legitimate name
	// that merely contains two dots (e.g. "release..candidate", "..hidden",
	// "v1.0..next") is never rejected.
	for _, part := range strings.Split(rest, "/") {
		if part == ".." {
			return "", "parent_traversal", false
		}
	}

	cleaned := path.Clean(rest)
	if cleaned == "." {
		return ".", "", true
	}

	base := path.Base(cleaned)
	if base == "action.yml" || base == "action.yaml" {
		return "", "direct_metadata_file_reference", false
	}

	return cleaned, "", true
}

func lessCall(a, b domain.CompositeActionCall) bool {
	if a.CallerWorkflow != b.CallerWorkflow {
		return a.CallerWorkflow < b.CallerWorkflow
	}
	if a.CallerJobID != b.CallerJobID {
		return a.CallerJobID < b.CallerJobID
	}
	return a.CallerStepIndex < b.CallerStepIndex
}
