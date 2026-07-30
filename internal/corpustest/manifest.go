// Package corpustest discovers, validates, and executes the deterministic,
// offline test corpus under testdata/corpus against the real CredScope
// pipeline. It intentionally re-uses production packages (config, ingest,
// analysis, reporters) rather than re-implementing analysis behavior.
package corpustest

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/rules"
	"gopkg.in/yaml.v3"
)

// CurrentManifestSchemaVersion is the only case.yaml schema version accepted
// today. Bump it, and add explicit migration handling, before changing the
// manifest shape in an incompatible way.
const CurrentManifestSchemaVersion = 1

const maxManifestSize = 1 << 20 // 1 MiB; manifests are small, hand-authored documents.

// Category is the top-level corpus grouping. Its string value must match the
// directory name the case lives under.
type Category string

const (
	CategoryGitleaks      Category = "gitleaks"
	CategoryGitHubActions Category = "github-actions"
	CategoryCompose       Category = "compose"
	CategoryIntegrated    Category = "integrated"
)

func knownCategories() []Category {
	return []Category{CategoryGitleaks, CategoryGitHubActions, CategoryCompose, CategoryIntegrated}
}

// ExpectResult is what the case asserts about the pipeline outcome.
type ExpectResult string

const (
	ExpectSuccess ExpectResult = "success"
	ExpectError   ExpectResult = "error"
)

var caseIDPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Manifest is the case.yaml schema. Field names are load-bearing: they are
// part of the corpus's documented, machine-readable contract.
type Manifest struct {
	SchemaVersion int          `yaml:"schema_version"`
	ID            string       `yaml:"id"`
	Title         string       `yaml:"title"`
	Description   string       `yaml:"description"`
	Category      Category     `yaml:"category"`
	Inputs        CaseInputs   `yaml:"inputs"`
	Config        CaseConfig   `yaml:"config"`
	Expect        CaseExpect   `yaml:"expect"`
	Covers        CaseCoverage `yaml:"covers"`
	Tags          []string     `yaml:"tags"`
	Canaries      []string     `yaml:"forbidden_output_strings"`
	Notes         string       `yaml:"notes"`
}

type CaseInputs struct {
	// Repository is a case-relative directory scanned as the repository root.
	Repository string `yaml:"repository"`
	// Gitleaks is an optional case-relative path to an imported Gitleaks JSON report.
	Gitleaks string `yaml:"gitleaks"`
	// AlternateRepository is optional: a second, semantically-identical
	// repository directory (e.g. differently ordered YAML maps) used only by
	// determinism regression cases to assert byte-identical analysis output.
	AlternateRepository string `yaml:"alternate_repository"`
}

type CaseConfig struct {
	// Profile overrides config.Default().Profile. Ignored when ConfigFile is set.
	Profile string `yaml:"profile"`
	// ConfigFile is an optional case-relative path to a .credscope.yml loaded
	// through the real config.Load validation path.
	ConfigFile string `yaml:"config_file"`
}

type CaseExpect struct {
	Result ExpectResult `yaml:"result"`
	// ErrorContains is required when Result is "error": a case-insensitive
	// substring the pipeline error message must contain.
	ErrorContains string `yaml:"error_contains"`
}

type CaseCoverage struct {
	Rules    []string `yaml:"rules"`
	Evidence []string `yaml:"evidence"`
	Edges    []string `yaml:"edges"`
}

// Case pairs a parsed, validated Manifest with its on-disk location.
type Case struct {
	ID   string
	Dir  string // absolute path to the case directory
	Path string // absolute path to case.yaml, for error messages
	Manifest
}

// LoadManifest reads and strictly decodes a case.yaml file. It does not
// validate cross-field or filesystem-dependent rules; call Validate for that.
func LoadManifest(path string) (Manifest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Manifest{}, fmt.Errorf("%s: symbolic links are not allowed", path)
	}
	if !info.Mode().IsRegular() {
		return Manifest{}, fmt.Errorf("%s: not a regular file", path)
	}
	if info.Size() > maxManifestSize {
		return Manifest{}, fmt.Errorf("%s: exceeds %d bytes", path, maxManifestSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read %s: %w", path, err)
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return Manifest{}, fmt.Errorf("parse %s: multiple YAML documents are not allowed", path)
	}
	return manifest, nil
}

// Validate enforces the case.yaml contract described in docs/TEST_CORPUS.md.
// dir is the absolute case directory the manifest was loaded from; category
// is the directory-derived category the manifest's own Category must match.
//
// Validate checks only structural, filter-independent safety: schema
// version, ID shape, category, confined paths, symlink rejection, canary
// declarations, and (for controlled-error cases) the absence of golden
// files. It deliberately does NOT require expected.json/expected.sarif to
// exist for success cases — that is a post-selection concern enforced by
// RequireGoldens once the -case filter (if any) has been applied, so that
// discovery and structural validation stay global while golden-file
// requirements stay scoped to whatever was actually selected to run.
func (m Manifest) Validate(dir string, category Category) error {
	if m.SchemaVersion != CurrentManifestSchemaVersion {
		return fmt.Errorf("unsupported schema_version %d (expected %d)", m.SchemaVersion, CurrentManifestSchemaVersion)
	}
	if !caseIDPattern.MatchString(m.ID) {
		return fmt.Errorf("id %q must be lowercase kebab-case", m.ID)
	}
	if filepath.Base(dir) != m.ID {
		return fmt.Errorf("id %q must match directory name %q", m.ID, filepath.Base(dir))
	}
	if strings.TrimSpace(m.Title) == "" {
		return fmt.Errorf("title must not be empty")
	}
	if strings.TrimSpace(m.Description) == "" {
		return fmt.Errorf("description must not be empty")
	}
	if m.Category != category {
		return fmt.Errorf("category %q must match parent directory category %q", m.Category, category)
	}
	if !containsCategory(knownCategories(), m.Category) {
		return fmt.Errorf("unknown category %q", m.Category)
	}

	if err := validateRelativePath("inputs.repository", m.Inputs.Repository, dir, true); err != nil {
		return err
	}
	if m.Inputs.Gitleaks != "" {
		if err := validateRelativePath("inputs.gitleaks", m.Inputs.Gitleaks, dir, false); err != nil {
			return err
		}
	}
	if m.Inputs.AlternateRepository != "" {
		if err := validateRelativePath("inputs.alternate_repository", m.Inputs.AlternateRepository, dir, true); err != nil {
			return err
		}
	}
	if m.Config.ConfigFile != "" {
		if err := validateRelativePath("config.config_file", m.Config.ConfigFile, dir, false); err != nil {
			return err
		}
		if m.Config.Profile != "" {
			return fmt.Errorf("config.profile and config.config_file are mutually exclusive")
		}
	}
	if m.Config.Profile != "" && !containsString([]string{"auto", "local", "ci", "staging", "production"}, m.Config.Profile) {
		return fmt.Errorf("config.profile %q must be one of auto, local, ci, staging, production", m.Config.Profile)
	}

	switch m.Expect.Result {
	case ExpectSuccess:
		if m.Expect.ErrorContains != "" {
			return fmt.Errorf("expect.error_contains must be empty when expect.result is success")
		}
	case ExpectError:
		if strings.TrimSpace(m.Expect.ErrorContains) == "" {
			return fmt.Errorf("expect.error_contains is required when expect.result is error")
		}
		for _, name := range []string{"expected.json", "expected.sarif"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return fmt.Errorf("expect.result is error but %s is present; controlled-error cases must not carry golden outputs", name)
			}
		}
	default:
		return fmt.Errorf("expect.result must be %q or %q, got %q", ExpectSuccess, ExpectError, m.Expect.Result)
	}

	for _, id := range m.Covers.Rules {
		if _, ok := rules.ByID(id); !ok {
			return fmt.Errorf("covers.rules references unknown rule %q", id)
		}
	}
	for _, kind := range m.Covers.Evidence {
		if !containsString(knownEvidenceKinds(), kind) {
			return fmt.Errorf("covers.evidence references unknown evidence kind %q", kind)
		}
	}
	for _, edge := range m.Covers.Edges {
		if !containsString(knownEdgeTypes(), edge) {
			return fmt.Errorf("covers.edges references unknown edge type %q", edge)
		}
	}

	if m.Inputs.Gitleaks != "" {
		hasSecretMaterial, err := gitleaksReportHasSecretOrMatch(filepath.Join(dir, filepath.FromSlash(path.Clean(filepath.ToSlash(m.Inputs.Gitleaks)))))
		if err != nil {
			return fmt.Errorf("inspect inputs.gitleaks for secret-safety declarations: %w", err)
		}
		if hasSecretMaterial && len(m.Canaries) == 0 {
			return fmt.Errorf("forbidden_output_strings must declare at least one canary because inputs.gitleaks contains a non-empty Secret or Match field")
		}
	}
	for _, canary := range m.Canaries {
		if strings.TrimSpace(canary) == "" {
			return fmt.Errorf("forbidden_output_strings must not contain an empty value")
		}
		if !strings.Contains(strings.ToUpper(canary), "CANARY") {
			return fmt.Errorf("forbidden_output_string %q does not look like a CREDSCOPE_TEST_CANARY_* marker", canary)
		}
	}

	for _, tag := range m.Tags {
		if strings.TrimSpace(tag) == "" {
			return fmt.Errorf("tags must not contain an empty value")
		}
	}
	return nil
}

// validateRelativePath rejects absolute paths, backslashes-as-separators,
// parent traversal, and any path that escapes the case directory once
// resolved. When mustExist is true the target must already exist on disk.
//
// Absolute-path detection is done with an explicit, manual backslash
// normalization (mirroring internal/config's validatePathPrefix) rather
// than filepath.ToSlash/IsAbs/VolumeName: those are GOOS-conditional and, on
// Linux, do not recognize a Windows-style drive-letter path like
// "C:\Windows\..." as absolute at all, since Linux's path separator is
// already "/". The corpus must reject such paths identically on every
// platform this test corpus (and CredScope's Linux CI) runs on.
func validateRelativePath(field, value, dir string, mustExist bool) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("%s contains a NUL byte", field)
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	windowsDrive := len(normalized) >= 3 && normalized[1] == ':' && normalized[2] == '/'
	if strings.HasPrefix(normalized, "/") || windowsDrive || path.IsAbs(normalized) || filepath.IsAbs(value) || filepath.VolumeName(value) != "" {
		return fmt.Errorf("%s %q must be case-relative, not absolute", field, value)
	}
	cleaned := path.Clean(normalized)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("%s %q escapes the case directory", field, value)
	}
	full := filepath.Join(dir, filepath.FromSlash(cleaned))
	rel, err := filepath.Rel(dir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s %q escapes the case directory", field, value)
	}
	if mustExist {
		if info, statErr := os.Lstat(full); statErr != nil {
			return fmt.Errorf("%s %q does not exist: %w", field, value, statErr)
		} else if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s %q is a symbolic link, which is not allowed", field, value)
		}
	}
	return nil
}

func knownEvidenceKinds() []string {
	return []string{
		string(domain.EvidenceConfirmedDataFlow),
		string(domain.EvidenceExposureContext),
		string(domain.EvidenceNetworkTopology),
		string(domain.EvidenceUnknownRuntime),
		string(domain.EvidenceStructuralCallOnly),
	}
}

func knownEdgeTypes() []string {
	return []string{
		string(domain.EdgeConfiguredIn), string(domain.EdgeAvailableToService), string(domain.EdgeAvailableToProcess),
		string(domain.EdgeReferencedByProcess), string(domain.EdgeMountedAsSecret), string(domain.EdgeExplicitlyForwardedTo),
		string(domain.EdgeDependsOn), string(domain.EdgeNetworkReachable), string(domain.EdgeExposesPort),
		string(domain.EdgeReadsEnvFile), string(domain.EdgeDetectedIn), string(domain.EdgeBelongsTo),
		string(domain.EdgeTriggeredBy), string(domain.EdgeHasPermission), string(domain.EdgeUsesEnvironment),
		string(domain.EdgeRunsAction), string(domain.EdgeMountsVolume), string(domain.EdgeCallsWorkflow),
	}
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func containsCategory(items []Category, value Category) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

// gitleaksReportHasSecretOrMatch does a permissive structural read (array or
// single object, matching the production adapter's decode) to check whether
// any entry declares a non-empty Secret or Match field. It is a manifest
// authoring lint, not a security boundary; malformed-report cases are
// exempt because they are never expected to reach a successful render.
func gitleaksReportHasSecretOrMatch(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	type rawEntry struct {
		Secret string `json:"Secret"`
		Match  string `json:"Match"`
	}
	trimmed := strings.TrimSpace(string(data))
	var entries []rawEntry
	switch {
	case strings.HasPrefix(trimmed, "["):
		if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
			return false, nil // malformed-report fixtures are validated by pipeline execution, not here
		}
	case strings.HasPrefix(trimmed, "{"):
		var single rawEntry
		if err := json.Unmarshal([]byte(trimmed), &single); err != nil {
			return false, nil
		}
		entries = []rawEntry{single}
	default:
		return false, nil
	}
	for _, entry := range entries {
		if entry.Secret != "" || entry.Match != "" {
			return true, nil
		}
	}
	return false, nil
}
