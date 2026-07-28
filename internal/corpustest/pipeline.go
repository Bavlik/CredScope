package corpustest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Bavlik/CredScope/internal/analysis"
	"github.com/Bavlik/CredScope/internal/config"
	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/ingest"
	"github.com/Bavlik/CredScope/internal/reporters"
	"github.com/Bavlik/CredScope/internal/reporters/jsonreport"
	"github.com/Bavlik/CredScope/internal/reporters/sarif"
)

// fixedInstant makes rendered timestamps deterministic across every corpus
// run, independent of wall-clock time or how long analysis took. Real scan
// timestamps are runtime-dependent and are explicitly not part of the
// corpus's golden-comparable contract; see docs/TEST_CORPUS.md normalization.
var fixedInstant = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	toolName    = "credscope"
	toolVersion = "corpustest"
)

// Rendered holds the two golden-comparable artifacts a successful case produces.
type Rendered struct {
	JSON  []byte
	SARIF []byte
}

// Outcome is the result of executing one corpus case against the real pipeline.
type Outcome struct {
	Rendered Rendered
	RunErr   error // set only for cases whose manifest expects a controlled error
}

// Execute copies the case's repository fixture into an isolated directory
// under workDir, runs the real ingest -> analyze -> report pipeline exactly
// as production code does, and returns either rendered golden artifacts or
// the observed pipeline error. Analysis runs twice from the same parsed
// input on every invocation (not just during explicit determinism checks)
// and Execute fails if rendering is not byte-identical both times.
func Execute(ctx context.Context, c Case, workDir string) (Outcome, error) {
	repoDir := filepath.Join(workDir, "repository")
	if err := copyTree(filepath.Join(c.Dir, c.Manifest.Inputs.Repository), repoDir); err != nil {
		return Outcome{}, fmt.Errorf("case %s: stage repository fixture: %w", c.ID, err)
	}

	cfg, err := loadCaseConfig(c)
	if err != nil {
		return Outcome{}, fmt.Errorf("case %s: load configuration: %w", c.ID, err)
	}

	gitleaksPath := ""
	if c.Manifest.Inputs.Gitleaks != "" {
		// internal/input.ReadFile resolves the report path root-confined to
		// the analyzed repository, exactly like any other discovered input,
		// so the staged copy must live inside repoDir, not beside it.
		gitleaksPath = filepath.Join(repoDir, "gitleaks-report.json")
		if err := copyFile(filepath.Join(c.Dir, c.Manifest.Inputs.Gitleaks), gitleaksPath, 0o644); err != nil {
			return Outcome{}, fmt.Errorf("case %s: stage gitleaks report: %w", c.ID, err)
		}
	}

	parsed, err := ingest.Repository(ctx, repoDir, cfg, gitleaksPath)
	if err != nil {
		return outcomeFromPipelineError(c, err)
	}

	options := analysisOptionsFromConfig(cfg)
	first, err := analysis.Analyze(ctx, parsed, options)
	if err != nil {
		return outcomeFromPipelineError(c, err)
	}
	second, err := analysis.Analyze(ctx, parsed, options)
	if err != nil {
		return Outcome{}, fmt.Errorf("case %s: analysis was non-deterministic: succeeded once, failed on repeat: %w", c.ID, err)
	}

	firstRendered, err := render(c.ID, cfg, first)
	if err != nil {
		return Outcome{}, fmt.Errorf("case %s: render analysis: %w", c.ID, err)
	}
	secondRendered, err := render(c.ID, cfg, second)
	if err != nil {
		return Outcome{}, fmt.Errorf("case %s: render repeat analysis: %w", c.ID, err)
	}
	if !bytes.Equal(firstRendered.JSON, secondRendered.JSON) {
		return Outcome{}, fmt.Errorf("case %s: JSON output was not byte-identical across two in-process analysis runs", c.ID)
	}
	if !bytes.Equal(firstRendered.SARIF, secondRendered.SARIF) {
		return Outcome{}, fmt.Errorf("case %s: SARIF output was not byte-identical across two in-process analysis runs", c.ID)
	}

	if c.Manifest.Inputs.AlternateRepository != "" {
		if err := verifyAlternateRepositoryMatches(ctx, c, cfg, options, firstRendered); err != nil {
			return Outcome{}, err
		}
	}

	if c.Manifest.Expect.Result == ExpectError {
		return Outcome{}, fmt.Errorf("case %s: expected a controlled error containing %q but analysis succeeded", c.ID, c.Manifest.Expect.ErrorContains)
	}

	return Outcome{Rendered: firstRendered}, nil
}

// outcomeFromPipelineError checks an observed ingest/analyze error against
// the manifest's error expectation. It scans the error message for declared
// canaries before ever including that message in a returned error, so a
// harness failure can never leak secret material into test output.
func outcomeFromPipelineError(c Case, err error) (Outcome, error) {
	if c.Manifest.Expect.Result != ExpectError {
		return Outcome{}, fmt.Errorf("case %s: unexpected pipeline error: %w", c.ID, err)
	}
	message := err.Error()
	if violations := scanForCanaries(c.ID, "pipeline error message", c.Manifest.Canaries, []byte(message)); len(violations) > 0 {
		return Outcome{}, fmt.Errorf("case %s: %s", c.ID, violations[0].String())
	}
	if !strings.Contains(strings.ToLower(message), strings.ToLower(c.Manifest.Expect.ErrorContains)) {
		return Outcome{}, fmt.Errorf("case %s: pipeline error %q does not contain expected substring %q", c.ID, message, c.Manifest.Expect.ErrorContains)
	}
	return Outcome{RunErr: err}, nil
}

func loadCaseConfig(c Case) (config.Config, error) {
	if c.Manifest.Config.ConfigFile != "" {
		return config.Load(filepath.Join(c.Dir, c.Manifest.Config.ConfigFile))
	}
	cfg := config.Default()
	if c.Manifest.Config.Profile != "" {
		cfg.Profile = c.Manifest.Config.Profile
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

// analysisOptionsFromConfig mirrors internal/cli/root.go's config-to-options
// conversion so corpus cases exercise the same translation production does.
func analysisOptionsFromConfig(cfg config.Config) analysis.Options {
	disabledRules := make(map[string]bool)
	for id, ruleCfg := range cfg.Rules {
		if !ruleCfg.Enabled {
			disabledRules[id] = true
		}
	}
	classifications := make(map[string]domain.Classification, len(cfg.Classifications))
	for name, value := range cfg.Classifications {
		classifications[strings.ToUpper(name)] = domain.Classification(value)
	}
	return analysis.Options{
		DisabledRules:   disabledRules,
		Profile:         domain.Profile(cfg.Profile),
		Classifications: classifications,
		IgnorePaths:     toIgnoreDirectives(cfg.Ignore.Paths),
		IgnoreVariables: toIgnoreDirectives(cfg.Ignore.Variables),
		IgnoreFindings:  toIgnoreDirectives(cfg.Ignore.Findings),
		IgnoreRules:     toIgnoreDirectives(cfg.Ignore.Rules),
	}
}

func toIgnoreDirectives(items []config.IgnoreEntry) []analysis.IgnoreDirective {
	result := make([]analysis.IgnoreDirective, 0, len(items))
	for _, item := range items {
		result = append(result, analysis.IgnoreDirective{Value: item.Value, Reason: item.Reason})
	}
	return result
}

func disabledRuleIDs(cfg config.Config) []string {
	var ids []string
	for id, ruleCfg := range cfg.Rules {
		if !ruleCfg.Enabled {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// render builds the same reporters.Input the CLI would build for a real scan,
// except for the deliberately fixed tool identity, timestamps, and repository
// label documented in docs/TEST_CORPUS.md's normalization rules.
func render(caseID string, cfg config.Config, result domain.AnalysisResult) (Rendered, error) {
	base := reporters.Input{
		Tool: reporters.Tool{Name: toolName, Version: toolVersion},
		Scan: reporters.Scan{
			Repository:        caseID,
			StartedAt:         fixedInstant,
			CompletedAt:       fixedInstant,
			FailOn:            cfg.Risk.FailOn,
			MinimumScore:      cfg.Risk.MinimumScore,
			ThresholdExceeded: reporters.ThresholdExceeded(result, cfg.Risk.FailOn, cfg.Risk.MinimumScore),
			Includes:          append([]string{}, cfg.Scan.Include...),
			Excludes:          append([]string{}, cfg.Scan.Exclude...),
			DisabledRules:     disabledRuleIDs(cfg),
			Profile:           result.Profile,
		},
		Analysis: result,
	}
	options := reporters.Options{Pretty: true}

	jsonInput := base
	jsonInput.Scan.Format = "json"
	var jsonBuf bytes.Buffer
	if err := jsonreport.New().Render(&jsonBuf, jsonInput, options); err != nil {
		return Rendered{}, fmt.Errorf("render json: %w", err)
	}

	sarifInput := base
	sarifInput.Scan.Format = "sarif"
	var sarifBuf bytes.Buffer
	if err := sarif.New().Render(&sarifBuf, sarifInput, options); err != nil {
		return Rendered{}, fmt.Errorf("render sarif: %w", err)
	}

	return Rendered{JSON: jsonBuf.Bytes(), SARIF: sarifBuf.Bytes()}, nil
}

// verifyAlternateRepositoryMatches proves that reordering YAML mapping keys
// (a purely syntactic change) does not change semantic analysis output. It
// is only invoked for cases that declare inputs.alternate_repository.
func verifyAlternateRepositoryMatches(ctx context.Context, c Case, cfg config.Config, options analysis.Options, primary Rendered) error {
	workDir, err := os.MkdirTemp("", "credscope-corpus-alt-*")
	if err != nil {
		return fmt.Errorf("case %s: create alternate working directory: %w", c.ID, err)
	}
	defer os.RemoveAll(workDir)

	repoDir := filepath.Join(workDir, "repository")
	if err := copyTree(filepath.Join(c.Dir, c.Manifest.Inputs.AlternateRepository), repoDir); err != nil {
		return fmt.Errorf("case %s: stage alternate repository: %w", c.ID, err)
	}
	gitleaksPath := ""
	if c.Manifest.Inputs.Gitleaks != "" {
		gitleaksPath = filepath.Join(repoDir, "gitleaks-report.json")
		if err := copyFile(filepath.Join(c.Dir, c.Manifest.Inputs.Gitleaks), gitleaksPath, 0o644); err != nil {
			return fmt.Errorf("case %s: stage gitleaks report for alternate repository: %w", c.ID, err)
		}
	}
	parsed, err := ingest.Repository(ctx, repoDir, cfg, gitleaksPath)
	if err != nil {
		return fmt.Errorf("case %s: alternate repository failed to ingest: %w", c.ID, err)
	}
	analyzed, err := analysis.Analyze(ctx, parsed, options)
	if err != nil {
		return fmt.Errorf("case %s: alternate repository failed to analyze: %w", c.ID, err)
	}
	rendered, err := render(c.ID, cfg, analyzed)
	if err != nil {
		return fmt.Errorf("case %s: render alternate repository: %w", c.ID, err)
	}
	// Reordering YAML mapping keys legitimately changes which source line
	// each key ends up on. Location.Line and every content-addressed hash ID
	// derived from it (node IDs, edge IDs, evidence path IDs) therefore
	// legitimately differ between the two fixtures even though nothing
	// semantic changed. Comparing rendered bytes directly would conflate
	// "moved to a different line" with "different behavior", so this check
	// instead compares a semantic projection: per-credential classification,
	// score, severity, and matched rule IDs. That is the behavior this
	// case exists to protect; exact evidence-location byte equality is
	// covered separately by the ordinary golden comparison against
	// repository/'s own committed expected.json/expected.sarif.
	primaryCredentials, err := semanticCredentials(primary.JSON)
	if err != nil {
		return fmt.Errorf("case %s: project primary JSON: %w", c.ID, err)
	}
	alternateCredentials, err := semanticCredentials(rendered.JSON)
	if err != nil {
		return fmt.Errorf("case %s: project alternate JSON: %w", c.ID, err)
	}
	if !reflect.DeepEqual(primaryCredentials, alternateCredentials) {
		return fmt.Errorf("case %s: alternate-ordering repository produced different credential classification, score, severity, or matched rules; YAML map ordering must not change semantic output", c.ID)
	}
	return nil
}

// semanticCredential is the subset of a rendered credential that must be
// identical regardless of incidental source YAML key ordering. It
// deliberately excludes IDs, fingerprints, and evidence locations, which are
// legitimately line-position-sensitive.
type semanticCredential struct {
	Label                string
	Classification       string
	ClassificationReason string
	ClassificationSource string
	ExpectedSecret       bool
	Score                int
	Severity             string
	MatchedRuleIDs       []string
}

func semanticCredentials(jsonBytes []byte) ([]semanticCredential, error) {
	var doc struct {
		Credentials []struct {
			Credential struct {
				Label                string `json:"label"`
				Classification       string `json:"classification"`
				ClassificationReason string `json:"classification_reason"`
				ClassificationSource string `json:"classification_source"`
				ExpectedSecret       bool   `json:"expected_secret"`
			} `json:"credential"`
			Score        int    `json:"score"`
			Severity     string `json:"severity"`
			MatchedRules []struct {
				RuleID string `json:"rule_id"`
			} `json:"matched_rules"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		return nil, err
	}
	result := make([]semanticCredential, 0, len(doc.Credentials))
	for _, item := range doc.Credentials {
		ruleIDs := make([]string, 0, len(item.MatchedRules))
		for _, match := range item.MatchedRules {
			ruleIDs = append(ruleIDs, match.RuleID)
		}
		sort.Strings(ruleIDs)
		result = append(result, semanticCredential{
			Label:                item.Credential.Label,
			Classification:       item.Credential.Classification,
			ClassificationReason: item.Credential.ClassificationReason,
			ClassificationSource: item.Credential.ClassificationSource,
			ExpectedSecret:       item.Credential.ExpectedSecret,
			Score:                item.Score,
			Severity:             item.Severity,
			MatchedRuleIDs:       ruleIDs,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Label < result[j].Label })
	return result, nil
}
