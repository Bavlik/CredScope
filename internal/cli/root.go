package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Bavlik/CredScope/internal/analysis"
	"github.com/Bavlik/CredScope/internal/config"
	"github.com/Bavlik/CredScope/internal/discovery"
	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/ingest"
	"github.com/Bavlik/CredScope/internal/reporters"
	htmlreport "github.com/Bavlik/CredScope/internal/reporters/html"
	jsonreport "github.com/Bavlik/CredScope/internal/reporters/jsonreport"
	mermaidreport "github.com/Bavlik/CredScope/internal/reporters/mermaid"
	sarifreport "github.com/Bavlik/CredScope/internal/reporters/sarif"
	terminalreport "github.com/Bavlik/CredScope/internal/reporters/terminal"
	"github.com/Bavlik/CredScope/internal/rules"
	"github.com/Bavlik/CredScope/internal/safefile"
	"github.com/Bavlik/CredScope/internal/sanitizer"
	"github.com/spf13/cobra"
)

const productName = "CredScope"

// BuildInfo is populated by release linker flags.
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Execute runs the CLI and maps errors onto the documented process exit codes.
func Execute(info BuildInfo) int {
	cmd := NewRootCommand(info, os.Stdout, os.Stderr)
	if err := cmd.Execute(); err != nil {
		var coded *codedError
		if errors.As(err, &coded) {
			if !coded.silent {
				fmt.Fprintf(os.Stderr, "credscope: %s\n", sanitizer.TerminalText(err.Error()))
			}
			return coded.code
		}
		fmt.Fprintf(os.Stderr, "credscope: %s\n", sanitizer.TerminalText(err.Error()))
		return ExitUsage
	}
	return ExitOK
}

// NewRootCommand creates a command tree without global mutable state, which keeps
// embedding and tests deterministic.
func NewRootCommand(info BuildInfo, stdout, stderr io.Writer) *cobra.Command {
	return newRootCommand(info, stdout, stderr, time.Now)
}

func newRootCommand(info BuildInfo, stdout, stderr io.Writer, clock func() time.Time) *cobra.Command {
	root := &cobra.Command{
		Use:           "credscope",
		Short:         "Analyze static credential exposure and reachability",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(newScanCommand(info, clock), newVersionCommand(info), newRulesCommand(), newExplainCommand())
	return root
}

type scanOptions struct {
	configPath         string
	gitleaksPath       string
	format             string
	output             string
	failOn             string
	minimumScore       int
	include            []string
	exclude            []string
	noColor            bool
	quiet              bool
	verbose            bool
	profile            string
	gitleaksPathPrefix string
}

func newScanCommand(info BuildInfo, clock func() time.Time) *cobra.Command {
	var opts scanOptions
	cmd := &cobra.Command{
		Use:   "scan [repository]",
		Short: "Analyze static credential exposure and produce a report",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}
			return runScan(cmd, root, opts, info, clock)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.gitleaksPath, "gitleaks-report", "", "path to a Gitleaks JSON report")
	f.StringVar(&opts.gitleaksPathPrefix, "gitleaks-path-prefix", "", "exact absolute scanner path prefix to strip from Gitleaks finding paths")
	f.StringVar(&opts.profile, "profile", "auto", "environment profile: auto, local, ci, staging, or production")
	f.StringVarP(&opts.format, "format", "f", "terminal", "report format: terminal, json, sarif, html, or mermaid")
	f.StringVarP(&opts.output, "output", "o", "", "write report to path")
	f.StringVar(&opts.failOn, "fail-on", "none", "failure threshold: none, informational, low, medium, high, or critical")
	f.IntVar(&opts.minimumScore, "minimum-score", 0, "minimum score to report (0-100)")
	f.StringSliceVar(&opts.include, "include", nil, "additional repository-relative include pattern")
	f.StringSliceVar(&opts.exclude, "exclude", nil, "repository-relative exclude pattern")
	f.StringVar(&opts.configPath, "config", "", "configuration file (default: .credscope.yml when present)")
	f.BoolVar(&opts.noColor, "no-color", false, "disable colored terminal output")
	f.BoolVarP(&opts.quiet, "quiet", "q", false, "suppress non-result output")
	f.BoolVarP(&opts.verbose, "verbose", "v", false, "show detailed evidence")
	return cmd
}

func runScan(cmd *cobra.Command, root string, opts scanOptions, info BuildInfo, clock func() time.Time) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return &codedError{code: ExitUsage, err: fmt.Errorf("resolve repository root: %w", err)}
	}

	cfgPath := opts.configPath
	if cfgPath == "" {
		candidate := filepath.Join(absRoot, config.DefaultFilename)
		if _, statErr := os.Stat(candidate); statErr == nil {
			cfgPath = candidate
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return &codedError{code: ExitUsage, err: fmt.Errorf("inspect default configuration: %w", statErr)}
		}
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return &codedError{code: ExitUsage, err: err}
	}
	applyCLIOverrides(cmd, &cfg, opts)
	if err := cfg.Validate(); err != nil {
		return &codedError{code: ExitUsage, err: err}
	}
	selectedReporter, err := reporterFor(cfg.Output.Format)
	if err != nil {
		return &codedError{code: ExitUsage, err: err}
	}
	started := clock().UTC()

	finder, err := discovery.New(absRoot, discovery.Options{
		Includes: cfg.Scan.Include,
		Excludes: cfg.Scan.Exclude,
	})
	if err != nil {
		return &codedError{code: ExitUsage, err: err}
	}
	files, err := finder.Find()
	if err != nil {
		return &codedError{code: ExitMalformedInput, err: err}
	}

	resolvedGitleaks := ""
	if opts.gitleaksPath != "" {
		resolved, resolveErr := finder.ResolveFile(opts.gitleaksPath)
		if resolveErr != nil {
			return &codedError{code: ExitMalformedInput, err: fmt.Errorf("gitleaks report: %w", resolveErr)}
		}
		files = append(files, discovery.File{Path: resolved, Kind: discovery.KindGitleaks})
		files = discovery.UniqueFiles(files)
		resolvedGitleaks = resolved
	}

	parsed, err := ingest.Repository(cmd.Context(), absRoot, cfg, resolvedGitleaks)
	if err != nil {
		return &codedError{code: ExitMalformedInput, err: err}
	}

	disabledRules := make(map[string]bool)
	disabledRuleIDs := make([]string, 0)
	for id, ruleConfig := range cfg.Rules {
		if !ruleConfig.Enabled {
			disabledRules[id] = true
			disabledRuleIDs = append(disabledRuleIDs, id)
		}
	}
	sort.Strings(disabledRuleIDs)
	classifications := make(map[string]domain.Classification, len(cfg.Classifications))
	for name, value := range cfg.Classifications {
		classifications[strings.ToUpper(name)] = domain.Classification(value)
	}
	analyzed, err := analysis.Analyze(cmd.Context(), parsed, analysis.Options{DisabledRules: disabledRules, Profile: domain.Profile(cfg.Profile), Classifications: classifications, IgnorePaths: ignoreDirectives(cfg.Ignore.Paths), IgnoreVariables: ignoreDirectives(cfg.Ignore.Variables), IgnoreFindings: ignoreDirectives(cfg.Ignore.Findings), IgnoreRules: ignoreDirectives(cfg.Ignore.Rules)})
	if err != nil {
		return &codedError{code: ExitInternal, err: fmt.Errorf("analyze repository: %w", err)}
	}
	exceeded := reporters.ThresholdExceeded(analyzed, cfg.Risk.FailOn, cfg.Risk.MinimumScore)
	completed := clock().UTC()
	repositoryName := sanitizer.TerminalText(filepath.Base(absRoot))
	if repositoryName == "" || repositoryName == "." {
		repositoryName = "repository"
	}
	input := reporters.Input{
		Tool:           reporters.Tool{Name: productName, Version: sanitizer.TerminalText(info.Version), Commit: sanitizer.TerminalText(info.Commit)},
		Scan:           reporters.Scan{Repository: repositoryName, StartedAt: started, CompletedAt: completed, FailOn: cfg.Risk.FailOn, MinimumScore: cfg.Risk.MinimumScore, Format: cfg.Output.Format, ThresholdExceeded: exceeded, Includes: append([]string{}, cfg.Scan.Include...), Excludes: append([]string{}, cfg.Scan.Exclude...), DisabledRules: disabledRuleIDs, NoColor: cfg.Output.NoColor, Quiet: cfg.Output.Quiet, Verbose: cfg.Output.Verbose, Profile: analyzed.Profile},
		Analysis:       analyzed,
		ParserWarnings: append([]domain.ParseWarning{}, parsed.Warnings...),
	}
	color := cfg.Output.Format == "terminal" && !cfg.Output.NoColor && writerIsTerminal(cmd.OutOrStdout())
	reportOptions := reporters.Options{Verbose: cfg.Output.Verbose, Quiet: cfg.Output.Quiet, Color: color, Pretty: cfg.Output.Path != ""}
	if err := selectedReporter.Validate(reportOptions); err != nil {
		return &codedError{code: ExitUsage, err: fmt.Errorf("validate %s report options: %w", cfg.Output.Format, err)}
	}
	var rendered bytes.Buffer
	if err := selectedReporter.Render(&rendered, input, reportOptions); err != nil {
		return &codedError{code: ExitInternal, err: fmt.Errorf("render %s report: %w", cfg.Output.Format, err)}
	}
	if cfg.Output.Path == "" {
		if _, err := cmd.OutOrStdout().Write(rendered.Bytes()); err != nil {
			return &codedError{code: ExitInternal, err: fmt.Errorf("write %s report to stdout: %w", cfg.Output.Format, err)}
		}
	} else {
		protected := make([]string, 0, len(files)+2)
		for _, file := range files {
			protected = append(protected, file.Path)
		}
		protected = append(protected, cfgPath, resolvedGitleaks)
		if err := safefile.WriteReportProtected(absRoot, cfg.Output.Path, rendered.Bytes(), protected); err != nil {
			return &codedError{code: ExitInternal, err: fmt.Errorf("write report: %w", err)}
		}
	}
	if exceeded {
		return &codedError{code: ExitThreshold, err: errors.New("configured risk threshold exceeded"), silent: true}
	}
	return nil
}

func reporterFor(format string) (reporters.Reporter, error) {
	switch format {
	case "terminal":
		return terminalreport.New(), nil
	case "json":
		return jsonreport.New(), nil
	case "sarif":
		return sarifreport.New(), nil
	case "html":
		return htmlreport.New(), nil
	case "mermaid":
		return mermaidreport.New(), nil
	default:
		return nil, fmt.Errorf("unsupported report format %q", sanitizer.TerminalText(format))
	}
}

func writerIsTerminal(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func applyCLIOverrides(cmd *cobra.Command, cfg *config.Config, opts scanOptions) {
	changed := cmd.Flags().Changed
	if changed("format") {
		cfg.Output.Format = opts.format
	}
	if changed("output") {
		cfg.Output.Path = opts.output
	}
	if changed("fail-on") {
		cfg.Risk.FailOn = opts.failOn
	}
	if changed("minimum-score") {
		cfg.Risk.MinimumScore = opts.minimumScore
	}
	if changed("include") {
		cfg.Scan.Include = append([]string(nil), opts.include...)
	}
	if changed("exclude") {
		cfg.Scan.Exclude = append([]string(nil), opts.exclude...)
	}
	if changed("no-color") {
		cfg.Output.NoColor = opts.noColor
	}
	if changed("quiet") {
		cfg.Output.Quiet = opts.quiet
	}
	if changed("verbose") {
		cfg.Output.Verbose = opts.verbose
	}
	if changed("profile") {
		cfg.Profile = opts.profile
	}
	if changed("gitleaks-path-prefix") {
		cfg.Gitleaks.PathPrefix = opts.gitleaksPathPrefix
	}
}

func ignoreDirectives(items []config.IgnoreEntry) []analysis.IgnoreDirective {
	result := make([]analysis.IgnoreDirective, 0, len(items))
	for _, item := range items {
		result = append(result, analysis.IgnoreDirective{Value: item.Value, Reason: item.Reason})
	}
	return result
}

func newVersionCommand(info BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s (commit %s, built %s)\n", productName, info.Version, info.Commit, info.Date)
			return nil
		},
	}
}

func newRulesCommand() *cobra.Command {
	parent := &cobra.Command{Use: "rules", Short: "Inspect CredScope rule identifiers"}
	parent.AddCommand(&cobra.Command{
		Use: "list", Short: "List stable rule identifiers", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, item := range rules.Catalog() {
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s\n", item.ID, item.Title)
			}
			return nil
		},
	})
	return parent
}

func newExplainCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "explain RULE_ID",
		Short: "Explain a stable rule identifier",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := strings.ToUpper(args[0])
			item, ok := rules.ByID(id)
			if !ok {
				return &codedError{code: ExitUsage, err: fmt.Errorf("unknown rule %q", sanitizer.TerminalText(args[0]))}
			}
			title := item.Title
			fmt.Fprintf(cmd.OutOrStdout(), "%s — %s\n", id, title)
			return nil
		},
	}
}
