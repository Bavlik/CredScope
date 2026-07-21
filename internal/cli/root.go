package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/credscope/credscope/internal/config"
	"github.com/credscope/credscope/internal/discovery"
	"github.com/credscope/credscope/internal/ingest"
	"github.com/credscope/credscope/internal/rules"
	"github.com/credscope/credscope/internal/sanitizer"
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
		fmt.Fprintf(os.Stderr, "credscope: %s\n", sanitizer.TerminalText(err.Error()))
		var coded *codedError
		if errors.As(err, &coded) {
			return coded.code
		}
		return ExitUsage
	}
	return ExitOK
}

// NewRootCommand creates a command tree without global mutable state, which keeps
// embedding and tests deterministic.
func NewRootCommand(info BuildInfo, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "credscope",
		Short:         "Map the blast radius of leaked credentials",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(newScanCommand(), newVersionCommand(info), newRulesCommand(), newExplainCommand())
	return root
}

type scanOptions struct {
	configPath   string
	gitleaksPath string
	format       string
	output       string
	failOn       string
	minimumScore int
	include      []string
	exclude      []string
	noColor      bool
	quiet        bool
	verbose      bool
}

func newScanCommand() *cobra.Command {
	var opts scanOptions
	cmd := &cobra.Command{
		Use:   "scan [repository]",
		Short: "Discover and validate supported security-analysis inputs",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}
			return runInputScan(cmd, root, opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.gitleaksPath, "gitleaks-report", "", "path to a Gitleaks JSON report")
	f.StringVarP(&opts.format, "format", "f", "terminal", "report format: terminal, json, sarif, html, or mermaid")
	f.StringVarP(&opts.output, "output", "o", "", "write report to path")
	f.StringVar(&opts.failOn, "fail-on", "none", "failure threshold: none, low, medium, high, or critical")
	f.IntVar(&opts.minimumScore, "minimum-score", 0, "minimum score to report (0-100)")
	f.StringSliceVar(&opts.include, "include", nil, "additional repository-relative include pattern")
	f.StringSliceVar(&opts.exclude, "exclude", nil, "repository-relative exclude pattern")
	f.StringVar(&opts.configPath, "config", "", "configuration file (default: .credscope.yml when present)")
	f.BoolVar(&opts.noColor, "no-color", false, "disable colored terminal output")
	f.BoolVarP(&opts.quiet, "quiet", "q", false, "suppress non-result output")
	f.BoolVarP(&opts.verbose, "verbose", "v", false, "show detailed evidence")
	return cmd
}

func runInputScan(cmd *cobra.Command, root string, opts scanOptions) error {
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
	if cfg.Output.Format != "terminal" || cfg.Output.Path != "" {
		return &codedError{code: ExitUsage, err: fmt.Errorf("report output is not implemented in Phase 2; use terminal format without --output")}
	}

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

	if cfg.Output.Quiet {
		return nil
	}
	writer := cmd.OutOrStdout()
	fmt.Fprintf(writer, "%s %s\n", productName, sanitizer.TerminalText("inputs"))
	fmt.Fprintf(writer, "Repository: %s\n", sanitizer.TerminalText(absRoot))
	fmt.Fprintln(writer, "Discovered inputs:")
	if len(files) == 0 {
		fmt.Fprintln(writer, "  (none)")
	}
	for _, file := range files {
		rel, relErr := filepath.Rel(absRoot, file.Path)
		if relErr != nil {
			rel = file.Path
		}
		fmt.Fprintf(writer, "  %s  %s\n", file.Kind, sanitizer.TerminalText(filepath.ToSlash(rel)))
	}
	if cfg.Output.Verbose {
		fmt.Fprintf(writer, "Configuration: fail-on=%s minimum-score=%d format=%s\n", cfg.Risk.FailOn, cfg.Risk.MinimumScore, cfg.Output.Format)
		fmt.Fprintf(writer, "Parsed inputs: findings=%d workflows=%d compose-projects=%d\n", len(parsed.Findings), len(parsed.Workflows), len(parsed.Compose))
	}
	return nil
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
