// Package terminal renders human-readable analysis without retaining raw shell
// bodies or emitting repository-controlled terminal control sequences.
package terminal

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/reporters"
	"github.com/credscope/credscope/internal/sanitizer"
)

type Reporter struct{}

func New() Reporter                               { return Reporter{} }
func (Reporter) Name() string                     { return "terminal" }
func (Reporter) Validate(reporters.Options) error { return nil }

func (Reporter) Render(writer io.Writer, input reporters.Input, options reporters.Options) error {
	summary := reporters.Summarize(input)
	credentials := reporters.OrderedCredentials(input, true)
	if !options.Quiet {
		fmt.Fprintf(writer, "%s %s\n", safe(input.Tool.Name), safe(input.Tool.Version))
		fmt.Fprintf(writer, "Repository: %s\n", safe(input.Scan.Repository))
		fmt.Fprintf(writer, "Scoring policy: %s\nRule catalog: %s\n\n", safe(input.Analysis.PolicyVersion), safe(input.Analysis.RuleCatalogVersion))
	}
	fmt.Fprintln(writer, "Summary")
	fmt.Fprintf(writer, "  Credentials analyzed: %d\n", summary.CredentialCount)
	fmt.Fprintf(writer, "  Critical: %d  High: %d  Medium: %d  Low: %d  Informational: %d\n", summary.Critical, summary.High, summary.Medium, summary.Low, summary.Informational)
	fmt.Fprintf(writer, "  Highest score: %d/100\n", summary.HighestScore)
	if len(credentials) == 0 {
		fmt.Fprintln(writer, "\nNo credential blast-radius paths were identified from the available static evidence.")
		if input.Scan.MinimumScore > 0 && summary.CredentialCount > 0 {
			fmt.Fprintf(writer, "No credential met the display minimum score of %d; complete machine reports retain all analyses.\n", input.Scan.MinimumScore)
		}
	} else {
		for _, credential := range credentials {
			renderCredential(writer, input.Analysis.Graph, credential, options)
		}
	}
	renderWarnings(writer, input, options)
	if !options.Quiet {
		fmt.Fprintf(writer, "\nThreshold: fail-on=%s minimum-score=%d exceeded=%t\n", safe(input.Scan.FailOn), input.Scan.MinimumScore, input.Scan.ThresholdExceeded)
	}
	return nil
}

func renderCredential(writer io.Writer, graph domain.Graph, item domain.CredentialAnalysis, options reporters.Options) {
	severity := strings.ToUpper(string(item.Severity))
	if options.Color {
		severity = colorSeverity(item.Severity, severity)
	}
	fmt.Fprintf(writer, "\n%s - %s\n", severity, safe(item.Credential.Label))
	fmt.Fprintf(writer, "Blast-radius score: %d/100\nConfidence: %s\n", item.Score, displayConfidence(item.Confidence.Overall))
	fmt.Fprintf(writer, "Reachable: workflows=%d jobs=%d services=%d permissions=%d environments=%d external-actions=%d ports=%d mounts=%d\n",
		item.Reachable.Workflows, item.Reachable.Jobs, item.Reachable.Services, item.Reachable.Permissions,
		item.Reachable.Environments, item.Reachable.ExternalActions, item.Reachable.PublishedPorts, item.Reachable.VolumeMounts)

	limit := reporters.DefaultEvidencePathLimit
	if options.Verbose {
		limit = reporters.VerboseEvidencePathLimit
	}
	selection := reporters.SelectEvidencePaths(graph, item.EvidencePaths, limit)
	if len(selection.Paths) > 0 {
		fmt.Fprintln(writer, "Evidence paths:")
		for _, path := range selection.Paths {
			fmt.Fprintf(writer, "  - %s\n", humanPath(path))
		}
		if selection.Omitted > 0 {
			fmt.Fprintf(writer, "  ... %d additional relevant paths omitted (complete graph remains available in JSON and HTML)\n", selection.Omitted)
		}
	}

	fmt.Fprintln(writer, "Score breakdown:")
	for _, contribution := range item.Contributions {
		if contribution.FinalContribution == 0 && !options.Verbose {
			continue
		}
		fmt.Fprintf(writer, "  +%d %s %s (base=%d confidence=%s/%d%%)\n", contribution.FinalContribution, safe(contribution.RuleID), safe(contribution.Description), contribution.BaseWeight, displayConfidence(contribution.Confidence), contribution.ConfidenceMultiplier)
		if options.Verbose {
			for _, evidence := range contribution.Evidence {
				fmt.Fprintf(writer, "      %s\n", evidenceLocation(evidence))
			}
		}
	}

	if len(item.Remediations) > 0 {
		fmt.Fprintln(writer, "Recommended actions:")
		for index, remediation := range item.Remediations {
			fmt.Fprintf(writer, "  %d. %s\n", index+1, safe(remediation.Title))
			if options.Verbose {
				fmt.Fprintf(writer, "     %s\n", safe(remediation.SuggestedAction))
			}
		}
	}
	if len(item.Warnings) > 0 {
		fmt.Fprintln(writer, "Analysis limitations:")
		for _, warning := range item.Warnings {
			fmt.Fprintf(writer, "  - %s\n", safe(warning))
		}
	}
}

func renderWarnings(writer io.Writer, input reporters.Input, options reporters.Options) {
	var warnings []string
	warnings = append(warnings, input.Analysis.Warnings...)
	for _, item := range input.ParserWarnings {
		message := item.Code + ": " + item.Message
		if item.Location.Path != "" {
			message += " at " + item.Location.Path
			if item.Location.Line > 0 {
				message += fmt.Sprintf(":%d", item.Location.Line)
			}
		}
		warnings = append(warnings, message)
	}
	warnings = append(warnings, input.NonFatalErrors...)
	sort.Strings(warnings)
	if len(warnings) == 0 || (options.Quiet && !options.Verbose) {
		return
	}
	fmt.Fprintln(writer, "\nScan warnings:")
	for _, warning := range warnings {
		fmt.Fprintf(writer, "  - %s\n", safe(warning))
	}
}

func humanPath(path domain.EvidencePath) string {
	labels := make([]string, 0, len(path.Nodes))
	for _, node := range path.Nodes {
		labels = append(labels, truncate(safe(node.Label), 120))
	}
	return strings.Join(labels, " -> ")
}

func evidenceLocation(item domain.Evidence) string {
	location := safe(item.Location.Path)
	if location == "" {
		location = "location unavailable"
	} else if item.Location.Line > 0 {
		location += fmt.Sprintf(":%d", item.Location.Line)
	}
	if item.Field != "" {
		location += " [" + safe(item.Field) + "]"
	}
	if item.Type != "" {
		location += " " + safe(item.Type)
	}
	return location
}

func colorSeverity(severity domain.Severity, value string) string {
	code := "36"
	switch severity {
	case domain.SeverityCritical:
		code = "1;31"
	case domain.SeverityHigh:
		code = "31"
	case domain.SeverityMedium:
		code = "33"
	case domain.SeverityLow:
		code = "34"
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func displayConfidence(value domain.Confidence) string {
	text := string(value)
	if text == "" {
		return "Unknown"
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

func safe(value string) string { return sanitizer.TerminalText(value) }

func truncate(value string, length int) string {
	runes := []rune(value)
	if len(runes) <= length {
		return value
	}
	return string(runes[:length-1]) + "…"
}
