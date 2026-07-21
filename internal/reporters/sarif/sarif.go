// Package sarif implements the bounded SARIF 2.1.0 representation used by
// CredScope. It emits one result per actionable rule and credential.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/reporters"
	"github.com/Bavlik/CredScope/internal/rules"
	"github.com/Bavlik/CredScope/internal/sanitizer"
)

const schemaURL = "https://json.schemastore.org/sarif-2.1.0.json"

type Reporter struct{}

func New() Reporter                               { return Reporter{} }
func (Reporter) Name() string                     { return "sarif" }
func (Reporter) Validate(reporters.Options) error { return nil }

type log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}
type run struct {
	Tool       tool          `json:"tool"`
	Results    []result      `json:"results"`
	Properties runProperties `json:"properties"`
}
type runProperties struct {
	EnvironmentProfile string   `json:"environmentProfile"`
	ProfileSource      string   `json:"profileSource"`
	ProfileReason      string   `json:"profileReason"`
	ProfileAssumptions []string `json:"profileAssumptions"`
	IgnoredCount       int      `json:"ignoredCount"`
}
type tool struct {
	Driver driver `json:"driver"`
}
type driver struct {
	Name           string           `json:"name"`
	Version        string           `json:"version"`
	InformationURI string           `json:"informationUri,omitempty"`
	Rules          []ruleDescriptor `json:"rules"`
}
type ruleDescriptor struct {
	ID               string        `json:"id"`
	Name             string        `json:"name"`
	ShortDescription message       `json:"shortDescription"`
	FullDescription  message       `json:"fullDescription"`
	Help             help          `json:"help"`
	DefaultConfig    defaultConfig `json:"defaultConfiguration"`
}
type message struct {
	Text string `json:"text"`
}
type help struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}
type defaultConfig struct {
	Level string `json:"level"`
}
type result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             message           `json:"message"`
	Locations           []location        `json:"locations,omitempty"`
	RelatedLocations    []relatedLocation `json:"relatedLocations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          properties        `json:"properties"`
}
type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}
type relatedLocation struct {
	ID               int              `json:"id"`
	Message          message          `json:"message"`
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}
type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           *region          `json:"region,omitempty"`
}
type artifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}
type region struct {
	StartLine int `json:"startLine"`
}
type properties struct {
	CredentialID         string `json:"credentialId"`
	Credential           string `json:"credential"`
	RiskScore            int    `json:"riskScore"`
	Confidence           string `json:"confidence"`
	PolicyVersion        string `json:"policyVersion"`
	RuleCatalogVersion   string `json:"ruleCatalogVersion"`
	RemediationID        string `json:"remediationId,omitempty"`
	Classification       string `json:"classification"`
	ClassificationSource string `json:"classificationSource"`
	EnvironmentProfile   string `json:"environmentProfile"`
	AnalysisSource       string `json:"analysisSource"`
	ProfileAssumptions   string `json:"profileAssumptions"`
}

type keyedResult struct {
	key   string
	value result
}

func (Reporter) Render(writer io.Writer, input reporters.Input, options reporters.Options) error {
	catalog := rules.Catalog()
	descriptors := make([]ruleDescriptor, 0, len(catalog))
	indexes := make(map[string]int, len(catalog))
	weights := make(map[string]int, len(catalog))
	for index, item := range catalog {
		indexes[item.ID] = index
		weights[item.ID] = item.Weight
		descriptors = append(descriptors, ruleDescriptor{ID: item.ID, Name: item.Title, ShortDescription: message{Text: item.Title}, FullDescription: message{Text: item.Description}, Help: help{Text: item.Description, Markdown: "**" + item.ID + " — " + item.Title + "**\n\n" + item.Description}, DefaultConfig: defaultConfig{Level: level(item.DefaultSeverity)}})
	}
	var keyed []keyedResult
	seenResults := make(map[string]bool)
	for _, credential := range reporters.OrderedCredentials(input, false) {
		for _, match := range credential.MatchedRules {
			if weights[match.RuleID] == 0 {
				continue
			}
			primary, related := locations(match.Evidence)
			remediation := remediationAction(credential, match.RemediationID)
			text := match.RuleID + ": " + match.Title + " for " + sanitizer.TerminalText(credential.Credential.Label) + ". Risk score " + strconv.Itoa(credential.Score) + "/100."
			if remediation != "" {
				text += " Recommended action: " + remediation
			}
			fingerprint := stableFingerprint(credential.Credential.ID + "\x00" + match.RuleID)
			source := "credscope_static_reachability"
			if match.RuleID == "CRD101" {
				source = "imported_secret_scanner"
			}
			item := result{RuleID: match.RuleID, RuleIndex: indexes[match.RuleID], Level: level(match.Severity), Message: message{Text: text}, RelatedLocations: related, PartialFingerprints: map[string]string{"credentialRule/v2": fingerprint}, Properties: properties{CredentialID: credential.Credential.ID, Credential: sanitizer.TerminalText(credential.Credential.Label), RiskScore: credential.Score, Confidence: string(match.Confidence), PolicyVersion: credential.PolicyVersion, RuleCatalogVersion: credential.RuleCatalogVersion, RemediationID: match.RemediationID, Classification: string(credential.Credential.Classification), ClassificationSource: credential.Credential.ClassificationSource, EnvironmentProfile: string(input.Analysis.Profile.Selected), AnalysisSource: source, ProfileAssumptions: strings.Join(input.Analysis.Profile.Assumptions, "; ")}}
			if primary != nil {
				item.Locations = []location{*primary}
			}
			locationKey := ""
			if primary != nil {
				locationKey = primary.PhysicalLocation.ArtifactLocation.URI
				if primary.PhysicalLocation.Region != nil {
					locationKey += ":" + strconv.Itoa(primary.PhysicalLocation.Region.StartLine)
				}
			}
			key := match.RuleID + "\x00" + credential.Credential.ID + "\x00" + locationKey
			if !seenResults[key] {
				seenResults[key] = true
				keyed = append(keyed, keyedResult{key: key, value: item})
			}
		}
	}
	sort.Slice(keyed, func(i, j int) bool { return keyed[i].key < keyed[j].key })
	results := make([]result, 0, len(keyed))
	for _, item := range keyed {
		results = append(results, item.value)
	}
	document := log{Schema: schemaURL, Version: "2.1.0", Runs: []run{{Tool: tool{Driver: driver{Name: input.Tool.Name, Version: input.Tool.Version, Rules: descriptors}}, Results: results, Properties: runProperties{EnvironmentProfile: string(input.Analysis.Profile.Selected), ProfileSource: input.Analysis.Profile.Source, ProfileReason: input.Analysis.Profile.Reason, ProfileAssumptions: append([]string{}, input.Analysis.Profile.Assumptions...), IgnoredCount: input.Analysis.IgnoredCount}}}}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	if options.Pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(document)
}

func locations(evidence []domain.Evidence) (*location, []relatedLocation) {
	items := append([]domain.Evidence{}, evidence...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].Location.Path != items[j].Location.Path {
			return items[i].Location.Path < items[j].Location.Path
		}
		if items[i].Location.Line != items[j].Location.Line {
			return items[i].Location.Line < items[j].Location.Line
		}
		return items[i].Field < items[j].Field
	})
	var physical []physicalLocation
	seen := make(map[string]bool)
	for _, item := range items {
		if item.Location.Path == "" {
			continue
		}
		uri := safeURI(item.Location.Path)
		key := uri + ":" + strconv.Itoa(item.Location.Line)
		if uri == "" || seen[key] {
			continue
		}
		seen[key] = true
		entry := physicalLocation{ArtifactLocation: artifactLocation{URI: uri, URIBaseID: "%SRCROOT%"}}
		if item.Location.Line > 0 {
			entry.Region = &region{StartLine: item.Location.Line}
		}
		physical = append(physical, entry)
	}
	if len(physical) == 0 {
		return nil, nil
	}
	primary := &location{PhysicalLocation: physical[0]}
	related := make([]relatedLocation, 0, len(physical)-1)
	for index, item := range physical[1:] {
		related = append(related, relatedLocation{ID: index + 1, Message: message{Text: "Related static evidence"}, PhysicalLocation: item})
	}
	return primary, related
}

func safeURI(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	value = strings.TrimLeft(value, "/")
	clean := path.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, ":") {
		return ""
	}
	parts := strings.Split(clean, "/")
	for index, part := range parts {
		parts[index] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func level(severity domain.Severity) string {
	switch severity {
	case domain.SeverityCritical, domain.SeverityHigh:
		return "error"
	case domain.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func remediationAction(credential domain.CredentialAnalysis, id string) string {
	for _, item := range credential.Remediations {
		if item.ID == id {
			return sanitizer.TerminalText(item.SuggestedAction)
		}
	}
	return ""
}

func stableFingerprint(value string) string {
	sum := sha256.Sum256([]byte("credscope:sarif:v1\x00" + value))
	return hex.EncodeToString(sum[:])
}
