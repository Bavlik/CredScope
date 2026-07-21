package sarif

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/reporters"
)

func TestSARIFStructureLocationsMappingAndDeduplication(t *testing.T) {
	ev := domain.Evidence{Location: domain.Location{Path: `.github\workflows\deploy hostile.yml`, Line: 7}, Confidence: domain.ConfidenceConfirmed}
	match := domain.RuleMatch{RuleID: "CRD201", Title: "Workflow grants write permission", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceConfirmed, Evidence: []domain.Evidence{ev}, RemediationID: "REM003"}
	credential := domain.CredentialAnalysis{Credential: domain.CredentialSubject{ID: "credential:safe", Label: "DEMO_TOKEN"}, Score: 70, Severity: domain.SeverityHigh, PolicyVersion: "v1", RuleCatalogVersion: "v1", MatchedRules: []domain.RuleMatch{match, match}, Remediations: []domain.RemediationResult{{ID: "REM003", SuggestedAction: "Reduce permissions"}}}
	input := reporters.Input{Tool: reporters.Tool{Name: "CredScope", Version: "test"}, Scan: reporters.Scan{StartedAt: time.Unix(1, 0)}, Analysis: domain.AnalysisResult{PolicyVersion: "v1", RuleCatalogVersion: "v1", Credentials: []domain.CredentialAnalysis{credential}}}
	var first, second bytes.Buffer
	if err := New().Render(&first, input, reporters.Options{Pretty: true}); err != nil {
		t.Fatal(err)
	}
	if err := New().Render(&second, input, reporters.Options{Pretty: true}); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("SARIF is not deterministic")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(first.Bytes())); got != "113898441a9be869942f0af252b2392fac01ee97795d9b04ff3214526def97b0" {
		t.Fatalf("SARIF golden hash = %s", got)
	}
	var decoded struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []any  `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID, Level string
				Locations     []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						}
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region,omitempty"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Partial map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != "2.1.0" || decoded.Schema != schemaURL || len(decoded.Runs) != 1 || len(decoded.Runs[0].Tool.Driver.Rules) != 27 {
		t.Fatalf("invalid SARIF header: %s", first.String())
	}
	if len(decoded.Runs[0].Results) != 1 {
		t.Fatalf("results = %d, want deduplicated 1", len(decoded.Runs[0].Results))
	}
	result := decoded.Runs[0].Results[0]
	if result.Level != "error" || len(result.Locations) != 1 || result.Locations[0].PhysicalLocation.Region.StartLine != 7 || !strings.Contains(result.Locations[0].PhysicalLocation.ArtifactLocation.URI, "%20") || result.Partial["credentialRule/v1"] == "" {
		t.Fatalf("invalid result: %#v", result)
	}
	if strings.Contains(first.String(), "RAW_SECRET_NOT_IN_MODEL") {
		t.Fatal("secret leak")
	}
}

func TestSARIFDoesNotFabricateUnknownLine(t *testing.T) {
	match := domain.RuleMatch{RuleID: "CRD101", Title: "Credential finding imported", Severity: domain.SeverityInformational, Confidence: domain.ConfidenceConfirmed, Evidence: []domain.Evidence{{Location: domain.Location{Path: "demo.env"}}}}
	input := reporters.Input{Tool: reporters.Tool{Name: "CredScope", Version: "test"}, Analysis: domain.AnalysisResult{Credentials: []domain.CredentialAnalysis{{Credential: domain.CredentialSubject{ID: "c", Label: "TOKEN"}, MatchedRules: []domain.RuleMatch{match}}}}}
	var output bytes.Buffer
	if err := New().Render(&output, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "startLine") {
		t.Fatalf("fabricated line: %s", output.String())
	}
}
