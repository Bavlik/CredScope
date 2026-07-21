package reporters

import (
	"testing"

	"github.com/credscope/credscope/internal/domain"
)

func TestThresholdInteractionAndSeverityBoundaries(t *testing.T) {
	result := domain.AnalysisResult{Credentials: []domain.CredentialAnalysis{
		{Score: 79, Severity: domain.SeverityHigh},
		{Score: 80, Severity: domain.SeverityCritical},
	}}
	for _, test := range []struct {
		fail    string
		minimum int
		want    bool
	}{
		{"none", 0, false}, {"informational", 100, false}, {"high", 80, true}, {"critical", 81, false}, {"critical", 80, true},
	} {
		if got := ThresholdExceeded(result, test.fail, test.minimum); got != test.want {
			t.Errorf("ThresholdExceeded(%q,%d)=%t want %t", test.fail, test.minimum, got, test.want)
		}
	}
}

func TestOrderedCredentialsUsesScoreThenLabel(t *testing.T) {
	input := Input{Scan: Scan{MinimumScore: 40}, Analysis: domain.AnalysisResult{Credentials: []domain.CredentialAnalysis{
		{Credential: domain.CredentialSubject{Label: "ZED"}, Score: 20, Severity: domain.SeverityLow},
		{Credential: domain.CredentialSubject{Label: "BETA"}, Score: 80, Severity: domain.SeverityCritical},
		{Credential: domain.CredentialSubject{Label: "ALPHA"}, Score: 80, Severity: domain.SeverityCritical},
	}}}
	got := OrderedCredentials(input, true)
	if len(got) != 2 || got[0].Credential.Label != "ALPHA" || got[1].Credential.Label != "BETA" {
		t.Fatalf("ordered = %#v", got)
	}
}
