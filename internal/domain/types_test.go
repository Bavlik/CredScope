package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFindingSerializationHasNoRawSecretField(t *testing.T) {
	finding := Finding{
		ID: "finding-1", RuleID: "CRD101", Description: "synthetic",
		Credential: CredentialIdentity{Label: "EXAMPLE_TOKEN", Fingerprint: "sha256:0123456789abcdef"},
		Location:   Location{Path: "example.env", Line: 1}, Source: "test",
	}
	encoded, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"raw_secret", "rawsecret", `"secret"`, `"match"`} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("serialized finding contains forbidden field %q: %s", forbidden, encoded)
		}
	}
}

func TestPublicEnumValuesAreStable(t *testing.T) {
	if ConfidenceConfirmed != "confirmed" || SeverityCritical != "critical" || EdgePassedTo != "PASSED_TO" {
		t.Fatal("public serialized enum changed")
	}
}
