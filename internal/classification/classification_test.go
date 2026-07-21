package classification

import (
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

func TestRequiredVariableClassifications(t *testing.T) {
	tests := []struct {
		name   string
		want   domain.Classification
		secret bool
	}{
		{"POSTGRES_PASSWORD", domain.ClassificationSecret, true},
		{"POSTGRES_USER", domain.ClassificationCredentialIdentifier, false},
		{"POSTGRES_DB", domain.ClassificationOperationalSetting, false},
		{"NEXT_PUBLIC_API_BASE_URL", domain.ClassificationPublicConfiguration, false},
		{"NEXT_PUBLIC_DEFAULT_LOCALE", domain.ClassificationPublicConfiguration, false},
		{"NEXT_PUBLIC_REGISTRATION_MODE", domain.ClassificationPublicConfiguration, false},
		{"REGISTRATION_MODE", domain.ClassificationOperationalSetting, false},
		{"MFA_ENFORCEMENT_MODE", domain.ClassificationOperationalSetting, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Assess(Input{Name: test.name, ReferenceKinds: []domain.ReferenceKind{domain.ReferenceComposeVariable}})
			if got.Classification != test.want || got.ExpectedSecret != test.secret {
				t.Fatalf("got classification=%s expected_secret=%t", got.Classification, got.ExpectedSecret)
			}
			if !test.secret && got.RotationApplicable {
				t.Fatal("non-secret classification must not recommend rotation")
			}
		})
	}
}

func TestImportedFindingOverridesPublicPrefix(t *testing.T) {
	got := Assess(Input{Name: "NEXT_PUBLIC_API_TOKEN", ImportedFinding: true})
	if got.Classification != domain.ClassificationSecret || !got.RotationApplicable || got.Source != "imported_scanner_finding" {
		t.Fatalf("unexpected scanner classification: %+v", got)
	}
}
