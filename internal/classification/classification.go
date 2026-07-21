// Package classification assigns conservative, source-aware labels to safe
// credential and configuration references. Names are indicators, not proof of
// secret material.
package classification

import (
	"sort"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
)

type Input struct {
	Name                 string
	ReferenceKinds       []domain.ReferenceKind
	ImportedFinding      bool
	Override             domain.Classification
	TestFixtureCandidate bool
}

type Result struct {
	Classification     domain.Classification
	Confidence         domain.Confidence
	Reason             string
	Source             string
	ExpectedSecret     bool
	RotationApplicable bool
}

func Assess(input Input) Result {
	name := strings.ToUpper(strings.TrimSpace(input.Name))
	if input.ImportedFinding {
		return Result{Classification: domain.ClassificationSecret, Confidence: domain.ConfidenceConfirmed, Reason: "An imported secret-scanner finding independently indicates secret-like content.", Source: "imported_scanner_finding", ExpectedSecret: true, RotationApplicable: true}
	}
	if input.Override != "" {
		return resultFor(input.Override, domain.ConfidenceConfirmed, "Repository configuration explicitly classifies this variable.", "repository_configuration")
	}
	for _, prefix := range []string{"NEXT_PUBLIC_", "VITE_", "REACT_APP_"} {
		if strings.HasPrefix(name, prefix) {
			return resultFor(domain.ClassificationPublicConfiguration, domain.ConfidenceHigh, "The variable uses a frontend prefix whose values are normally bundled for public client use.", "variable_name_heuristic")
		}
	}
	for _, kind := range uniqueKinds(input.ReferenceKinds) {
		if kind == domain.ReferenceSecret || kind == domain.ReferenceComposeSecret {
			return Result{Classification: domain.ClassificationSecret, Confidence: domain.ConfidenceHigh, Reason: "The source syntax explicitly identifies a secret reference; static analysis does not prove its value.", Source: "source_syntax", ExpectedSecret: true, RotationApplicable: false}
		}
	}
	if credentialIdentifier(name) {
		return resultFor(domain.ClassificationCredentialIdentifier, domain.ConfidenceHigh, "The variable names a credential identity rather than secret authentication material.", "variable_name_heuristic")
	}
	if operational(name) {
		return resultFor(domain.ClassificationOperationalSetting, domain.ConfidenceHigh, "The variable name indicates an application or deployment operating mode.", "variable_name_heuristic")
	}
	if secretName(name) {
		return Result{Classification: domain.ClassificationSecret, Confidence: domain.ConfidenceMedium, Reason: "A common secret-name suffix suggests secret material, but the name alone is not proof.", Source: "variable_name_heuristic", ExpectedSecret: true, RotationApplicable: false}
	}
	if sensitiveConfiguration(name) {
		return resultFor(domain.ClassificationSensitiveConfiguration, domain.ConfidenceMedium, "The variable appears to contain connection or security-relevant configuration without necessarily containing a secret.", "variable_name_heuristic")
	}
	return resultFor(domain.ClassificationUnknown, domain.ConfidenceLow, "Available static evidence is insufficient for a more specific classification.", "conservative_default")
}

func resultFor(classification domain.Classification, confidence domain.Confidence, reason, source string) Result {
	expected := classification == domain.ClassificationSecret || classification == domain.ClassificationCredential
	return Result{Classification: classification, Confidence: confidence, Reason: reason, Source: source, ExpectedSecret: expected, RotationApplicable: false}
}

func secretName(name string) bool {
	for _, suffix := range []string{"_PASSWORD", "_PASS", "_TOKEN", "_SECRET", "_PRIVATE_KEY", "_API_KEY", "_ACCESS_KEY", "_CLIENT_SECRET"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return name == "PASSWORD" || name == "PASS" || name == "TOKEN" || name == "SECRET" || name == "PRIVATE_KEY" || name == "API_KEY" || name == "ACCESS_KEY" || name == "CLIENT_SECRET"
}

func credentialIdentifier(name string) bool {
	return name == "USER" || name == "USERNAME" || strings.HasSuffix(name, "_USER") || strings.HasSuffix(name, "_USERNAME") || strings.HasSuffix(name, "_USER_ID") || strings.HasSuffix(name, "_ACCOUNT_ID")
}

func operational(name string) bool {
	return name == "POSTGRES_DB" || name == "DATABASE_NAME" || strings.HasSuffix(name, "_MODE") || strings.HasSuffix(name, "_LOCALE") || strings.HasSuffix(name, "_ENV") || strings.HasSuffix(name, "_ENVIRONMENT") || strings.HasSuffix(name, "_PORT")
}

func sensitiveConfiguration(name string) bool {
	return strings.HasSuffix(name, "_URL") || strings.HasSuffix(name, "_URI") || strings.HasSuffix(name, "_HOST") || strings.HasSuffix(name, "_ENDPOINT") || strings.HasSuffix(name, "_CERT")
}

func uniqueKinds(items []domain.ReferenceKind) []domain.ReferenceKind {
	set := make(map[domain.ReferenceKind]struct{}, len(items))
	for _, item := range items {
		set[item] = struct{}{}
	}
	result := make([]domain.ReferenceKind, 0, len(set))
	for item := range set {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
