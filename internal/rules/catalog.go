// Package rules contains the versioned, data-driven security rule catalog and
// structural match engine. Parsers do not depend on this package.
package rules

import (
	"sort"

	"github.com/credscope/credscope/internal/domain"
)

const CatalogVersion = "v1"

type Rule struct {
	ID                   string            `json:"id"`
	Title                string            `json:"title"`
	Description          string            `json:"description"`
	Category             string            `json:"category"`
	DefaultSeverity      domain.Severity   `json:"default_severity"`
	Weight               int               `json:"weight"`
	DefaultConfidence    domain.Confidence `json:"default_confidence"`
	EvidenceRequirements []string          `json:"evidence_requirements"`
	RemediationID        string            `json:"remediation_id"`
	References           []string          `json:"references"`
	Enabled              bool              `json:"enabled"`
	PolicyVersion        string            `json:"policy_version"`
}

func Catalog() []Rule {
	rules := []Rule{
		rule("CRD101", "Credential finding imported", "A scanner-neutral credential finding was imported.", "credential_exposure", domain.SeverityInformational, 15, domain.ConfidenceConfirmed, []string{"scanner finding linked to credential"}, "REM001"),
		rule("CRD102", "Credential referenced by workflow", "A GitHub Actions workflow structurally references the credential.", "github_actions", domain.SeverityLow, 8, domain.ConfidenceConfirmed, []string{"credential-to-workflow path"}, "REM007"),
		rule("CRD103", "Credential used by multiple jobs", "The credential is structurally referenced by multiple workflow jobs.", "github_actions", domain.SeverityMedium, 8, domain.ConfidenceHigh, []string{"two or more distinct job nodes"}, "REM007"),
		rule("CRD104", "Credential used by pull_request_target", "The credential reaches a workflow triggered by pull_request_target.", "github_actions", domain.SeverityHigh, 16, domain.ConfidenceHigh, []string{"credential path to pull_request_target trigger"}, "REM005"),
		rule("CRD201", "Workflow grants write permission", "A reachable workflow or job explicitly grants a write-level permission.", "github_actions", domain.SeverityHigh, 12, domain.ConfidenceConfirmed, []string{"reachable permission with write level"}, "REM003"),
		rule("CRD202", "Workflow grants write-all", "A reachable workflow or job explicitly grants write-all.", "github_actions", domain.SeverityCritical, 20, domain.ConfidenceConfirmed, []string{"reachable all:write-all permission"}, "REM003"),
		rule("CRD203", "Secret passed to shell", "A credential reference occurs in an inert workflow shell block.", "github_actions", domain.SeverityHigh, 12, domain.ConfidenceConfirmed, []string{"credential edge with shell evidence"}, "REM008"),
		rule("CRD204", "Secret passed to third-party action", "A credential reaches a third-party action input or step scope; third-party does not imply malicious.", "github_actions", domain.SeverityMedium, 10, domain.ConfidenceConfirmed, []string{"credential path through step to third-party action"}, "REM007"),
		rule("CRD205", "Third-party action uses mutable reference", "A reachable third-party action is pinned to a mutable revision rather than a full commit SHA.", "github_actions", domain.SeverityMedium, 7, domain.ConfidenceConfirmed, []string{"reachable third-party action with mutable revision"}, "REM006"),
		rule("CRD206", "Secret propagated through job output", "A job output directly references the credential.", "github_actions", domain.SeverityHigh, 12, domain.ConfidenceConfirmed, []string{"credential propagation edge with job output evidence"}, "REM009"),
		rule("CRD207", "Missing explicit workflow permissions", "A reachable workflow omits an explicit permissions declaration; effective defaults depend on repository settings.", "github_actions", domain.SeverityLow, 5, domain.ConfidenceHigh, []string{"reachable workflow marked missing explicit permissions"}, "REM004"),
		rule("CRD208", "Credential reaches production environment", "The credential reaches an environment whose name appears production-like.", "github_actions", domain.SeverityMedium, 12, domain.ConfidenceMedium, []string{"reachable production-like environment"}, "REM017"),
		rule("CRD301", "Credential passed to Compose service", "A Compose service directly receives the credential reference.", "docker_compose", domain.SeverityLow, 8, domain.ConfidenceConfirmed, []string{"credential-to-service passed-to edge"}, "REM011"),
		rule("CRD302", "Credential reaches privileged service", "The credential reaches a service configured with privileged mode.", "docker_compose", domain.SeverityHigh, 18, domain.ConfidenceConfirmed, []string{"reachable privileged service"}, "REM013"),
		rule("CRD303", "Credential reaches published host port", "The credential reaches a service publishing a host port; external reachability depends on runtime configuration.", "docker_compose", domain.SeverityMedium, 8, domain.ConfidenceMedium, []string{"reachable published port"}, "REM012"),
		rule("CRD304", "Credential reaches Docker socket mount", "The credential reaches a service mounting a Docker socket.", "docker_compose", domain.SeverityCritical, 20, domain.ConfidenceConfirmed, []string{"reachable Docker socket volume"}, "REM014"),
		rule("CRD305", "Credential reaches host-network service", "The credential reaches a service configured with host network mode.", "docker_compose", domain.SeverityHigh, 12, domain.ConfidenceConfirmed, []string{"reachable host-network service"}, "REM015"),
		rule("CRD306", "Credential shared across multiple services", "The same credential is directly passed to multiple Compose services.", "docker_compose", domain.SeverityMedium, 8, domain.ConfidenceConfirmed, []string{"two or more directly affected services"}, "REM007"),
		rule("CRD307", "Credential reaches writable host bind mount", "The credential reaches a service with a writable host bind mount.", "docker_compose", domain.SeverityHigh, 10, domain.ConfidenceHigh, []string{"reachable writable host bind"}, "REM018"),
		rule("CRD308", "Container user cannot be confirmed as non-root", "No explicit non-root user can be confirmed for a reached service; this does not prove root execution.", "docker_compose", domain.SeverityLow, 3, domain.ConfidenceLow, []string{"reachable service without verified non-root user"}, "REM016"),
		rule("CRD401", "Credential shared across CI and runtime", "The same credential is referenced by GitHub Actions and passed to a Compose service.", "cross_component", domain.SeverityHigh, 15, domain.ConfidenceHigh, []string{"reachable workflow and direct Compose service"}, "REM010"),
		rule("CRD402", "Credential reaches multiple production components", "The credential reaches multiple structurally production-like components.", "cross_component", domain.SeverityHigh, 10, domain.ConfidenceMedium, []string{"two or more production-like environments or services"}, "REM017"),
		rule("CRD403", "Credential reaches write permission and deployment environment", "The credential reaches both a write-level repository permission and a deployment environment.", "cross_component", domain.SeverityHigh, 14, domain.ConfidenceHigh, []string{"reachable write permission and deployment environment"}, "REM003"),
		rule("CRD404", "Credential has multiple independent reachability paths", "The credential has multiple independent first-hop paths to affected components.", "cross_component", domain.SeverityMedium, 8, domain.ConfidenceHigh, []string{"two or more distinct direct component paths"}, "REM007"),
		rule("CRD501", "Reusable workflow unresolved", "A reachable reusable workflow was not resolved; no network lookup was attempted.", "analysis_warning", domain.SeverityInformational, 0, domain.ConfidenceUnknown, []string{"reachable unresolved reusable workflow"}, "REM019"),
		rule("CRD502", "Runtime permissions cannot be confirmed", "Static Compose analysis cannot confirm the effective runtime permissions of a reached service.", "analysis_warning", domain.SeverityInformational, 0, domain.ConfidenceUnknown, []string{"reachable Compose service"}, "REM020"),
		rule("CRD503", "External network exposure cannot be confirmed", "A host port is published, but actual external reachability cannot be confirmed statically.", "analysis_warning", domain.SeverityInformational, 0, domain.ConfidenceUnknown, []string{"reachable published host port"}, "REM020"),
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func rule(id, title, description, category string, severity domain.Severity, weight int, confidence domain.Confidence, evidence []string, remediation string) Rule {
	return Rule{ID: id, Title: title, Description: description, Category: category, DefaultSeverity: severity, Weight: weight, DefaultConfidence: confidence, EvidenceRequirements: evidence, RemediationID: remediation, References: []string{}, Enabled: true, PolicyVersion: domain.ScoringPolicy}
}

func ByID(id string) (Rule, bool) {
	for _, item := range Catalog() {
		if item.ID == id {
			return item, true
		}
	}
	return Rule{}, false
}
