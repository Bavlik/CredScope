// Package remediation maps matched structural rules to safe, deterministic
// recommendations. It never modifies analyzed files.
package remediation

import (
	"sort"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
)

type Definition struct {
	ID              string
	Title           string
	Why             string
	SuggestedAction string
	Priority        int
}

func Catalog() []Definition {
	items := []Definition{
		{"REM001", "Rotate the exposed credential", "A scanner finding indicates credential material was present in repository content.", "Revoke or rotate the credential through its provider, update authorized consumers, and remove exposed history using the provider's incident procedure.", 1},
		{"REM002", "Replace static cloud credentials with OIDC", "Static cloud credentials in CI create long-lived material that can be copied or reused.", "Use GitHub Actions OIDC with a narrowly scoped trust policy and short-lived credentials where the cloud provider supports it.", 2},
		{"REM003", "Reduce GitHub Actions permissions", "Write-capable workflow tokens can alter repository or package state.", "Declare only the specific read or write scopes required by the affected job, preferring job-level least privilege.", 2},
		{"REM004", "Add explicit workflow permissions", "Omitted permissions inherit repository defaults that static analysis cannot confirm.", "Add an explicit read-only workflow permissions block, then grant narrowly scoped job-level writes only where necessary.", 3},
		{"REM005", "Harden pull_request_target use", "pull_request_target runs with base-repository context and can expose privileged resources if untrusted content is executed.", "Avoid checking out or executing pull-request head content in this workflow; separate untrusted validation from privileged operations.", 1},
		{"REM006", "Pin third-party actions to full commit SHAs", "Mutable tags can resolve to different code over time.", "Replace the mutable revision with a reviewed full 40-character commit SHA and use dependency automation to track updates.", 3},
		{"REM007", "Restrict credential scope", "The credential reaches more workflow or service scope than may be necessary.", "Limit the credential to the smallest job, step, environment, or service scope that requires it and use separate credentials for independent consumers.", 3},
		{"REM008", "Avoid passing secrets through shell commands", "Shell interpolation can expose credentials through command construction, tracing, process arguments, or error output.", "Pass the secret through the narrowest supported secret input or environment scope and prevent command tracing; do not interpolate it into command text.", 2},
		{"REM009", "Avoid credential propagation through job outputs", "Job outputs broaden the lifetime and number of consumers of credential-derived data.", "Remove secret values from outputs and let each authorized job retrieve its own narrowly scoped credential.", 2},
		{"REM010", "Separate CI and runtime credentials", "Sharing one identity across build automation and runtime services couples otherwise independent trust boundaries.", "Issue separate least-privilege credentials for CI and runtime services, with independent rotation and revocation.", 2},
		{"REM011", "Use Compose secrets for sensitive values", "Plain environment mappings broaden credential visibility inside a container and its tooling.", "Use a Compose secret or an external secret injection mechanism supported by the deployment environment, scoped to the receiving service.", 3},
		{"REM012", "Review published host ports", "Published ports may increase service reachability depending on host firewall and network configuration.", "Remove unnecessary port publishing or bind it to an appropriate interface, then enforce host and network access controls.", 3},
		{"REM013", "Remove privileged mode", "Privileged containers receive broad host-facing capabilities.", "Set privileged to false and grant only the specific capabilities and devices the workload requires.", 1},
		{"REM014", "Remove Docker socket mounts", "Access to the Docker socket commonly provides control over the container host.", "Remove the socket mount; if an integration is unavoidable, use a narrowly authorized proxy and isolate the workload.", 1},
		{"REM015", "Avoid host networking", "Host networking removes network namespace isolation and changes service exposure semantics.", "Use an isolated Compose network and explicitly publish only required ports.", 2},
		{"REM016", "Use a verified non-root container user", "Static configuration cannot confirm a non-root runtime identity when user is omitted.", "Set and verify a dedicated numeric non-root user in the image and Compose service, with only required filesystem permissions.", 4},
		{"REM017", "Separate production and development credentials", "Production-like components should not share broadly scoped credentials with lower-trust environments.", "Use environment-specific credentials and approval controls, with production access restricted to the deployment path.", 2},
		{"REM018", "Restrict writable host bind mounts", "Writable host binds let the container modify host files within the mounted path.", "Remove the bind mount, make it read-only, or replace it with a narrowly scoped managed volume.", 2},
		{"REM019", "Review unresolved reusable workflow", "The called workflow was intentionally not fetched, so its behavior and effective secret handling remain unknown.", "Review the referenced workflow at the pinned revision and restrict secrets and permissions passed to it.", 4},
		{"REM020", "Verify runtime security controls", "Static repository analysis cannot prove effective runtime permissions or external network exposure.", "Validate the deployed service identity, capabilities, firewall, bind address, and network policy in the target environment.", 4},
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

// Generate deduplicates definitions while retaining every triggering rule,
// evidence path, and affected source location.
func Generate(credential domain.CredentialSubject, matches []domain.RuleMatch) []domain.RemediationResult {
	definitions := make(map[string]Definition)
	for _, item := range Catalog() {
		definitions[item.ID] = item
	}
	type accumulator struct {
		definition Definition
		rules      []string
		paths      []string
		locations  []domain.Location
		confidence domain.Confidence
	}
	items := make(map[string]*accumulator)
	add := func(id string, match domain.RuleMatch) {
		definition, ok := definitions[id]
		if !ok {
			return
		}
		current := items[id]
		if current == nil {
			current = &accumulator{definition: definition, confidence: match.Confidence}
			items[id] = current
		}
		current.rules = append(current.rules, match.RuleID)
		current.paths = append(current.paths, match.PathIDs...)
		for _, item := range match.Evidence {
			if item.Location.Path != "" || item.Location.Line > 0 {
				current.locations = append(current.locations, item.Location)
			}
		}
		if confidenceRank(match.Confidence) > confidenceRank(current.confidence) {
			current.confidence = match.Confidence
		}
	}
	for _, match := range matches {
		add(match.RemediationID, match)
	}
	if strings.Contains(strings.ToUpper(credential.Label), "AWS") && hasWorkflowMatch(matches) {
		for _, match := range matches {
			if match.RuleID == "CRD102" {
				add("REM002", match)
				break
			}
		}
	}
	result := make([]domain.RemediationResult, 0, len(items))
	for _, item := range items {
		result = append(result, domain.RemediationResult{ID: item.definition.ID, Title: item.definition.Title, Why: item.definition.Why, TriggeringRuleIDs: uniqueStrings(item.rules), EvidencePathIDs: uniqueStrings(item.paths), AffectedLocations: uniqueLocations(item.locations), Confidence: item.confidence, SuggestedAction: item.definition.SuggestedAction, Priority: item.definition.Priority})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Priority != result[j].Priority {
			return result[i].Priority < result[j].Priority
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func hasWorkflowMatch(matches []domain.RuleMatch) bool {
	for _, match := range matches {
		if match.RuleID == "CRD102" {
			return true
		}
	}
	return false
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item != "" {
			seen[item] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for item := range seen {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func uniqueLocations(items []domain.Location) []domain.Location {
	seen := make(map[domain.Location]struct{}, len(items))
	for _, item := range items {
		seen[item] = struct{}{}
	}
	result := make([]domain.Location, 0, len(seen))
	for item := range seen {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Path != result[j].Path {
			return result[i].Path < result[j].Path
		}
		if result[i].Line != result[j].Line {
			return result[i].Line < result[j].Line
		}
		return result[i].Column < result[j].Column
	})
	return result
}

func confidenceRank(value domain.Confidence) int {
	switch value {
	case domain.ConfidenceConfirmed:
		return 4
	case domain.ConfidenceHigh:
		return 3
	case domain.ConfidenceMedium:
		return 2
	case domain.ConfidenceLow:
		return 1
	default:
		return 0
	}
}
