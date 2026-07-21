// Package profile selects deterministic environment assumptions for analysis.
package profile

import (
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
)

func Select(requested domain.Profile, parsed domain.ParsedRepository) domain.ProfileSelection {
	if requested == "" {
		requested = domain.ProfileAuto
	}
	if requested != domain.ProfileAuto {
		return domain.ProfileSelection{Requested: requested, Selected: requested, Source: "explicit", Reason: "Selected explicitly by command-line option or repository configuration.", Assumptions: assumptions(requested)}
	}
	for _, project := range parsed.Compose {
		lower := strings.ToLower(project.File)
		switch {
		case strings.Contains(lower, "prod"):
			return inferred(domain.ProfileProduction, "A Compose filename contains a production marker.")
		case strings.Contains(lower, "staging") || strings.Contains(lower, "stage"):
			return inferred(domain.ProfileStaging, "A Compose filename contains a staging marker.")
		case strings.Contains(lower, "local") || strings.Contains(lower, "dev"):
			return inferred(domain.ProfileLocal, "A Compose filename contains a local or development marker.")
		}
		for _, service := range project.Services {
			if service.ProductionLike {
				return inferred(domain.ProfileProduction, "A Docker Compose service or profile name contains a production marker.")
			}
		}
	}
	if len(parsed.Workflows) > 0 && len(parsed.Compose) == 0 {
		return inferred(domain.ProfileCI, "The repository contains GitHub Actions workflows and no Docker Compose input.")
	}
	return domain.ProfileSelection{Requested: domain.ProfileAuto, Selected: domain.ProfileAuto, Source: "conservative_fallback", Reason: "Repository filenames and supported inputs do not identify one environment profile with sufficient confidence.", Assumptions: assumptions(domain.ProfileAuto)}
}

func inferred(selected domain.Profile, reason string) domain.ProfileSelection {
	return domain.ProfileSelection{Requested: domain.ProfileAuto, Selected: selected, Source: "repository_context", Reason: reason, Assumptions: assumptions(selected)}
}

func assumptions(selected domain.Profile) []string {
	switch selected {
	case domain.ProfileLocal:
		return []string{"Published ports are treated as development exposure context.", "Loopback bindings reduce host exposure.", "Internet exposure is not assumed."}
	case domain.ProfileCI:
		return []string{"Jobs are treated as ephemeral unless repository evidence says otherwise.", "Secrets available to jobs and steps are reported.", "Untrusted pull-request risk is evaluated separately."}
	case domain.ProfileStaging:
		return []string{"Published services receive moderate exposure weighting.", "Deployment controls remain unknown unless represented in repository content.", "Internet exposure is not assumed."}
	case domain.ProfileProduction:
		return []string{"Published services, broad credential sharing, and privileged runtime settings receive stricter risk weighting.", "Internet exposure is not assumed without direct evidence."}
	default:
		return []string{"Deployment environment is uncertain.", "Published ports provide exposure context only.", "Runtime data flow and internet exposure remain unknown."}
	}
}
