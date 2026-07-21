package profile

import (
	"reflect"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

func TestProfilesAreDeterministic(t *testing.T) {
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{{File: ".github/workflows/ci.yml"}}}
	for _, requested := range []domain.Profile{domain.ProfileAuto, domain.ProfileLocal, domain.ProfileCI, domain.ProfileStaging, domain.ProfileProduction} {
		first, second := Select(requested, parsed), Select(requested, parsed)
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("profile %s is not deterministic", requested)
		}
	}
	if got := Select(domain.ProfileAuto, parsed); got.Selected != domain.ProfileCI || got.Source != "repository_context" {
		t.Fatalf("unexpected auto profile: %+v", got)
	}
	production := domain.ParsedRepository{Compose: []domain.ComposeProject{{File: "compose.yml", Services: []domain.ComposeService{{Name: "api", ProductionLike: true}}}}}
	if got := Select(domain.ProfileAuto, production); got.Selected != domain.ProfileProduction {
		t.Fatalf("production context not inferred: %+v", got)
	}
}
