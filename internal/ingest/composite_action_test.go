package ingest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bavlik/CredScope/internal/config"
	"github.com/Bavlik/CredScope/internal/domain"
)

func writeIngestFixture(t *testing.T, root, relPath, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const ingestCompositeActionYAML = `name: Deploy
description: Deploys the app
runs:
  using: composite
  steps:
    - run: echo hi
      shell: bash
`

const ingestCallerWorkflowYAML = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/deploy
`

// 65. ingest attaches the composite-action resolution to ParsedRepository.
func TestRepositoryAttachesCompositeActionResolution(t *testing.T) {
	root := t.TempDir()
	writeIngestFixture(t, root, ".github/workflows/ci.yml", ingestCallerWorkflowYAML)
	writeIngestFixture(t, root, ".github/actions/deploy/action.yml", ingestCompositeActionYAML)

	result, err := Repository(context.Background(), root, config.Default(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.CompositeActions.Actions) != 1 || result.CompositeActions.Actions[0].Directory != ".github/actions/deploy" {
		t.Fatalf("composite actions = %#v", result.CompositeActions.Actions)
	}
	if len(result.CompositeActions.Calls) != 1 || result.CompositeActions.Calls[0].Status != domain.CompositeActionResolvedLocalComposite {
		t.Fatalf("composite calls = %#v", result.CompositeActions.Calls)
	}
}

// CA3A: ingest surfaces repository-wide nested composite-action resolution
// (a canonical action reachable only through another action's own nested
// uses:, never directly by any workflow) end-to-end through Repository.
func TestRepositoryAttachesNestedCompositeActionResolution(t *testing.T) {
	root := t.TempDir()
	writeIngestFixture(t, root, ".github/workflows/ci.yml", ingestCallerWorkflowYAML)
	writeIngestFixture(t, root, ".github/actions/deploy/action.yml", `name: Deploy
description: Deploys the app
runs:
  using: composite
  steps:
    - uses: ./.github/actions/authenticate
`)
	writeIngestFixture(t, root, ".github/actions/authenticate/action.yml", ingestCompositeActionYAML)

	result, err := Repository(context.Background(), root, config.Default(), "")
	if err != nil {
		t.Fatal(err)
	}
	foundAuth := false
	for _, action := range result.CompositeActions.Actions {
		if action.Directory == ".github/actions/authenticate" {
			foundAuth = true
		}
	}
	if !foundAuth {
		t.Fatalf("expected the nested-only authenticate action to be resolved and retained, got %#v", result.CompositeActions.Actions)
	}
	if len(result.CompositeActions.NestedCalls) != 1 || result.CompositeActions.NestedCalls[0].CanonicalDirectory != ".github/actions/authenticate" {
		t.Fatalf("expected one nested call to authenticate, got %#v", result.CompositeActions.NestedCalls)
	}
}

// 71. context cancellation propagates through ingest's composite-action resolution.
func TestRepositoryPropagatesCancellationToCompositeResolution(t *testing.T) {
	root := t.TempDir()
	writeIngestFixture(t, root, ".github/workflows/ci.yml", ingestCallerWorkflowYAML)
	writeIngestFixture(t, root, ".github/actions/deploy/action.yml", ingestCompositeActionYAML)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Repository(ctx, root, config.Default(), ""); err == nil {
		t.Fatal("expected context cancellation error")
	}
}
