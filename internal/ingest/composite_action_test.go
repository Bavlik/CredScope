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
