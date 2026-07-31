package githubactions

import (
	"strings"
	"testing"
)

const collidingInputsYAML = `name: Deploy
description: Deploys the app
inputs:
  "api token":
    required: true
  api_token:
    required: true
runs:
  using: composite
  steps:
    - run: echo hi
      shell: bash
`

// Two distinct declared input keys ("api token" and "api_token") normalize
// through sanitizer.Identifier to the same identifier. Silently keeping
// either declaration would leave CA2's caller-binding matching ambiguous
// about which declaration a normalized "api_token" binding actually targets,
// so the whole action metadata must be rejected as malformed instead.
func TestActionMetadataInputNormalizedNameCollisionRejected(t *testing.T) {
	_, err := parseInlineAction(t, "action.yml", collidingInputsYAML)
	if err == nil {
		t.Fatal("expected a parse error for colliding normalized input names")
	}
	if !strings.Contains(err.Error(), "normalizes to already-declared identifier") || !strings.Contains(err.Error(), `"api_token"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Second collision-prone pair from the same family as the workflow-step
// with: guardrail ("token!" / "token_").
func TestActionMetadataInputNormalizedNameCollisionRejectedBangUnderscore(t *testing.T) {
	yaml := `name: Deploy
description: Deploys the app
inputs:
  "token!":
    required: true
  token_:
    required: true
runs:
  using: composite
  steps:
    - run: echo hi
      shell: bash
`
	_, err := parseInlineAction(t, "action.yml", yaml)
	if err == nil {
		t.Fatal("expected a parse error for colliding normalized input names")
	}
	if !strings.Contains(err.Error(), "normalizes to already-declared identifier") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The error is deterministic across repeated parses of identical content.
func TestActionMetadataInputNormalizedNameCollisionDeterministicError(t *testing.T) {
	_, first := parseInlineAction(t, "action.yml", collidingInputsYAML)
	_, second := parseInlineAction(t, "action.yml", collidingInputsYAML)
	if first == nil || second == nil {
		t.Fatal("expected parse errors")
	}
	if first.Error() != second.Error() {
		t.Fatalf("error not deterministic: first=%q second=%q", first.Error(), second.Error())
	}
}

// Distinct, non-colliding input names remain unaffected — this is a
// validation guardrail only, not a change to normal valid input parsing.
func TestActionMetadataInputDistinctNamesUnaffected(t *testing.T) {
	yaml := `name: Deploy
description: Deploys the app
inputs:
  token:
    required: true
  region:
    required: false
runs:
  using: composite
  steps:
    - run: echo hi
      shell: bash
`
	metadata, err := parseInlineAction(t, "action.yml", yaml)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Inputs) != 2 {
		t.Fatalf("expected two distinct inputs, got %#v", metadata.Inputs)
	}
}
