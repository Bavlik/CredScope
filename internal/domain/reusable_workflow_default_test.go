package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func boolPtr(v bool) *bool         { return &v }
func numberPtr(v float64) *float64 { return &v }
func stringPtr(v string) *string   { return &v }

func TestReusableWorkflowInputDefaultBooleanFalseSerializesExplicitly(t *testing.T) {
	def := ReusableWorkflowInputDefault{Type: "boolean", Boolean: boolPtr(false)}
	encoded, err := json.Marshal(def)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"boolean":false`) {
		t.Fatalf("false default must serialize explicitly: %s", encoded)
	}
	if strings.Contains(string(encoded), `"string"`) || strings.Contains(string(encoded), `"number"`) {
		t.Fatalf("inactive union fields must be omitted: %s", encoded)
	}
}

func TestReusableWorkflowInputDefaultBooleanTrue(t *testing.T) {
	def := ReusableWorkflowInputDefault{Type: "boolean", Boolean: boolPtr(true)}
	encoded, err := json.Marshal(def)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"boolean":true`) {
		t.Fatalf("true default must serialize: %s", encoded)
	}
}

func TestReusableWorkflowInputDefaultNumberZeroSerializesExplicitly(t *testing.T) {
	def := ReusableWorkflowInputDefault{Type: "number", Number: numberPtr(0)}
	encoded, err := json.Marshal(def)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"number":0`) {
		t.Fatalf("zero default must serialize explicitly: %s", encoded)
	}
	if strings.Contains(string(encoded), `"string"`) || strings.Contains(string(encoded), `"boolean"`) {
		t.Fatalf("inactive union fields must be omitted: %s", encoded)
	}
}

func TestReusableWorkflowInputDefaultNumberFractional(t *testing.T) {
	def := ReusableWorkflowInputDefault{Type: "number", Number: numberPtr(1.5)}
	encoded, err := json.Marshal(def)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"number":1.5`) {
		t.Fatalf("fractional default must serialize: %s", encoded)
	}
}

func TestReusableWorkflowInputDefaultEmptyStringSerializesExplicitly(t *testing.T) {
	def := ReusableWorkflowInputDefault{Type: "string", String: stringPtr("")}
	encoded, err := json.Marshal(def)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"string":""`) {
		t.Fatalf("empty string default must serialize explicitly: %s", encoded)
	}
	if strings.Contains(string(encoded), `"boolean"`) || strings.Contains(string(encoded), `"number"`) {
		t.Fatalf("inactive union fields must be omitted: %s", encoded)
	}
}

func TestReusableWorkflowInputDefaultNonEmptyString(t *testing.T) {
	def := ReusableWorkflowInputDefault{Type: "string", String: stringPtr("production")}
	encoded, err := json.Marshal(def)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"string":"production"`) {
		t.Fatalf("non-empty string default must serialize: %s", encoded)
	}
}

func TestReusableWorkflowInputDefaultRoundTripPreservesTypeAndValue(t *testing.T) {
	cases := []ReusableWorkflowInputDefault{
		{Type: "boolean", Boolean: boolPtr(false)},
		{Type: "boolean", Boolean: boolPtr(true)},
		{Type: "number", Number: numberPtr(0)},
		{Type: "number", Number: numberPtr(1.5)},
		{Type: "string", String: stringPtr("")},
		{Type: "string", String: stringPtr("production")},
	}
	for _, original := range cases {
		encoded, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		var decoded ReusableWorkflowInputDefault
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Type != original.Type {
			t.Fatalf("type not preserved: got %#v want %#v", decoded, original)
		}
		switch original.Type {
		case "boolean":
			if decoded.Boolean == nil || *decoded.Boolean != *original.Boolean {
				t.Fatalf("boolean not preserved: got %#v want %#v", decoded, original)
			}
		case "number":
			if decoded.Number == nil || *decoded.Number != *original.Number {
				t.Fatalf("number not preserved: got %#v want %#v", decoded, original)
			}
		case "string":
			if decoded.String == nil || *decoded.String != *original.String {
				t.Fatalf("string not preserved: got %#v want %#v", decoded, original)
			}
		}
	}
}

func TestReusableWorkflowInputDefaultNilMeansNoDefault(t *testing.T) {
	def := ReusableWorkflowInputDefinition{Name: "environment", Type: "string"}
	if def.Default != nil {
		t.Fatalf("expected nil Default when no default was declared, got %#v", def.Default)
	}
	encoded, err := json.Marshal(def)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"default"`) {
		t.Fatalf("absent default must be omitted entirely: %s", encoded)
	}
}
