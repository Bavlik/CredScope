package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".credscope.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultIsValid(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default().Validate(): %v", err)
	}
	if cfg.Risk.FailOn != "none" || cfg.Output.Format != "terminal" {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
}

func TestInformationalFailureThresholdIsValid(t *testing.T) {
	cfg := Default()
	cfg.Risk.FailOn = "informational"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadOverlaysDefaults(t *testing.T) {
	path := writeConfig(t, "version: 1\nrisk:\n  fail_on: high\n  minimum_score: 42\noutput:\n  verbose: true\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Risk.FailOn != "high" || cfg.Risk.MinimumScore != 42 || !cfg.Output.Verbose {
		t.Fatalf("configuration not loaded: %#v", cfg)
	}
	if cfg.Output.Format != "terminal" || len(cfg.Scan.Include) == 0 {
		t.Fatal("unspecified defaults were not preserved")
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	path := writeConfig(t, "version: 1\nscan:\n  mystery: true\n")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "field mystery not found") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestLoadRejectsUnknownRuleField(t *testing.T) {
	path := writeConfig(t, "version: 1\nrules:\n  CRD101:\n    enabled: true\n    weight: 99\n")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "field weight not found") {
		t.Fatalf("expected nested unknown-field error, got %v", err)
	}
}

func TestLoadRejectsMalformedYAML(t *testing.T) {
	path := writeConfig(t, "version: 1\nscan: [unterminated\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "parse configuration") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestLoadRejectsMultipleDocuments(t *testing.T) {
	path := writeConfig(t, "version: 1\n---\nversion: 1\n")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("expected multiple-document error, got %v", err)
	}
}

func TestValidateRejectsTraversalAndInvalidValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"version", func(c *Config) { c.Version = 3 }},
		{"score", func(c *Config) { c.Risk.MinimumScore = 101 }},
		{"severity", func(c *Config) { c.Risk.FailOn = "urgent" }},
		{"format", func(c *Config) { c.Output.Format = "xml" }},
		{"traversal", func(c *Config) { c.Scan.Include = []string{"../outside"} }},
		{"conflicting output", func(c *Config) { c.Output.Quiet, c.Output.Verbose = true, true }},
		{"rule ID", func(c *Config) { c.Rules["BAD001"] = RuleConfig{Enabled: true} }},
		{"root gitleaks prefix", func(c *Config) { c.Gitleaks.PathPrefix = "/" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoadRejectsOversizedConfiguration(t *testing.T) {
	path := writeConfig(t, "version: 1\n#"+strings.Repeat("x", maxConfigSize))
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestIgnoreEntriesRequireReasonsAndRejectUnsafeValues(t *testing.T) {
	cfg := Default()
	cfg.Ignore.Paths = []IgnoreEntry{{Value: "tests/**"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "requires a human-readable reason") {
		t.Fatalf("expected missing reason error, got %v", err)
	}
	cfg = Default()
	cfg.Ignore.Paths = []IgnoreEntry{{Value: "../outside", Reason: "not relevant"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("unsafe ignore path accepted")
	}
	cfg = Default()
	cfg.Ignore.Variables = []IgnoreEntry{{Value: "TOKEN=actual-value", Reason: "bad entry"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("secret-like ignore value accepted")
	}
}

func TestIgnoreMetadataRejectsCommonSecretMaterial(t *testing.T) {
	secretLikeToken := "gh" + "p_" + strings.Repeat("a", 36)
	for _, content := range []string{
		"version: 2\nignore:\n  findings:\n    - value: " + secretLikeToken + "\n      reason: copied token\n",
		"version: 2\nignore:\n  rules:\n    - value: CRD101\n      reason: PASSWORD=do-not-store-values-here\n",
	} {
		path := writeConfig(t, content)
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "must not contain secret material") {
			t.Fatalf("secret-like ignore metadata was accepted: %v", err)
		}
	}
}

func TestValidV2Controls(t *testing.T) {
	cfg := Default()
	cfg.Profile = "production"
	cfg.Gitleaks.PathPrefix = "/repo"
	cfg.Ignore.Variables = []IgnoreEntry{{Value: "PUBLIC_MODE", Reason: "documented public setting"}}
	cfg.Classifications["PUBLIC_MODE"] = "public_configuration"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateOutputPathIsRepositoryRelative(t *testing.T) {
	valid := Default()
	valid.Output.Path = filepath.FromSlash("reports/nested/report.json")
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid nested output: %v", err)
	}
	for _, path := range []string{"../outside.json", "reports/../../outside.json", "/tmp/report.json", `C:\outside\report.json`, `\\server\share\report.json`, "bad\x00name"} {
		t.Run(strings.ReplaceAll(path, "\\", "_"), func(t *testing.T) {
			cfg := Default()
			cfg.Output.Path = path
			if err := cfg.Validate(); err == nil {
				t.Fatalf("unsafe output path %q was accepted", path)
			}
		})
	}
}
