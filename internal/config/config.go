// Package config loads and validates CredScope's versioned configuration.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	DefaultFilename = ".credscope.yml"
	maxConfigSize   = 1 << 20
)

type Config struct {
	Version         int                   `yaml:"version" json:"version"`
	Profile         string                `yaml:"profile" json:"profile"`
	Scan            ScanConfig            `yaml:"scan" json:"scan"`
	Gitleaks        GitleaksConfig        `yaml:"gitleaks" json:"gitleaks"`
	Ignore          IgnoreConfig          `yaml:"ignore" json:"ignore"`
	Classifications map[string]string     `yaml:"classifications" json:"classifications"`
	Risk            RiskConfig            `yaml:"risk" json:"risk"`
	Rules           map[string]RuleConfig `yaml:"rules" json:"rules"`
	Output          OutputConfig          `yaml:"output" json:"output"`
}

type GitleaksConfig struct {
	PathPrefix string `yaml:"path_prefix" json:"path_prefix"`
}

type IgnoreEntry struct {
	Value  string `yaml:"value" json:"value"`
	Reason string `yaml:"reason" json:"reason"`
}

type IgnoreConfig struct {
	Paths     []IgnoreEntry `yaml:"paths" json:"paths"`
	Variables []IgnoreEntry `yaml:"variables" json:"variables"`
	Findings  []IgnoreEntry `yaml:"findings" json:"findings"`
	Rules     []IgnoreEntry `yaml:"rules" json:"rules"`
}

type ScanConfig struct {
	Include []string `yaml:"include" json:"include"`
	Exclude []string `yaml:"exclude" json:"exclude"`
}

type RiskConfig struct {
	FailOn       string `yaml:"fail_on" json:"fail_on"`
	MinimumScore int    `yaml:"minimum_score" json:"minimum_score"`
}

type RuleConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

type OutputConfig struct {
	Format  string `yaml:"format" json:"format"`
	Path    string `yaml:"path" json:"path"`
	NoColor bool   `yaml:"no_color" json:"no_color"`
	Quiet   bool   `yaml:"quiet" json:"quiet"`
	Verbose bool   `yaml:"verbose" json:"verbose"`
}

func Default() Config {
	return Config{
		Version: 2,
		Profile: "auto",
		Scan: ScanConfig{
			Include: []string{
				".github/workflows/*.yml",
				".github/workflows/*.yaml",
				"docker-compose.yml", "docker-compose.yaml",
				"compose.yml", "compose.yaml",
			},
			Exclude: []string{
				".git/**", "vendor/**", "node_modules/**", "dist/**",
				"build/**", "coverage/**", ".tmp/**",
			},
		},
		Risk:            RiskConfig{FailOn: "none", MinimumScore: 0},
		Rules:           make(map[string]RuleConfig),
		Classifications: make(map[string]string),
		Output:          OutputConfig{Format: "terminal"},
	}
}

// Load overlays a strict YAML document onto built-in defaults. An empty path
// means defaults only. Unknown fields and multiple YAML documents are errors.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Config{}, fmt.Errorf("load configuration %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Config{}, fmt.Errorf("load configuration %q: symbolic links are not allowed", path)
	}
	if !info.Mode().IsRegular() {
		return Config{}, fmt.Errorf("load configuration %q: not a regular file", path)
	}
	if info.Size() > maxConfigSize {
		return Config{}, fmt.Errorf("load configuration %q: file exceeds %d bytes", path, maxConfigSize)
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("load configuration %q: %w", path, err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(io.LimitReader(f, maxConfigSize+1))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse configuration %q: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, fmt.Errorf("parse configuration %q: multiple YAML documents are not allowed", path)
		}
		return Config{}, fmt.Errorf("parse configuration %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate configuration %q: %w", path, err)
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Version != 1 && c.Version != 2 {
		return fmt.Errorf("unsupported configuration version %d (expected 1 or 2)", c.Version)
	}
	if !oneOf(c.Profile, "auto", "local", "ci", "staging", "production") {
		return fmt.Errorf("profile must be one of auto, local, ci, staging, production")
	}
	if err := validatePathPrefix(c.Gitleaks.PathPrefix); err != nil {
		return fmt.Errorf("gitleaks.path_prefix: %w", err)
	}
	if c.Risk.MinimumScore < 0 || c.Risk.MinimumScore > 100 {
		return fmt.Errorf("risk.minimum_score must be between 0 and 100")
	}
	if !oneOf(c.Risk.FailOn, "none", "informational", "low", "medium", "high", "critical") {
		return fmt.Errorf("risk.fail_on must be one of none, informational, low, medium, high, critical")
	}
	if !oneOf(c.Output.Format, "terminal", "json", "sarif", "html", "mermaid") {
		return fmt.Errorf("output.format must be one of terminal, json, sarif, html, mermaid")
	}
	if c.Output.Quiet && c.Output.Verbose {
		return fmt.Errorf("output.quiet and output.verbose cannot both be true")
	}
	if c.Output.Path != "" {
		if err := validateOutputPath(c.Output.Path); err != nil {
			return fmt.Errorf("output.path %q: %w", c.Output.Path, err)
		}
	}
	for _, set := range []struct {
		name   string
		values []string
	}{{"scan.include", c.Scan.Include}, {"scan.exclude", c.Scan.Exclude}} {
		for _, pattern := range set.values {
			if err := validatePattern(pattern); err != nil {
				return fmt.Errorf("%s pattern %q: %w", set.name, pattern, err)
			}
		}
	}
	for id := range c.Rules {
		if len(id) != 6 || !strings.HasPrefix(id, "CRD") || id[3] < '1' || id[3] > '5' {
			return fmt.Errorf("rules contains invalid rule ID %q", id)
		}
		for _, ch := range id[3:] {
			if ch < '0' || ch > '9' {
				return fmt.Errorf("rules contains invalid rule ID %q", id)
			}
		}
	}
	for name, value := range c.Classifications {
		if !validVariableName(name) {
			return fmt.Errorf("classifications contains invalid variable name %q", name)
		}
		if !oneOf(value, "secret", "credential", "credential_identifier", "sensitive_configuration", "public_configuration", "operational_setting", "unknown") {
			return fmt.Errorf("classifications.%s has invalid classification %q", name, value)
		}
	}
	for _, set := range []struct {
		name  string
		items []IgnoreEntry
	}{{"ignore.paths", c.Ignore.Paths}, {"ignore.variables", c.Ignore.Variables}, {"ignore.findings", c.Ignore.Findings}, {"ignore.rules", c.Ignore.Rules}} {
		for _, item := range set.items {
			if strings.TrimSpace(item.Reason) == "" {
				return fmt.Errorf("%s entry %q requires a human-readable reason", set.name, item.Value)
			}
			if strings.ContainsAny(item.Reason, "\x00\r\n") {
				return fmt.Errorf("%s entry %q has an invalid reason", set.name, item.Value)
			}
			if containsSecretMaterial(item.Value) || containsSecretMaterial(item.Reason) {
				return fmt.Errorf("%s entry must not contain secret material", set.name)
			}
			if strings.Contains(item.Value, "=") || strings.ContainsAny(item.Value, "\x00\r\n\t ") {
				return fmt.Errorf("%s entry value must be an identifier or path pattern, not a secret value", set.name)
			}
			switch set.name {
			case "ignore.paths":
				if err := validatePattern(item.Value); err != nil {
					return fmt.Errorf("%s entry %q: %w", set.name, item.Value, err)
				}
			case "ignore.variables":
				if !validVariableName(item.Value) {
					return fmt.Errorf("%s contains invalid variable %q", set.name, item.Value)
				}
			case "ignore.rules":
				if len(item.Value) != 6 || !strings.HasPrefix(item.Value, "CRD") {
					return fmt.Errorf("%s contains invalid rule %q", set.name, item.Value)
				}
			case "ignore.findings":
				if item.Value == "" {
					return fmt.Errorf("%s contains an empty finding identifier", set.name)
				}
			}
		}
	}
	return nil
}

func validatePathPrefix(value string) error {
	if value == "" {
		return nil
	}
	if strings.ContainsRune(value, 0) {
		return errors.New("contains a NUL byte")
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	if !strings.HasPrefix(normalized, "/") && !(len(normalized) >= 3 && normalized[1] == ':' && normalized[2] == '/') {
		return errors.New("must be an absolute container or Windows path")
	}
	cleaned := path.Clean(normalized)
	if cleaned == "/" || (len(cleaned) == 2 && cleaned[1] == ':') || (len(cleaned) == 3 && cleaned[1:] == ":/") {
		return errors.New("must identify a directory below the filesystem root")
	}
	for _, part := range strings.Split(normalized, "/") {
		if part == ".." {
			return errors.New("cannot contain parent traversal")
		}
	}
	return nil
}

func validVariableName(value string) bool {
	if value == "" {
		return false
	}
	for index, ch := range value {
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_' || (index > 0 && ch >= '0' && ch <= '9') {
			continue
		}
		return false
	}
	return true
}

func containsSecretMaterial(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range []string{"ghp_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "xoxa-", "sk-"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	upper := strings.ToUpper(value)
	if strings.Contains(upper, "-----BEGIN ") && strings.Contains(upper, "PRIVATE KEY-----") {
		return true
	}
	for _, assignment := range []string{"PASSWORD=", "PASS=", "TOKEN=", "SECRET=", "PRIVATE_KEY=", "API_KEY=", "ACCESS_KEY=", "CLIENT_SECRET="} {
		if strings.Contains(upper, assignment) {
			return true
		}
	}
	return len(value) == 20 && strings.HasPrefix(value, "AKIA")
}

func validatePattern(pattern string) error {
	if pattern == "" {
		return errors.New("must not be empty")
	}
	if strings.ContainsRune(pattern, 0) {
		return errors.New("contains a NUL byte")
	}
	normalized := filepath.ToSlash(pattern)
	if filepath.IsAbs(pattern) || filepath.VolumeName(pattern) != "" || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return errors.New("must be repository-relative and cannot traverse parents")
	}
	return nil
}

func validateOutputPath(value string) error {
	if strings.ContainsRune(value, 0) {
		return errors.New("contains a NUL byte")
	}
	portable := strings.ReplaceAll(value, "\\", "/")
	cleaned := filepath.ToSlash(filepath.Clean(value))
	windowsDrive := len(portable) >= 2 && portable[1] == ':'
	if filepath.IsAbs(value) || filepath.VolumeName(value) != "" || windowsDrive || strings.HasPrefix(portable, "/") {
		return errors.New("must be relative to the analyzed repository root")
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return errors.New("must name a file beneath the analyzed repository root")
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
