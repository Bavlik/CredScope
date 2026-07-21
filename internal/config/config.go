// Package config loads and validates CredScope's versioned configuration.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	DefaultFilename = ".credscope.yml"
	maxConfigSize   = 1 << 20
)

type Config struct {
	Version int                   `yaml:"version" json:"version"`
	Scan    ScanConfig            `yaml:"scan" json:"scan"`
	Risk    RiskConfig            `yaml:"risk" json:"risk"`
	Rules   map[string]RuleConfig `yaml:"rules" json:"rules"`
	Output  OutputConfig          `yaml:"output" json:"output"`
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
		Version: 1,
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
		Risk:   RiskConfig{FailOn: "none", MinimumScore: 0},
		Rules:  make(map[string]RuleConfig),
		Output: OutputConfig{Format: "terminal"},
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
	if c.Version != 1 {
		return fmt.Errorf("unsupported configuration version %d (expected 1)", c.Version)
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
	return nil
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

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
