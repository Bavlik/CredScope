package repositoryquality

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var fullCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate repository")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
}

func TestActionManifestInputsOutputsAndCompositeRuntime(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Inputs  map[string]any `yaml:"inputs"`
		Outputs map[string]any `yaml:"outputs"`
		Runs    struct {
			Using string `yaml:"using"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	var manifestNode yaml.Node
	if err := yaml.Unmarshal(data, &manifestNode); err != nil {
		t.Fatal(err)
	}
	for _, use := range collectUses(&manifestNode) {
		parts := strings.Split(use, "@")
		if len(parts) != 2 || !fullCommit.MatchString(parts[1]) {
			t.Fatalf("composite Action dependency is not pinned to a full commit: %q", use)
		}
	}
	wantInputs := []string{"config", "fail-on", "format", "gitleaks-path-prefix", "gitleaks-report", "minimum-score", "no-color", "output", "path", "profile", "verbose"}
	wantOutputs := []string{"credentials-analyzed", "highest-score", "highest-severity", "report-path", "threshold-exceeded"}
	if got := sortedKeys(manifest.Inputs); strings.Join(got, ",") != strings.Join(wantInputs, ",") {
		t.Fatalf("inputs = %v", got)
	}
	if got := sortedKeys(manifest.Outputs); strings.Join(got, ",") != strings.Join(wantOutputs, ",") {
		t.Fatalf("outputs = %v", got)
	}
	if manifest.Runs.Using != "composite" {
		t.Fatalf("runtime = %q", manifest.Runs.Using)
	}
}

func TestDocumentedActionWorkflowIsValidYAML(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "docs", "examples", "github-action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("documented workflow is invalid YAML: %v", err)
	}
	if !strings.Contains(string(data), "--redact") || !strings.Contains(string(data), "if: always()") {
		t.Fatal("documented workflow must redact Gitleaks output and preserve SARIF upload after threshold exit")
	}
}

func TestWorkflowYAMLPermissionsTriggersAndPins(t *testing.T) {
	root := repositoryRoot(t)
	paths, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("workflow discovery: %v, %d files", err, len(paths))
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			var rootNode yaml.Node
			if err := yaml.Unmarshal(data, &rootNode); err != nil {
				t.Fatalf("invalid workflow YAML: %v", err)
			}
			text := string(data)
			if strings.Contains(text, "permissions: write-all") || strings.Contains(text, "pull_request_target") {
				t.Fatal("workflow contains a prohibited broad permission or trigger")
			}
			for _, use := range collectUses(&rootNode) {
				if strings.HasPrefix(use, "./") {
					continue
				}
				parts := strings.Split(use, "@")
				if len(parts) != 2 || !fullCommit.MatchString(parts[1]) {
					t.Fatalf("third-party Action is not pinned to a full commit: %q", use)
				}
			}
			base := filepath.Base(path)
			switch base {
			case "release.yml":
				if !strings.Contains(text, "tags:") || strings.Contains(text, "branches:") {
					t.Fatal("release workflow must be tag-only")
				}
				if strings.Count(text, "contents: write") != 1 || !strings.Contains(text, "  validate:") || !strings.Contains(text, "  publish:") || !strings.Contains(text, "    needs: validate") {
					t.Fatal("release workflow must grant write permission only to a publish job that depends on validation")
				}
			case "codeql.yml":
				if !strings.Contains(text, "security-events: write") || strings.Contains(text, "contents: write") {
					t.Fatal("CodeQL permissions are not least privilege")
				}
			default:
				if strings.Contains(text, "contents: write") || strings.Contains(text, "security-events: write") {
					t.Fatal("ordinary workflow grants write permission")
				}
			}
		})
	}
}

func TestDocumentationMatchesActionAndContainsNoSensitiveLocalData(t *testing.T) {
	root := repositoryRoot(t)
	docPaths := []string{"README.md", "docs/github-action.md", "docs/installation.md", "docs/RELEASING.md", "action.yml"}
	combined := ""
	for _, path := range docPaths {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		combined += string(data)
	}
	for _, input := range []string{"path", "gitleaks-report", "config", "format", "output", "fail-on", "minimum-score", "verbose", "no-color"} {
		if !strings.Contains(combined, "`"+input+"`") && !strings.Contains(combined, input+":") {
			t.Fatalf("documented Action input %q is missing", input)
		}
	}
	for _, forbidden := range []string{"@example.invalid", "ghp_"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("documentation contains forbidden local data marker %q", forbidden)
		}
	}
	raw := "FAKE_RAW_" + "SECRET_FOR_TESTS_ONLY"
	if strings.Contains(combined, raw) {
		t.Fatal("documentation or Action manifest contains a raw synthetic secret")
	}
}

func TestReleaseWorkflowCannotCreateTags(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(data))
	for _, forbidden := range []string{"git tag", "git push", "workflow_dispatch", "packages: write", "id-token: write"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("release workflow contains unapproved behavior %q", forbidden)
		}
	}
}

func TestWinGetPortableManifestsAreConsistent(t *testing.T) {
	root := repositoryRoot(t)
	versionBytes, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	version := strings.TrimSpace(string(versionBytes))
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(version) {
		t.Fatalf("VERSION must contain plain X.Y.Z syntax, got %q", version)
	}
	directory := filepath.Join(root, "packaging", "winget", "Bavlik.CredScope", version)

	var versionManifest struct {
		PackageIdentifier string `yaml:"PackageIdentifier"`
		PackageVersion    string `yaml:"PackageVersion"`
		DefaultLocale     string `yaml:"DefaultLocale"`
		ManifestType      string `yaml:"ManifestType"`
		ManifestVersion   string `yaml:"ManifestVersion"`
	}
	readYAML(t, filepath.Join(directory, "Bavlik.CredScope.yaml"), &versionManifest)
	if versionManifest.PackageIdentifier != "Bavlik.CredScope" || versionManifest.PackageVersion != version || versionManifest.DefaultLocale != "en-US" || versionManifest.ManifestType != "version" || versionManifest.ManifestVersion != "1.12.0" {
		t.Fatalf("invalid WinGet version manifest: %#v", versionManifest)
	}

	type nestedFile struct {
		RelativeFilePath     string `yaml:"RelativeFilePath"`
		PortableCommandAlias string `yaml:"PortableCommandAlias"`
	}
	var installerManifest struct {
		PackageIdentifier   string   `yaml:"PackageIdentifier"`
		PackageVersion      string   `yaml:"PackageVersion"`
		InstallerType       string   `yaml:"InstallerType"`
		NestedInstallerType string   `yaml:"NestedInstallerType"`
		Commands            []string `yaml:"Commands"`
		Installers          []struct {
			Architecture         string       `yaml:"Architecture"`
			NestedInstallerFiles []nestedFile `yaml:"NestedInstallerFiles"`
			InstallerURL         string       `yaml:"InstallerUrl"`
			InstallerSHA256      string       `yaml:"InstallerSha256"`
		} `yaml:"Installers"`
		ManifestType    string `yaml:"ManifestType"`
		ManifestVersion string `yaml:"ManifestVersion"`
	}
	readYAML(t, filepath.Join(directory, "Bavlik.CredScope.installer.yaml"), &installerManifest)
	if installerManifest.PackageIdentifier != "Bavlik.CredScope" || installerManifest.PackageVersion != version || installerManifest.InstallerType != "zip" || installerManifest.NestedInstallerType != "portable" || installerManifest.ManifestType != "installer" || installerManifest.ManifestVersion != "1.12.0" || strings.Join(installerManifest.Commands, ",") != "credscope" {
		t.Fatalf("invalid WinGet installer manifest: %#v", installerManifest)
	}
	wantArchitectures := []string{"arm64", "x64"}
	var architectures []string
	sha256Pattern := regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)
	for _, installer := range installerManifest.Installers {
		architectures = append(architectures, installer.Architecture)
		if len(installer.NestedInstallerFiles) != 1 || installer.NestedInstallerFiles[0].RelativeFilePath != "credscope.exe" || installer.NestedInstallerFiles[0].PortableCommandAlias != "credscope" {
			t.Fatalf("invalid portable alias for %s: %#v", installer.Architecture, installer.NestedInstallerFiles)
		}
		placeholderURL := strings.HasPrefix(installer.InstallerURL, "REPLACE_WITH_WINDOWS_")
		placeholderHash := strings.HasPrefix(installer.InstallerSHA256, "REPLACE_WITH_WINDOWS_")
		if (!placeholderURL && !strings.HasPrefix(installer.InstallerURL, "https://github.com/Bavlik/CredScope/releases/download/")) || (!placeholderHash && !sha256Pattern.MatchString(installer.InstallerSHA256)) {
			t.Fatalf("invalid URL or SHA-256 for %s", installer.Architecture)
		}
	}
	sort.Strings(architectures)
	if strings.Join(architectures, ",") != strings.Join(wantArchitectures, ",") {
		t.Fatalf("WinGet architectures = %v, want %v", architectures, wantArchitectures)
	}

	var localeManifest struct {
		PackageIdentifier string `yaml:"PackageIdentifier"`
		PackageVersion    string `yaml:"PackageVersion"`
		Publisher         string `yaml:"Publisher"`
		PackageName       string `yaml:"PackageName"`
		License           string `yaml:"License"`
		ManifestType      string `yaml:"ManifestType"`
		ManifestVersion   string `yaml:"ManifestVersion"`
	}
	readYAML(t, filepath.Join(directory, "Bavlik.CredScope.locale.en-US.yaml"), &localeManifest)
	if localeManifest.PackageIdentifier != "Bavlik.CredScope" || localeManifest.PackageVersion != version || localeManifest.Publisher != "Abdallah Alotaibi" || localeManifest.PackageName != "CredScope" || localeManifest.License != "Apache-2.0" || localeManifest.ManifestType != "defaultLocale" || localeManifest.ManifestVersion != "1.12.0" {
		t.Fatalf("invalid WinGet locale manifest: %#v", localeManifest)
	}
}

func readYAML(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, target); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func collectUses(node *yaml.Node) []string {
	var values []string
	var walk func(*yaml.Node)
	walk = func(current *yaml.Node) {
		if current.Kind == yaml.MappingNode {
			for index := 0; index+1 < len(current.Content); index += 2 {
				key, value := current.Content[index], current.Content[index+1]
				if key.Value == "uses" && value.Kind == yaml.ScalarNode {
					values = append(values, value.Value)
				}
				walk(value)
			}
			return
		}
		for _, child := range current.Content {
			walk(child)
		}
	}
	walk(node)
	sort.Strings(values)
	return values
}

func sortedKeys(input map[string]any) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
