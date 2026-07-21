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
				if !strings.Contains(text, "contents: write") {
					t.Fatal("release workflow lacks its scoped release permission")
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
	docPaths := []string{"README.md", "docs/github-action.md", "docs/installation.md", "docs/releasing.md", "docs/RELEASE_CHECKLIST.md", "action.yml"}
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
