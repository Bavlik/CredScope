package repositoryquality

import (
	"archive/zip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

// architectureExpectation pins the exact, real, published installer fields
// for one WinGet architecture entry. Values are transcribed from the actual
// published GitHub Release checksums.txt and archive layout, not derived.
type architectureExpectation struct {
	relativeFilePath string
	installerURL     string
	installerSHA256  string
}

// wingetVersionExpectation pins the exact fields every committed
// packaging/winget/Bavlik.CredScope/<version> manifest directory must
// contain. There is intentionally no generic fallback: a new version
// directory must not be committed until an explicit entry is added here,
// which forces a human to transcribe its real, published values rather than
// letting a placeholder or a loosened pattern check slip through.
type wingetVersionExpectation struct {
	publisher     string
	publisherURL  string
	architectures map[string]architectureExpectation
}

var wingetManifestExpectations = map[string]wingetVersionExpectation{
	// Historical: flat archive layout (credscope.exe at the archive root),
	// finalized against the published v0.2.0 GitHub Release. Must not change.
	"0.2.0": {
		publisher:    "Abdallah Alotaibi",
		publisherURL: "https://github.com/Bavlik",
		architectures: map[string]architectureExpectation{
			"x64": {
				relativeFilePath: "credscope.exe",
				installerURL:     "https://github.com/Bavlik/CredScope/releases/download/v0.2.0/credscope_0.2.0_windows_amd64.zip",
				installerSHA256:  "E43C22B4E52C790C04D7B1F02CD87F3CE907CA0688FAA11A5B4493A446A8277C",
			},
			"arm64": {
				relativeFilePath: "credscope.exe",
				installerURL:     "https://github.com/Bavlik/CredScope/releases/download/v0.2.0/credscope_0.2.0_windows_arm64.zip",
				installerSHA256:  "6A394A31E24E3A431E23DDFC070C4822F447513B2E8024075ADA25C4EDE706F7",
			},
		},
	},
	// Current: directory-wrapped archive layout (credscope_<version>_<os>_<arch>/credscope.exe),
	// finalized against the published v0.2.2 GitHub Release, current Bavlik brand.
	"0.2.2": {
		publisher:    "Bavlik",
		publisherURL: "https://abdullahcv.com",
		architectures: map[string]architectureExpectation{
			"x64": {
				relativeFilePath: "credscope_0.2.2_windows_amd64/credscope.exe",
				installerURL:     "https://github.com/Bavlik/CredScope/releases/download/v0.2.2/credscope_0.2.2_windows_amd64.zip",
				installerSHA256:  "4CDD55B0D4FCCA555A1F3D4C9E8CFBEE98E7E69E26A2D3EFB030BF2E3F6A85E8",
			},
			"arm64": {
				relativeFilePath: "credscope_0.2.2_windows_arm64/credscope.exe",
				installerURL:     "https://github.com/Bavlik/CredScope/releases/download/v0.2.2/credscope_0.2.2_windows_arm64.zip",
				installerSHA256:  "D6EF2B980842F6E4026DE4266B29ABEEEBD22AE261953033D34AF587E44C9E3D",
			},
		},
	},
}

// TestWinGetPortableManifestsAreConsistent validates every WinGet manifest
// version directory that is actually checked in against an explicit,
// hand-transcribed expectation in wingetManifestExpectations. It intentionally
// does not require a directory for the current VERSION: manifests for a
// version are only finalized after that version's GitHub Release archives
// and published SHA-256 checksums exist (see scripts/update-winget-manifest.ps1
// and packaging/winget/README.md). An unregistered version directory fails
// the test rather than falling back to a loose, generic pattern check.
func TestWinGetPortableManifestsAreConsistent(t *testing.T) {
	root := repositoryRoot(t)
	base := filepath.Join(root, "packaging", "winget", "Bavlik.CredScope")
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	versionPattern := regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	checked := 0
	for _, entry := range entries {
		if !entry.IsDir() || !versionPattern.MatchString(entry.Name()) {
			continue
		}
		version := entry.Name()
		directory := filepath.Join(base, version)
		checked++

		t.Run(version, func(t *testing.T) {
			expectation, ok := wingetManifestExpectations[version]
			if !ok {
				t.Fatalf("no explicit expectation registered in wingetManifestExpectations for committed WinGet manifest version %q; add one with its real, published values before committing this directory", version)
			}

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
			for _, installer := range installerManifest.Installers {
				architectures = append(architectures, installer.Architecture)
				want, ok := expectation.architectures[installer.Architecture]
				if !ok {
					t.Fatalf("no expectation registered for architecture %q in version %q", installer.Architecture, version)
				}
				if len(installer.NestedInstallerFiles) != 1 || installer.NestedInstallerFiles[0].PortableCommandAlias != "credscope" {
					t.Fatalf("invalid portable alias for %s: %#v", installer.Architecture, installer.NestedInstallerFiles)
				}
				if relative := installer.NestedInstallerFiles[0].RelativeFilePath; relative != want.relativeFilePath {
					t.Fatalf("RelativeFilePath for %s = %q, want exactly %q", installer.Architecture, relative, want.relativeFilePath)
				}
				if installer.InstallerURL != want.installerURL {
					t.Fatalf("InstallerUrl for %s = %q, want exactly %q", installer.Architecture, installer.InstallerURL, want.installerURL)
				}
				if !strings.EqualFold(installer.InstallerSHA256, want.installerSHA256) {
					t.Fatalf("InstallerSha256 for %s = %q, want exactly %q", installer.Architecture, installer.InstallerSHA256, want.installerSHA256)
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
				PublisherUrl      string `yaml:"PublisherUrl"`
				PackageName       string `yaml:"PackageName"`
				License           string `yaml:"License"`
				ManifestType      string `yaml:"ManifestType"`
				ManifestVersion   string `yaml:"ManifestVersion"`
			}
			readYAML(t, filepath.Join(directory, "Bavlik.CredScope.locale.en-US.yaml"), &localeManifest)
			if localeManifest.PackageIdentifier != "Bavlik.CredScope" || localeManifest.PackageVersion != version || localeManifest.PackageName != "CredScope" || localeManifest.License != "Apache-2.0" || localeManifest.ManifestType != "defaultLocale" || localeManifest.ManifestVersion != "1.12.0" {
				t.Fatalf("invalid WinGet locale manifest: %#v", localeManifest)
			}
			if localeManifest.Publisher != expectation.publisher || localeManifest.PublisherUrl != expectation.publisherURL {
				t.Fatalf("WinGet locale publisher for %s = (%q, %q), want exactly (%q, %q)", version, localeManifest.Publisher, localeManifest.PublisherUrl, expectation.publisher, expectation.publisherURL)
			}
		})
	}
	if checked == 0 {
		t.Fatal("no WinGet manifest version directories found under packaging/winget/Bavlik.CredScope")
	}
}

// resolvePowerShellExecutable finds a PowerShell interpreter to run the
// WinGet packaging scripts' tests with. CredScope CI runs this package's
// "quality" job on ubuntu-latest, where only pwsh (PowerShell 7+) exists —
// there is no powershell.exe there. pwsh is preferred on every platform;
// Windows PowerShell is only considered as a Windows-only fallback, since it
// does not exist elsewhere. If nothing is found the test fails loudly
// instead of silently skipping this security coverage.
func resolvePowerShellExecutable(t *testing.T) string {
	t.Helper()
	candidates := []string{"pwsh"}
	if runtime.GOOS == "windows" {
		candidates = append(candidates, "powershell.exe", "powershell")
	}
	for _, candidate := range candidates {
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved
		}
	}
	t.Fatalf("no PowerShell executable found (tried %s); install pwsh to run the WinGet packaging security tests", strings.Join(candidates, ", "))
	return ""
}

// runResolvePortableExecutableRelativePath invokes
// scripts/resolve-portable-executable-path.ps1 — a thin -File-invocable
// wrapper around Resolve-PortableExecutableRelativePath in
// scripts/winget-manifest-functions.ps1 — against a fixture ZIP, returning
// its stdout (trimmed) and whether the invocation failed.
func runResolvePortableExecutableRelativePath(t *testing.T, powershell, zipPath string) (string, error) {
	t.Helper()
	root := repositoryRoot(t)
	wrapperPath := filepath.Join(root, "scripts", "resolve-portable-executable-path.ps1")
	cmd := exec.Command(powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", wrapperPath, "-Path", zipPath)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// writeFixtureZip builds a minimal ZIP archive at path containing the given
// entry names (each holding a small placeholder payload), without any of the
// safety normalization Resolve-PortableExecutableRelativePath itself applies
// — so malicious entry names (e.g. path traversal) can be exercised.
func writeFixtureZip(t *testing.T, path string, entries ...string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	for _, name := range entries {
		entryWriter, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entryWriter.Write([]byte("placeholder")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestResolvePortableExecutableRelativePath exercises the ZIP-layout
// inspection that scripts/update-winget-manifest.ps1 relies on to set
// RelativeFilePath. It must locate credscope.exe by inspecting the archive
// rather than assuming a fixed layout, covering both the historical flat
// layout and the directory-wrapped layout GoReleaser produces since
// CHANGELOG [0.2.1], and it must fail clearly instead of silently accepting
// an unsafe or ambiguous archive.
func TestResolvePortableExecutableRelativePath(t *testing.T) {
	powershell := resolvePowerShellExecutable(t)

	cases := []struct {
		name       string
		entries    []string
		wantPath   string
		wantErr    bool
		errKeyword string
	}{
		{name: "flat archive root", entries: []string{"credscope.exe", "README.md"}, wantPath: "credscope.exe"},
		{name: "wrapped amd64 archive", entries: []string{"credscope_0.2.2_windows_amd64/credscope.exe", "credscope_0.2.2_windows_amd64/README.md"}, wantPath: "credscope_0.2.2_windows_amd64/credscope.exe"},
		{name: "wrapped arm64 archive", entries: []string{"credscope_0.2.2_windows_arm64/credscope.exe", "credscope_0.2.2_windows_arm64/README.md"}, wantPath: "credscope_0.2.2_windows_arm64/credscope.exe"},
		{name: "missing executable", entries: []string{"README.md", "LICENSE"}, wantErr: true, errKeyword: "does not contain credscope.exe"},
		{name: "duplicate executables", entries: []string{"credscope.exe", "sub/credscope.exe"}, wantErr: true, errKeyword: "more than one credscope.exe"},
		{name: "traversal path", entries: []string{"../credscope.exe"}, wantErr: true, errKeyword: "traversal entry"},
		{name: "absolute path", entries: []string{"/credscope.exe"}, wantErr: true, errKeyword: "absolute path entry"},
		{name: "unexpected executable elsewhere", entries: []string{"credscope.exe", "extra/payload.exe"}, wantErr: true, errKeyword: "unexpected executable entry"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			zipPath := filepath.Join(t.TempDir(), "fixture.zip")
			writeFixtureZip(t, zipPath, testCase.entries...)
			output, err := runResolvePortableExecutableRelativePath(t, powershell, zipPath)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("expected failure, got success with output: %s", output)
				}
				if testCase.errKeyword != "" && !strings.Contains(output, testCase.errKeyword) {
					t.Fatalf("expected error output to contain %q, got: %s", testCase.errKeyword, output)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected success, got error: %v, output: %s", err, output)
			}
			if output != testCase.wantPath {
				t.Fatalf("RelativeFilePath = %q, want %q", output, testCase.wantPath)
			}
		})
	}
}

// TestResolvePortableExecutableRelativePathMatchesCommittedManifest ties the
// resolver's output to the already-validated, real committed v0.2.2
// manifest: rebuilding a synthetic archive with the exact same entry layout
// GoReleaser produces must resolve to the exact RelativeFilePath values
// already shipped in packaging/winget/Bavlik.CredScope/0.2.2.
func TestResolvePortableExecutableRelativePathMatchesCommittedManifest(t *testing.T) {
	powershell := resolvePowerShellExecutable(t)
	root := repositoryRoot(t)
	directory := filepath.Join(root, "packaging", "winget", "Bavlik.CredScope", "0.2.2")

	var installerManifest struct {
		PackageVersion string `yaml:"PackageVersion"`
		Installers     []struct {
			Architecture         string `yaml:"Architecture"`
			NestedInstallerFiles []struct {
				RelativeFilePath string `yaml:"RelativeFilePath"`
			} `yaml:"NestedInstallerFiles"`
		} `yaml:"Installers"`
	}
	readYAML(t, filepath.Join(directory, "Bavlik.CredScope.installer.yaml"), &installerManifest)
	version := installerManifest.PackageVersion

	archOSArch := map[string]string{"x64": "windows_amd64", "arm64": "windows_arm64"}
	for _, installer := range installerManifest.Installers {
		osArch, ok := archOSArch[installer.Architecture]
		if !ok || len(installer.NestedInstallerFiles) != 1 {
			t.Fatalf("unexpected committed installer entry: %#v", installer)
		}
		wantPath := "credscope_" + version + "_" + osArch + "/credscope.exe"
		if installer.NestedInstallerFiles[0].RelativeFilePath != wantPath {
			t.Fatalf("committed RelativeFilePath = %q, want %q", installer.NestedInstallerFiles[0].RelativeFilePath, wantPath)
		}

		zipPath := filepath.Join(t.TempDir(), "fixture.zip")
		writeFixtureZip(t, zipPath, wantPath, osArch+"/README.md")
		output, err := runResolvePortableExecutableRelativePath(t, powershell, zipPath)
		if err != nil {
			t.Fatalf("resolver failed for %s: %v, output: %s", installer.Architecture, err, output)
		}
		if output != wantPath {
			t.Fatalf("resolver output = %q, want %q (matching committed manifest)", output, wantPath)
		}
	}
}

// TestReleaseDocumentationReflectsCurrentVersion checks that GitHub-facing
// documentation advertises the current release and no longer carries the
// pre-launch Cloudsmith APT readiness caveats, while historical version
// references (changelog entries, WinGet manifests) remain untouched.
func TestReleaseDocumentationReflectsCurrentVersion(t *testing.T) {
	root := repositoryRoot(t)
	version := strings.TrimSpace(readTextFile(t, filepath.Join(root, "VERSION")))

	readme := readTextFile(t, filepath.Join(root, "README.md"))
	installation := readTextFile(t, filepath.Join(root, "docs", "installation.md"))
	githubAction := readTextFile(t, filepath.Join(root, "docs", "github-action.md"))

	for _, stale := range []string{
		"Cloudsmith repository exists and publishing is enabled",
		"Once the repository is available",
		"requires the Cloudsmith repository",
		"will not resolve to a published repository",
		"becomes usable only after the maintainer publishes",
	} {
		for name, doc := range map[string]string{"README.md": readme, "docs/installation.md": installation, "docs/github-action.md": githubAction} {
			if strings.Contains(doc, stale) {
				t.Fatalf("%s contains stale Cloudsmith readiness wording %q", name, stale)
			}
		}
	}

	if !strings.Contains(readme, "CredScope@v"+version) {
		t.Fatalf("README GitHub Action example does not reference the current release v%s", version)
	}
	if !strings.Contains(githubAction, "CredScope@v"+version) {
		t.Fatalf("docs/github-action.md example does not reference the current release v%s", version)
	}
	if !strings.Contains(readme, "credscope_"+version+"_windows_amd64.zip") {
		t.Fatalf("README GitHub Release example does not reference the current release archive v%s", version)
	}

	changelog := readTextFile(t, filepath.Join(root, "CHANGELOG.md"))
	if !strings.Contains(changelog, "[0.2.0] - 2026-07-22") {
		t.Fatal("historical v0.2.0 changelog entry must remain")
	}
	if _, err := os.Stat(filepath.Join(root, "packaging", "winget", "Bavlik.CredScope", "0.2.0")); err != nil {
		t.Fatal("historical WinGet 0.2.0 manifest directory must remain")
	}
}

// TestReleaseCheckDoesNotRequireUnpublishedWinGetManifests guards against a
// regression of the release-check ordering bug: scripts/release-check.ps1
// runs BEFORE a version is tagged and its GitHub Release archives exist, so
// it must not require packaging/winget/Bavlik.CredScope/<version>/*.yaml --
// those can only be generated afterward, from real published checksums (see
// docs/RELEASING.md and debian equivalents of "don't check for artifacts
// that can't exist yet").
func TestReleaseCheckDoesNotRequireUnpublishedWinGetManifests(t *testing.T) {
	root := repositoryRoot(t)
	script := readTextFile(t, filepath.Join(root, "scripts", "release-check.ps1"))

	// Explanatory comments are allowed to mention "packaging/winget" (and do,
	// to document why it's deliberately absent); what must never reappear is
	// an actual $requiredFiles array entry building that path.
	requiredFilesStart := strings.Index(script, "$requiredFiles = @(")
	if requiredFilesStart < 0 {
		t.Fatal("release-check.ps1 no longer defines $requiredFiles; update this test")
	}
	requiredFilesEnd := strings.Index(script[requiredFilesStart:], ")")
	if requiredFilesEnd < 0 {
		t.Fatal("could not find the end of the $requiredFiles array in release-check.ps1")
	}
	requiredFilesBlock := script[requiredFilesStart : requiredFilesStart+requiredFilesEnd]
	if strings.Contains(requiredFilesBlock, "packaging/winget") {
		t.Fatal("release-check.ps1's $requiredFiles must not require WinGet manifests before a version is tagged and released")
	}
	if strings.Contains(script, "WinGet manifest version mismatch") {
		t.Fatal("release-check.ps1 must not validate WinGet manifest PackageVersion before a version is tagged and released")
	}

	// The other pre-tag safeguards must remain intact: clean worktree,
	// expected branch, VERSION match, required documentation, no existing
	// local/remote tag, go test, go vet, goreleaser check.
	for _, marker := range []string{
		`git status --porcelain=v1 --untracked-files=all`,
		`$branch -ne $ExpectedBranch`,
		`$versionFile -ne $Version`,
		`'docs/ARCHITECTURE.md'`,
		`'docs/THREAT_MODEL.md'`,
		`refs/tags/v$Version`,
		`git ls-remote --exit-code --tags origin`,
		`'test', './...'`,
		`'vet', './...'`,
		`@('check')`,
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("release-check.ps1 is missing an expected pre-tag safeguard: %q", marker)
		}
	}
}

// TestReleaseCheckChangelogPatternMatchesRealHeadings guards against the
// other half of the release-check ordering bug: the CHANGELOG.md check must
// recognize the real heading shape ("## [0.2.3] - 2026-07-27"), not require
// the literal text "v0.2.3", which never appears in a changelog heading.
func TestReleaseCheckChangelogPatternMatchesRealHeadings(t *testing.T) {
	root := repositoryRoot(t)
	script := readTextFile(t, filepath.Join(root, "scripts", "release-check.ps1"))

	if strings.Contains(script, `[regex]::Escape("v$Version")`) {
		t.Fatal(`release-check.ps1 must not require the literal text "v<version>" inside CHANGELOG.md; changelog headings never use a "v" prefix`)
	}

	version := strings.TrimSpace(readTextFile(t, filepath.Join(root, "VERSION")))
	changelog := readTextFile(t, filepath.Join(root, "CHANGELOG.md"))
	headingPattern := regexp.MustCompile(`(?m)^## \[` + regexp.QuoteMeta(version) + `\] - \d{4}-\d{2}-\d{2}\s*$`)
	if !headingPattern.MatchString(changelog) {
		t.Fatalf("CHANGELOG.md does not contain a '## [%s] - YYYY-MM-DD' heading that release-check.ps1's pattern would recognize", version)
	}
}

// TestReleasingDocumentsWinGetAsPostRelease confirms docs/RELEASING.md still
// orders WinGet manifest generation strictly after tagging and publishing
// GitHub Release assets, matching what scripts/release-check.ps1 (pre-tag)
// and scripts/update-winget-manifest.ps1 (post-release) actually enforce.
func TestReleasingDocumentsWinGetAsPostRelease(t *testing.T) {
	root := repositoryRoot(t)
	releasing := readTextFile(t, filepath.Join(root, "docs", "RELEASING.md"))

	checkIndex := strings.Index(releasing, "release-check.ps1")
	tagIndex := strings.Index(releasing, "git tag")
	publishIndex := strings.Index(releasing, "release workflow succeeds and publishes the archives")
	wingetGenerateIndex := strings.Index(releasing, "update-winget-manifest.ps1")
	wingetValidateIndex := strings.Index(releasing, "winget validate")

	for name, index := range map[string]int{
		"release-check.ps1 step":     checkIndex,
		"git tag step":               tagIndex,
		"publish archives step":      publishIndex,
		"update-winget-manifest.ps1": wingetGenerateIndex,
		"winget validate":            wingetValidateIndex,
	} {
		if index < 0 {
			t.Fatalf("docs/RELEASING.md is missing the %s", name)
		}
	}

	if !(checkIndex < tagIndex && tagIndex < publishIndex && publishIndex < wingetGenerateIndex && wingetGenerateIndex < wingetValidateIndex) {
		t.Fatalf("docs/RELEASING.md must order: pre-tag release check -> tag -> publish release assets -> generate WinGet manifests -> validate WinGet manifests (indexes: %d, %d, %d, %d, %d)", checkIndex, tagIndex, publishIndex, wingetGenerateIndex, wingetValidateIndex)
	}
}

// TestVerifyReportsApprovesOnlyTheSingleBavlikWebsiteLink exercises the
// scripts/verify-reports.go external-resource guard as the CI smoke test
// invokes it: it must accept the one approved footer link and still reject
// any other external href or src, including a doubled approved link.
func TestVerifyReportsApprovesOnlyTheSingleBavlikWebsiteLink(t *testing.T) {
	root := repositoryRoot(t)
	validJSON := []byte(`{"schema_version":"2"}`)

	htmlWith := func(footer string) []byte {
		return []byte("<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\"></head><body><main>content</main>" + footer + "</body></html>")
	}

	cases := []struct {
		name    string
		footer  string
		wantErr bool
	}{
		{"approved link only", `<footer><a href="https://abdullahcv.com">abdullahcv.com</a></footer>`, false},
		{"missing approved link", `<footer>no link</footer>`, true},
		{"approved link duplicated", `<footer><a href="https://abdullahcv.com">a</a><a href="https://abdullahcv.com">b</a></footer>`, true},
		{"unapproved href alongside approved", `<footer><a href="https://abdullahcv.com">a</a><a href="http://evil.example">b</a></footer>`, true},
		{"unapproved src", `<footer><a href="https://abdullahcv.com">a</a><img src="http://evil.example/pixel.png"></footer>`, true},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "credscope.json"), validJSON, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "credscope.html"), htmlWith(testCase.footer), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("go", "run", "./scripts/verify-reports.go", dir)
			cmd.Dir = root
			output, err := cmd.CombinedOutput()
			if testCase.wantErr && err == nil {
				t.Fatalf("expected verify-reports to fail, output: %s", output)
			}
			if !testCase.wantErr && err != nil {
				t.Fatalf("expected verify-reports to pass, err: %v, output: %s", err, output)
			}
		})
	}
}

func readTextFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
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
