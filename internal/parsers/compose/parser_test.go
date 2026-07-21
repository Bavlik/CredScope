package compose

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/credscope/credscope/internal/domain"
)

func fixtureRoot(kind string) string { return filepath.Join("..", "..", "..", "testdata", kind) }

func parseVulnerable(t *testing.T) domain.ComposeProject {
	t.Helper()
	project, err := New().Parse(context.Background(), fixtureRoot("vulnerable"), "compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	return project
}

func TestParseComposeServicesEnvironmentAndSharing(t *testing.T) {
	project := parseVulnerable(t)
	if len(project.Services) != 3 || project.Services[0].Name != "database" || project.Services[1].Name != "production-api" {
		t.Fatalf("services not deterministic: %#v", project.Services)
	}
	api := findService(t, project, "production-api")
	if !hasReference(api.References, "EXAMPLE_AWS_DEPLOY_KEY") || !hasReference(api.References, "FAKE_PRODUCTION_TOKEN") {
		t.Fatalf("mapping environment references = %#v", api.References)
	}
	database := findService(t, project, "database")
	if !hasReference(database.References, "FAKE_PRODUCTION_TOKEN") || !hasReference(database.References, "DEMO_DATABASE_PASSWORD") {
		t.Fatalf("list environment references = %#v", database.References)
	}
	if len(project.SharedCredentials) != 1 || project.SharedCredentials[0].Name != "FAKE_PRODUCTION_TOKEN" || !reflect.DeepEqual(project.SharedCredentials[0].Services, []string{"database", "production-api", "worker"}) {
		t.Fatalf("shared credentials = %#v", project.SharedCredentials)
	}
}

func TestParseComposePortsVolumesPrivilegeAndNetwork(t *testing.T) {
	project := parseVulnerable(t)
	api := findService(t, project, "production-api")
	if len(api.Ports) != 1 || api.Ports[0].Published != "8443" || api.Ports[0].Target != "443" || api.Ports[0].HostIP != "0.0.0.0" {
		t.Fatalf("ports = %#v", api.Ports)
	}
	if !api.Privileged || !hasSignal(api.Signals, "host_port_published") || !hasSignal(api.Signals, "privileged_service") || !hasSignal(api.Signals, "docker_socket_mount") || !hasSignal(api.Signals, "writable_host_bind_mount") {
		t.Fatalf("service signals = %#v", api.Signals)
	}
	if len(api.Volumes) != 2 || !hasDockerSocket(api.Volumes) {
		t.Fatalf("volumes = %#v", api.Volumes)
	}
	database := findService(t, project, "database")
	if !database.HostNetwork || !hasSignal(database.Signals, "host_network") {
		t.Fatalf("host network not detected: %#v", database)
	}
}

func TestParseComposeEnvFileSecretsAndMetadata(t *testing.T) {
	project := parseVulnerable(t)
	api := findService(t, project, "production-api")
	if len(api.EnvFiles) != 1 || api.EnvFiles[0].Path != "./demo.env" || api.EnvFiles[0].Evidence.Location.Line == 0 {
		t.Fatalf("env_file = %#v", api.EnvFiles)
	}
	if len(api.Secrets) != 1 || api.Secrets[0].Source != "demo_database_password" {
		t.Fatalf("service secrets = %#v", api.Secrets)
	}
	if len(project.Secrets) != 1 || project.Secrets[0].File != "./secrets/demo-database-password.txt" {
		t.Fatalf("top secrets = %#v", project.Secrets)
	}
	if !api.ProductionLike || api.Restart != "always" || api.WorkingDirectory != "/app" || len(api.DependsOn) != 1 {
		t.Fatalf("service metadata = %#v", api)
	}
	if !hasSignal(api.Signals, "missing_explicit_non_root_user") {
		t.Fatal("missing user signal not represented")
	}
	worker := findService(t, project, "worker")
	if !worker.UserSpecified || hasSignal(worker.Signals, "missing_explicit_non_root_user") {
		t.Fatal("explicit user was not respected")
	}
}

func TestComposeDoesNotRetainLiteralEnvironmentSecret(t *testing.T) {
	project := parseVulnerable(t)
	encoded, err := json.Marshal(project)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "clearly-fake-demo-password") {
		t.Fatal("literal environment value was serialized")
	}
	api := findService(t, project, "production-api")
	var found bool
	for _, binding := range api.Environment {
		if binding.Name == "STATIC_DEMO_PASSWORD" {
			found = binding.HasLiteral && binding.LiteralFingerprint != ""
		}
	}
	if !found {
		t.Fatal("literal was not represented by a fingerprint")
	}
}

func TestSafeComposeHasNoPublishedPortOrPrivilege(t *testing.T) {
	project, err := New().Parse(context.Background(), fixtureRoot("safe"), "compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	api := findService(t, project, "api")
	if len(api.Ports) != 0 || api.Privileged || api.HostNetwork || hasSignal(api.Signals, "host_port_published") {
		t.Fatalf("safe service misclassified: %#v", api)
	}
	if len(api.ExposedPorts) != 1 || api.ExposedPorts[0].Name != "8080" {
		t.Fatalf("exposed ports = %#v", api.ExposedPorts)
	}
}

func TestMalformedComposeReturnsTypedSafeError(t *testing.T) {
	_, err := New().Parse(context.Background(), fixtureRoot("malformed"), "compose.yml")
	if err == nil || !strings.Contains(err.Error(), "docker-compose parse error") {
		t.Fatalf("expected typed parse error, got %v", err)
	}
	if strings.Contains(err.Error(), "DEMO_DATABASE_PASSWORD_VALUE") {
		t.Fatal("error leaked synthetic secret")
	}
}

func TestComposeHostileNamesHaveControlsRemoved(t *testing.T) {
	root := t.TempDir()
	content := "services:\n  \"api\\u001b[31m ] --> X[bad]\":\n    image: example.invalid/demo\n"
	if err := os.WriteFile(filepath.Join(root, "compose.yml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	project, err := New().Parse(context.Background(), root, "compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(project.Services[0].Name, "\x1b") || strings.Contains(project.Services[0].Name, "]") {
		t.Fatalf("hostile identifier not sanitized: %q", project.Services[0].Name)
	}
}

func TestComposeParsingAndSerializationAreDeterministic(t *testing.T) {
	first := parseVulnerable(t)
	second := parseVulnerable(t)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("Compose output changed between parses")
	}
	left, _ := json.Marshal(first)
	right, _ := json.Marshal(second)
	if string(left) != string(right) {
		t.Fatal("Compose JSON serialization changed")
	}
}

func TestComposeLongSyntaxAndWindowsBindMount(t *testing.T) {
	root := t.TempDir()
	content := `services:
  api:
    user: "1000"
    ports:
      - target: 8080
        published: 18080
        host_ip: 127.0.0.1
        protocol: tcp
    volumes:
      - type: bind
        source: C:\demo\config
        target: /app/config
        read_only: true
`
	if err := os.WriteFile(filepath.Join(root, "compose.yml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	project, err := New().Parse(context.Background(), root, "compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	api := project.Services[0]
	if api.Ports[0].Published != "18080" || api.Ports[0].Target != "8080" {
		t.Fatalf("long port = %#v", api.Ports[0])
	}
	if !api.Volumes[0].HostBind || !api.Volumes[0].ReadOnly || api.Volumes[0].WritableHostBind {
		t.Fatalf("long volume = %#v", api.Volumes[0])
	}
}

func TestComposeSafelySupportsBoundedYAMLMerges(t *testing.T) {
	root := t.TempDir()
	content := `x-defaults: &defaults
  user: "1000"
  restart: unless-stopped
services:
  api:
    <<: *defaults
    image: example.invalid/demo
`
	if err := os.WriteFile(filepath.Join(root, "compose.yml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	project, err := New().Parse(context.Background(), root, "compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	api := project.Services[0]
	if api.User != "1000" || api.Restart != "unless-stopped" {
		t.Fatalf("merged defaults not applied: %#v", api)
	}
}

func findService(t *testing.T, project domain.ComposeProject, name string) domain.ComposeService {
	t.Helper()
	for _, service := range project.Services {
		if service.Name == name {
			return service
		}
	}
	t.Fatalf("service %q not found", name)
	return domain.ComposeService{}
}
func hasReference(refs []domain.Reference, name string) bool {
	for _, ref := range refs {
		if ref.Name == name {
			return true
		}
	}
	return false
}
func hasSignal(signals []domain.StructuralSignal, kind string) bool {
	for _, signal := range signals {
		if signal.Kind == kind {
			return true
		}
	}
	return false
}
func hasDockerSocket(volumes []domain.ComposeVolume) bool {
	for _, volume := range volumes {
		if volume.DockerSocket {
			return true
		}
	}
	return false
}
