package ingest

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/config"
)

func TestRepositoryIntegrationAndSecretNonDisclosure(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vulnerable")
	result, err := Repository(context.Background(), root, config.Default(), "gitleaks.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 2 || len(result.Workflows) != 2 || len(result.Compose) != 1 {
		t.Fatalf("unexpected ingestion counts: findings=%d workflows=%d compose=%d", len(result.Findings), len(result.Workflows), len(result.Compose))
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(encoded)
	for _, forbidden := range []string{"FAKE_RAW_SECRET_FOR_TESTS_ONLY", "DEMO_DATABASE_PASSWORD_VALUE_FOR_TESTS_ONLY", "clearly-fake-demo-password", "deploy --token"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("parsed repository contains forbidden synthetic raw material")
		}
	}
	second, err := Repository(context.Background(), root, config.Default(), "gitleaks.json")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, second) {
		t.Fatal("repository ingestion is not deterministic")
	}
}

func TestRepositoryRejectsMalformedDiscoveredWorkflow(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "malformed")
	_, err := Repository(context.Background(), root, config.Default(), "")
	if err == nil {
		t.Fatal("expected malformed discovered input error")
	}
	if strings.Contains(err.Error(), "FAKE_RAW_SECRET_FOR_TESTS_ONLY") {
		t.Fatal("error leaked synthetic secret")
	}
}
