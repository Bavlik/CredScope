package main

import "testing"

func TestDevelopmentBuildMetadataDefaults(t *testing.T) {
	if version != "dev" || commit != "none" || date != "unknown" {
		t.Fatalf("development metadata = %q %q %q", version, commit, date)
	}
}
