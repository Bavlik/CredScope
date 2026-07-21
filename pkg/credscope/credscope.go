// Package credscope exposes stable foundations for embedding CredScope.
package credscope

import (
	"github.com/credscope/credscope/internal/config"
	"github.com/credscope/credscope/internal/discovery"
	"github.com/credscope/credscope/internal/domain"
)

const (
	SchemaVersion = domain.SchemaVersion
	ScoringPolicy = domain.ScoringPolicy
)

type (
	Config             = config.Config
	Finding            = domain.Finding
	CredentialIdentity = domain.CredentialIdentity
	Report             = domain.Report
	DiscoveredFile     = discovery.File
)

func DefaultConfig() Config { return config.Default() }

// Discover returns supported inputs without parsing or executing them.
func Discover(repositoryRoot string, cfg Config) ([]DiscoveredFile, error) {
	finder, err := discovery.New(repositoryRoot, discovery.Options{
		Includes: cfg.Scan.Include,
		Excludes: cfg.Scan.Exclude,
	})
	if err != nil {
		return nil, err
	}
	return finder.Find()
}
