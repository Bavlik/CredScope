// Package adapters defines scanner-neutral adapter contracts.
package adapters

import "github.com/credscope/credscope/internal/domain"

// FindingAdapter is implemented by scanner importers. Keeping this as an alias
// preserves the Phase 1 extension seam without coupling callers to Gitleaks.
type FindingAdapter = domain.FindingSource
