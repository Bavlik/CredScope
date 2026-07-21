// Package parsers defines Phase 2 structural parser contracts.
package parsers

import (
	"context"

	"github.com/credscope/credscope/internal/domain"
)

type WorkflowParser interface {
	Name() string
	Parse(context.Context, string, string) (domain.Workflow, error)
}

type ComposeParser interface {
	Name() string
	Parse(context.Context, string, string) (domain.ComposeProject, error)
}
