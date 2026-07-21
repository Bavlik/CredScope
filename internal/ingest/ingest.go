// Package ingest orchestrates Phase 2 adapters and parsers into neutral models.
package ingest

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/Bavlik/CredScope/internal/adapters/gitleaks"
	"github.com/Bavlik/CredScope/internal/config"
	"github.com/Bavlik/CredScope/internal/discovery"
	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/parsers/compose"
	"github.com/Bavlik/CredScope/internal/parsers/githubactions"
)

func Repository(ctx context.Context, root string, cfg config.Config, gitleaksReport string) (domain.ParsedRepository, error) {
	if err := ctx.Err(); err != nil {
		return domain.ParsedRepository{}, err
	}
	if err := cfg.Validate(); err != nil {
		return domain.ParsedRepository{}, fmt.Errorf("validate ingestion configuration: %w", err)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return domain.ParsedRepository{}, fmt.Errorf("resolve repository root: %w", err)
	}
	finder, err := discovery.New(absRoot, discovery.Options{Includes: cfg.Scan.Include, Excludes: cfg.Scan.Exclude})
	if err != nil {
		return domain.ParsedRepository{}, err
	}
	files, err := finder.Find()
	if err != nil {
		return domain.ParsedRepository{}, err
	}
	result := domain.ParsedRepository{RepositoryRoot: absRoot}
	workflowParser := githubactions.New()
	composeParser := compose.New()
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return domain.ParsedRepository{}, err
		}
		switch file.Kind {
		case discovery.KindGitHubActions:
			workflow, parseErr := workflowParser.Parse(ctx, absRoot, file.Path)
			if parseErr != nil {
				return domain.ParsedRepository{}, parseErr
			}
			result.Workflows = append(result.Workflows, workflow)
			result.Warnings = append(result.Warnings, workflow.Warnings...)
		case discovery.KindCompose:
			project, parseErr := composeParser.Parse(ctx, absRoot, file.Path)
			if parseErr != nil {
				return domain.ParsedRepository{}, parseErr
			}
			result.Compose = append(result.Compose, project)
			result.Warnings = append(result.Warnings, project.Warnings...)
		}
	}
	if gitleaksReport != "" {
		result.Findings, err = gitleaks.NewWithPathPrefix(absRoot, gitleaksReport, cfg.Gitleaks.PathPrefix).Findings(ctx)
		if err != nil {
			return domain.ParsedRepository{}, err
		}
	}
	sort.Slice(result.Workflows, func(i, j int) bool { return result.Workflows[i].File < result.Workflows[j].File })
	sort.Slice(result.Compose, func(i, j int) bool { return result.Compose[i].File < result.Compose[j].File })
	sort.Slice(result.Warnings, func(i, j int) bool {
		if result.Warnings[i].Location.Path != result.Warnings[j].Location.Path {
			return result.Warnings[i].Location.Path < result.Warnings[j].Location.Path
		}
		if result.Warnings[i].Location.Line != result.Warnings[j].Location.Line {
			return result.Warnings[i].Location.Line < result.Warnings[j].Location.Line
		}
		return result.Warnings[i].Code < result.Warnings[j].Code
	})
	return result, nil
}
