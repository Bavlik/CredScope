package corpustest

import (
	"context"
	"fmt"
	"sort"
)

// PendingGolden is one case's freshly rendered artifacts, staged in memory
// before any file on disk is touched.
type PendingGolden struct {
	Case  Case
	JSON  []byte
	SARIF []byte
}

// StageAll executes every success-expecting case in cases (controlled-error
// cases carry no goldens and are skipped) and returns their rendered
// artifacts staged in memory only. It returns an error on the very first
// case that fails, before staging any further case, so a caller can
// guarantee that when this returns an error, nothing has been written to
// disk for any case in the batch — the batch is all-or-nothing.
//
// workDirFor supplies an isolated working directory per case (tests pass
// t.TempDir; production code can do the same).
func StageAll(ctx context.Context, cases []Case, workDirFor func(id string) string) ([]PendingGolden, error) {
	var pending []PendingGolden
	for _, c := range cases {
		if c.Manifest.Expect.Result == ExpectError {
			continue
		}
		outcome, err := Execute(ctx, c, workDirFor(c.ID))
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", c.ID, err)
		}
		pending = append(pending, PendingGolden{Case: c, JSON: outcome.Rendered.JSON, SARIF: outcome.Rendered.SARIF})
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].Case.ID < pending[j].Case.ID })
	return pending, nil
}

// PublishAll atomically writes every staged golden file and returns the IDs
// written, in order. Call it only after StageAll has succeeded for the
// entire batch you intend to publish.
func PublishAll(pending []PendingGolden) ([]string, error) {
	updated := make([]string, 0, len(pending))
	for _, item := range pending {
		if err := updateGolden(item.Case, "expected.json", item.JSON); err != nil {
			return updated, fmt.Errorf("write golden expected.json for %s: %w", item.Case.ID, err)
		}
		if err := updateGolden(item.Case, "expected.sarif", item.SARIF); err != nil {
			return updated, fmt.Errorf("write golden expected.sarif for %s: %w", item.Case.ID, err)
		}
		updated = append(updated, item.Case.ID)
	}
	return updated, nil
}
