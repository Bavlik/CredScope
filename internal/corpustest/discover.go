package corpustest

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Discover walks corpusRoot (testdata/corpus) for <category>/<case-id>/case.yaml
// manifests, loads and validates every one, and returns them sorted
// deterministically by ID. It fails on the first structural problem it
// cannot recover from (unreadable directory) but aggregates all manifest
// validation errors so a single run reports every broken case at once.
//
// Discover only checks global, filter-independent structural safety: unique
// IDs, valid manifests, confined paths, no symlinks, required README.md.
// It never requires golden files to exist — that is a property of what was
// actually selected to run (see RequireGoldens), checked only after any
// -case filter has been applied, so an unrelated case missing its goldens
// can never block a different, explicitly selected case from running.
func Discover(corpusRoot string) ([]Case, error) {
	categoryDirs, err := os.ReadDir(corpusRoot)
	if err != nil {
		return nil, fmt.Errorf("read corpus root %s: %w", corpusRoot, err)
	}

	var cases []Case
	var problems []string
	seenIDs := make(map[string]string) // id -> first case.yaml path that declared it

	for _, categoryEntry := range categoryDirs {
		if !categoryEntry.IsDir() {
			continue
		}
		category := Category(categoryEntry.Name())
		if !containsCategory(knownCategories(), category) {
			continue // non-category directories (e.g. none today) are ignored, not errors
		}
		categoryDir := filepath.Join(corpusRoot, categoryEntry.Name())
		caseDirs, err := os.ReadDir(categoryDir)
		if err != nil {
			return nil, fmt.Errorf("read category %s: %w", category, err)
		}
		for _, caseEntry := range caseDirs {
			if !caseEntry.IsDir() {
				continue
			}
			caseDir := filepath.Join(categoryDir, caseEntry.Name())
			manifestPath := filepath.Join(caseDir, "case.yaml")
			if _, statErr := os.Stat(manifestPath); statErr != nil {
				problems = append(problems, fmt.Sprintf("%s: missing case.yaml", caseDir))
				continue
			}
			manifest, err := LoadManifest(manifestPath)
			if err != nil {
				problems = append(problems, err.Error())
				continue
			}
			if err := manifest.Validate(caseDir, category); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", manifestPath, err))
				continue
			}
			if readmePath := filepath.Join(caseDir, "README.md"); !fileExists(readmePath) {
				problems = append(problems, fmt.Sprintf("%s: missing README.md", caseDir))
				continue
			}
			if existing, ok := seenIDs[manifest.ID]; ok {
				problems = append(problems, fmt.Sprintf("%s: duplicate case id %q also declared at %s", manifestPath, manifest.ID, existing))
				continue
			}
			seenIDs[manifest.ID] = manifestPath
			cases = append(cases, Case{ID: manifest.ID, Dir: caseDir, Path: manifestPath, Manifest: manifest})
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		message := fmt.Sprintf("corpus discovery found %d problem(s):", len(problems))
		for _, problem := range problems {
			message += "\n  - " + problem
		}
		return nil, fmt.Errorf("%s", message)
	}

	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	return cases, nil
}

// ByID returns the single case matching id, deterministically re-running
// Discover. It is a convenience for `go test -run TestCorpus/<id>` style
// single-case debugging outside the *testing.T subtest tree.
func ByID(corpusRoot, id string) (Case, error) {
	cases, err := Discover(corpusRoot)
	if err != nil {
		return Case{}, err
	}
	for _, c := range cases {
		if c.ID == id {
			return c, nil
		}
	}
	return Case{}, fmt.Errorf("no corpus case with id %q", id)
}

// Filter narrows cases to the single case matching id. Case IDs are
// non-secret, human-chosen kebab-case slugs (never scanner findings or
// evidence text), so an unknown ID's error safely lists every valid ID to
// help correct a typo.
func Filter(cases []Case, id string) ([]Case, error) {
	if id == "" {
		return cases, nil
	}
	for _, c := range cases {
		if c.ID == id {
			return []Case{c}, nil
		}
	}
	ids := make([]string, len(cases))
	for i, c := range cases {
		ids[i] = c.ID
	}
	sort.Strings(ids)
	return nil, fmt.Errorf("no corpus case with id %q; valid ids: %s", id, strings.Join(ids, ", "))
}

// RequireGoldens checks that every success-expecting case among cases has
// committed expected.json/expected.sarif files. Pass the already-filtered
// case list (e.g. the result of Filter) so an unrelated, unselected case's
// missing goldens never blocks a different case from running.
func RequireGoldens(cases []Case) error {
	var missing []string
	for _, c := range cases {
		if c.Manifest.Expect.Result != ExpectSuccess {
			continue
		}
		for _, name := range []string{"expected.json", "expected.sarif"} {
			if _, err := os.Stat(filepath.Join(c.Dir, name)); err != nil {
				missing = append(missing, c.ID+"/"+name)
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("missing golden file(s): %s (regenerate with -update, optionally scoped with -case)", strings.Join(missing, ", "))
}

func fileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink == 0
}
