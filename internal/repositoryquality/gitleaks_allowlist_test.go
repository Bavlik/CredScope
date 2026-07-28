package repositoryquality

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// gitleaksAllowlist is a minimal, hand-rolled representation of one
// [[allowlists]] or [[rules.allowlists]] TOML block from .gitleaks.toml. A
// full TOML parser is deliberately not introduced as a new dependency for
// this one config file; the format here is simple enough (flat key/value
// pairs, single-level string arrays) that targeted regexes and a small
// string-aware scanner are sufficient and keep this guard dependency-free,
// matching this repository's minimal-dependency posture.
type gitleaksAllowlist struct {
	Description string
	Condition   string
	RegexTarget string
	Paths       []string
	Regexes     []string
	TargetRules []string
}

// gitleaksRuleAllowlist is a [[rules.allowlists]] entry together with the
// ID of the [[rules]] block it belongs to.
type gitleaksRuleAllowlist struct {
	RuleID string
	gitleaksAllowlist
}

var (
	gitleaksDescriptionRe = regexp.MustCompile(`(?m)^\s*description\s*=\s*"([^"]*)"`)
	gitleaksConditionRe   = regexp.MustCompile(`(?m)^\s*condition\s*=\s*"([^"]*)"`)
	gitleaksRegexTargetRe = regexp.MustCompile(`(?m)^\s*regexTarget\s*=\s*"([^"]*)"`)
	gitleaksRuleIDRe      = regexp.MustCompile(`(?m)^\s*id\s*=\s*"([^"]*)"`)
	gitleaksArrayEntryRe  = regexp.MustCompile(`'''(.*?)'''|"([^"]*)"`)
	gitleaksUseDefaultRe  = regexp.MustCompile(`(?m)^\s*useDefault\s*=\s*(true|false)`)
)

func gitleaksTOMLPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repositoryRoot(t), ".gitleaks.toml")
}

func readGitleaksTOML(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(gitleaksTOMLPath(t))
	if err != nil {
		t.Fatalf("read .gitleaks.toml: %v", err)
	}
	return string(data)
}

func parseFields(block string) gitleaksAllowlist {
	return gitleaksAllowlist{
		Description: firstSubmatch(gitleaksDescriptionRe, block),
		Condition:   firstSubmatch(gitleaksConditionRe, block),
		RegexTarget: firstSubmatch(gitleaksRegexTargetRe, block),
		Paths:       extractArray(block, "paths"),
		Regexes:     extractArray(block, "regexes"),
		TargetRules: extractArray(block, "targetRules"),
	}
}

// parseGitleaksGlobalAllowlists splits .gitleaks.toml on top-level
// "[[allowlists]]" headers and extracts each block's fields. It never
// matches the nested "[[rules.allowlists]]" header, since that string does
// not contain "[[allowlists]]" as a substring ("rules." sits between the
// two opening brackets and the word), and never captures content past the
// start of a following [[rules]] block, since gitleaksArrayEntryRe-based
// field extraction only looks within each split segment.
func parseGitleaksGlobalAllowlists(t *testing.T, document string) []gitleaksAllowlist {
	t.Helper()
	// Truncate at the first [[rules]] block so a top-level split can never
	// accidentally include rule-scoped content in a global block's tail.
	global := document
	if idx := strings.Index(document, "\n[[rules]]"); idx >= 0 {
		global = document[:idx]
	}
	blocks := strings.Split(global, "[[allowlists]]")
	var allowlists []gitleaksAllowlist
	for _, raw := range blocks[1:] { // blocks[0] is everything before the first allowlist
		allowlists = append(allowlists, parseFields(raw))
	}
	return allowlists
}

// parseGitleaksRuleAllowlists finds every [[rules]] block, reads its id,
// and extracts every nested [[rules.allowlists]] entry within it.
func parseGitleaksRuleAllowlists(t *testing.T, document string) []gitleaksRuleAllowlist {
	t.Helper()
	var result []gitleaksRuleAllowlist
	ruleBlocks := strings.Split(document, "\n[[rules]]")
	for _, raw := range ruleBlocks[1:] { // ruleBlocks[0] is everything before the first [[rules]] block
		ruleID := firstSubmatch(gitleaksRuleIDRe, raw)
		subBlocks := strings.Split(raw, "[[rules.allowlists]]")
		for _, sub := range subBlocks[1:] {
			result = append(result, gitleaksRuleAllowlist{RuleID: ruleID, gitleaksAllowlist: parseFields(sub)})
		}
	}
	return result
}

// ruleBlockBody returns the content of a [[rules]] block up to (but not
// including) its first nested [[rules.allowlists]] header — i.e. exactly
// the part of the block that is allowed to contain only `id`.
func ruleBlockBody(document, ruleID string) (string, bool) {
	ruleBlocks := strings.Split(document, "\n[[rules]]")
	for _, raw := range ruleBlocks[1:] {
		if firstSubmatch(gitleaksRuleIDRe, raw) != ruleID {
			continue
		}
		if idx := strings.Index(raw, "[[rules.allowlists]]"); idx >= 0 {
			return raw[:idx], true
		}
		return raw, true
	}
	return "", false
}

func firstSubmatch(re *regexp.Regexp, text string) string {
	match := re.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

// extractArray finds `key = [...]` and returns its string entries. TOML
// arrays here appear in two styles: single-line double-quoted
// (targetRules = ["generic-api-key"]) and multi-line triple-quoted (paths,
// regexes, one entry per line, optionally indented under [[rules.allowlists]]).
// A regex value can itself legitimately contain "]" (e.g. "[a-f0-9]{64}"),
// so the closing bracket is found with a small string-aware scan rather
// than a regex, to avoid stopping at that inner bracket instead of the
// array's real end.
func extractArray(block, key string) []string {
	marker := regexp.MustCompile(`(?m)^\s*` + key + `\s*=\s*\[`)
	loc := marker.FindStringIndex(block)
	if loc == nil {
		return nil
	}
	rest := block[loc[1]:]
	end := indexOfArrayClose(rest)
	if end < 0 {
		return nil
	}
	entries := gitleaksArrayEntryRe.FindAllStringSubmatch(rest[:end], -1)
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry[1] != "" {
			values = append(values, entry[1]) // triple-quoted literal
		} else {
			values = append(values, entry[2]) // double-quoted string
		}
	}
	return values
}

// indexOfArrayClose returns the index of the "]" that closes an array whose
// opening "[" was just before s, skipping over "]" characters that appear
// inside triple-single-quoted or double-quoted TOML string literals.
func indexOfArrayClose(s string) int {
	i := 0
	for i < len(s) {
		switch {
		case strings.HasPrefix(s[i:], "'''"):
			end := strings.Index(s[i+3:], "'''")
			if end < 0 {
				return -1
			}
			i += 3 + end + 3
		case s[i] == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(s) {
				return -1
			}
			i = j + 1
		case s[i] == ']':
			return i
		default:
			i++
		}
	}
	return -1
}

func containsPattern(values []string, substring string) bool {
	for _, value := range values {
		if strings.Contains(value, substring) {
			return true
		}
	}
	return false
}

func stringSlicesEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// isCorpusCanaryShape recognizes the global raw-fixture-input canary
// allowlist: broadly scoped to any path under testdata/corpus/, narrowed
// only by requiring the CREDSCOPE_TEST_CANARY_ namespace in the matched
// text, via condition = "AND" so it can never match on path alone.
func isCorpusCanaryShape(a gitleaksAllowlist) bool {
	return a.Condition == "AND" &&
		containsPattern(a.Paths, "testdata/corpus/") &&
		containsPattern(a.Regexes, "CREDSCOPE_TEST_CANARY_")
}

// isCorpusGeneratedGoldenSHA256Shape recognizes the rule-specific
// generated-golden-output allowlist: narrowly scoped to exactly
// expected.json/expected.sarif files and exactly a 64-character lowercase
// hex pattern, via condition = "AND" so it can never match on path alone —
// and, being a [[rules.allowlists]] entry, applies only within its parent
// rule's own findings, never via a global targetRules shortcut.
const (
	corpusGoldenSHA256PathPattern  = `^testdata/corpus/.*/expected\.(json|sarif)$`
	corpusGoldenSHA256RegexPattern = `^[a-f0-9]{64}$`
)

func isCorpusGeneratedGoldenSHA256Shape(a gitleaksAllowlist) bool {
	return a.Condition == "AND" &&
		a.RegexTarget == "" &&
		stringSlicesEqual(a.Paths, []string{corpusGoldenSHA256PathPattern}) &&
		stringSlicesEqual(a.Regexes, []string{corpusGoldenSHA256RegexPattern})
}

// TestGitleaksUseDefaultRemainsEnabled proves the config still extends
// gitleaks' default ruleset rather than replacing it with a narrower,
// weaker one.
func TestGitleaksUseDefaultRemainsEnabled(t *testing.T) {
	document := readGitleaksTOML(t)
	match := gitleaksUseDefaultRe.FindStringSubmatch(document)
	if len(match) < 2 {
		t.Fatal(".gitleaks.toml does not set useDefault under [extend]")
	}
	if match[1] != "true" {
		t.Fatalf("useDefault must remain true, got %q", match[1])
	}
}

// TestGitleaksExactlyFourGlobalAllowlistsRemain proves the global
// [[allowlists]] list is exactly the original three entries plus the
// corpus canary allowlist — the rule-specific golden-output allowlist must
// NOT appear here; it lives under [[rules]] id = "generic-api-key" instead.
func TestGitleaksExactlyFourGlobalAllowlistsRemain(t *testing.T) {
	document := readGitleaksTOML(t)
	global := parseGitleaksGlobalAllowlists(t, document)
	if len(global) != 4 {
		t.Fatalf("expected exactly 4 global allowlist entries (3 original + corpus canary), got %d: %#v", len(global), descriptions(global))
	}
	want := []string{
		"Synthetic Gitleaks input fixtures used to verify immediate redaction",
		"Generated secret-safe examples contain irreversible SHA-256 fingerprint fields",
		"Synthetic test-corpus canaries only: requires BOTH a testdata/corpus/ path AND the exact CREDSCOPE_TEST_CANARY_ namespace, never a path-only match",
		"Git-ignored local toolchains, build outputs, and temporary reports are never release inputs",
	}
	for _, description := range want {
		found := false
		for _, allowlist := range global {
			if allowlist.Description == description {
				found = true
			}
		}
		if !found {
			t.Errorf("pre-existing global allowlist %q is missing or was modified", description)
		}
	}
}

func descriptions(allowlists []gitleaksAllowlist) []string {
	result := make([]string, len(allowlists))
	for i, allowlist := range allowlists {
		result[i] = allowlist.Description
	}
	return result
}

// TestGitleaksGlobalCorpusCanaryAllowlistRequiresPathAndNamespace proves the
// global corpus canary allowlist exists, is unchanged, and requires BOTH a
// testdata/corpus/ path AND the exact CREDSCOPE_TEST_CANARY_ namespace via
// condition = "AND" — never a path-only match.
func TestGitleaksGlobalCorpusCanaryAllowlistRequiresPathAndNamespace(t *testing.T) {
	global := parseGitleaksGlobalAllowlists(t, readGitleaksTOML(t))

	var canary *gitleaksAllowlist
	for i := range global {
		if isCorpusCanaryShape(global[i]) {
			canary = &global[i]
			break
		}
	}
	if canary == nil {
		t.Fatal("no global allowlist entry matches the approved canary shape (condition AND, testdata/corpus/ path, CREDSCOPE_TEST_CANARY_ regex)")
	}
	if canary.Condition != "AND" {
		t.Fatalf("corpus canary allowlist must use condition = \"AND\", got %q", canary.Condition)
	}
	if !containsPattern(canary.Paths, `testdata/corpus/`) {
		t.Fatalf("corpus canary allowlist path pattern must be restricted to testdata/corpus/, got %v", canary.Paths)
	}
	if len(canary.Regexes) == 0 || !containsPattern(canary.Regexes, "CREDSCOPE_TEST_CANARY_") {
		t.Fatalf("corpus canary allowlist must require the CREDSCOPE_TEST_CANARY_ namespace, got regexes %v", canary.Regexes)
	}
}

// TestGitleaksNoGlobalGoldenOutputAllowlistUsingTargetRules proves the
// global targetRules-based golden-output allowlist (the shape that did not
// work against the pinned Gitleaks v8.30.1 binary, per Kali testing) is
// gone: no global allowlist may reference a testdata/corpus expected.json/
// expected.sarif path with a 64-hex regex, whether or not it sets
// targetRules.
func TestGitleaksNoGlobalGoldenOutputAllowlistUsingTargetRules(t *testing.T) {
	global := parseGitleaksGlobalAllowlists(t, readGitleaksTOML(t))
	for _, allowlist := range global {
		if isCorpusGeneratedGoldenSHA256Shape(allowlist) {
			t.Fatalf("global allowlist %q matches the removed golden-output shape; it must be a [[rules.allowlists]] entry under generic-api-key instead", allowlist.Description)
		}
		if len(allowlist.TargetRules) > 0 && containsPattern(allowlist.Paths, "testdata/corpus") {
			t.Fatalf("global allowlist %q uses targetRules together with a testdata/corpus path; the tested, working shape is rule-specific ([[rules.allowlists]]), not global targetRules", allowlist.Description)
		}
	}
}

// TestGitleaksRuleSpecificCorpusGoldenAllowlistIsNarrowlyScoped proves the
// generic-api-key rule carries exactly one nested [[rules.allowlists]]
// entry, and that it matches the Kali-tested shape exactly: condition AND,
// the exact path and secret regexes, and no regexTarget override (the
// default target is the extracted Secret, which is what this allowlist
// must check against).
func TestGitleaksRuleSpecificCorpusGoldenAllowlistIsNarrowlyScoped(t *testing.T) {
	document := readGitleaksTOML(t)
	ruleAllowlists := parseGitleaksRuleAllowlists(t, document)

	var matching []gitleaksRuleAllowlist
	for _, ra := range ruleAllowlists {
		if isCorpusGeneratedGoldenSHA256Shape(ra.gitleaksAllowlist) {
			matching = append(matching, ra)
		}
	}
	if len(matching) != 1 {
		t.Fatalf("expected exactly 1 rule-specific corpus golden allowlist, found %d", len(matching))
	}
	golden := matching[0]

	if golden.RuleID != "generic-api-key" {
		t.Errorf("rule-specific golden allowlist's parent rule id must be exactly \"generic-api-key\", got %q", golden.RuleID)
	}
	if golden.Condition != "AND" {
		t.Errorf("rule-specific golden allowlist must use condition = \"AND\", got %q", golden.Condition)
	}
	if golden.RegexTarget != "" {
		t.Errorf("rule-specific golden allowlist must not set regexTarget (default targets the extracted Secret); got %q", golden.RegexTarget)
	}
	if !stringSlicesEqual(golden.Paths, []string{corpusGoldenSHA256PathPattern}) {
		t.Errorf("rule-specific golden allowlist paths must be exactly [%q], got %v", corpusGoldenSHA256PathPattern, golden.Paths)
	}
	if !stringSlicesEqual(golden.Regexes, []string{corpusGoldenSHA256RegexPattern}) {
		t.Errorf("rule-specific golden allowlist regexes must be exactly [%q], got %v", corpusGoldenSHA256RegexPattern, golden.Regexes)
	}
	if len(golden.TargetRules) != 0 {
		t.Errorf("rule-specific golden allowlist must not also set targetRules; got %v", golden.TargetRules)
	}
}

// TestGitleaksRuleSpecificCorpusGoldenAllowlistCannotBeBroadened exercises
// the allowlist regex's actual matching semantics: it must match only
// well-formed 64-character lowercase hex SHA-256 digests, and reject every
// neighboring shape a careless future edit might broaden it into.
func TestGitleaksRuleSpecificCorpusGoldenAllowlistCannotBeBroadened(t *testing.T) {
	ruleAllowlists := parseGitleaksRuleAllowlists(t, readGitleaksTOML(t))

	var golden *gitleaksRuleAllowlist
	for i := range ruleAllowlists {
		if isCorpusGeneratedGoldenSHA256Shape(ruleAllowlists[i].gitleaksAllowlist) {
			golden = &ruleAllowlists[i]
			break
		}
	}
	if golden == nil {
		t.Fatal("no rule-specific allowlist entry matches the approved generated-golden-SHA-256 shape")
	}
	if len(golden.Regexes) != 1 {
		t.Fatalf("expected exactly one regex on the golden SHA-256 allowlist, got %v", golden.Regexes)
	}

	pattern, err := regexp.Compile(golden.Regexes[0])
	if err != nil {
		t.Fatalf("golden SHA-256 allowlist regex does not compile: %v", err)
	}

	// Built at runtime rather than as a source-code literal: a hard-coded
	// 64-character lowercase hex string in this file would itself match the
	// generic-api-key rule when Gitleaks scans CredScope's own source, since
	// the allowlist above only exempts testdata/corpus/**/expected.* paths.
	// This test verifies the regex's shape, not any specific digest, so a
	// synthetic runtime-generated value serves exactly as well.
	validSHA256 := strings.Repeat("a", 64)
	canaryToken := strings.Join([]string{
		"CREDSCOPE",
		"TEST",
		"CANARY",
		"GITLEAKS",
		"NORMAL",
		"001",
	}, "_")
	cases := []struct {
		name    string
		value   string
		matches bool
	}{
		{"valid lowercase 64-hex SHA-256", validSHA256, true},
		{"uppercase hex", strings.ToUpper(validSHA256), false},
		{"mixed-case hex", strings.ToUpper(validSHA256[:1]) + validSHA256[1:], false},
		{"63 characters (one short)", validSHA256[:63], false},
		{"65 characters (one long)", validSHA256 + "0", false},
		{"non-hex character", "g" + validSHA256[1:], false},
		{"arbitrary canary token", canaryToken, false},
		{"empty string", "", false},
		{"64-hex embedded in a longer string", "prefix-" + validSHA256 + "-suffix", false},
	}
	for _, testCase := range cases {
		if got := pattern.MatchString(testCase.value); got != testCase.matches {
			t.Errorf("%s: pattern.MatchString(%q) = %v, want %v", testCase.name, testCase.value, got, testCase.matches)
		}
	}
}

// TestGitleaksGenericAPIKeyRuleDoesNotRedefineDetectionFields proves the
// [[rules]] id = "generic-api-key" block contains only the rule ID and its
// nested [[rules.allowlists]] entry — it must never redefine the rule's own
// detection fields (regex, secretGroup, entropy, keywords) or disable it,
// since gitleaks merges a [[rules]] block by ID onto the extended default
// rule of the same ID, and any of those fields here would silently override
// (rather than merely allowlist within) the built-in generic-api-key rule.
func TestGitleaksGenericAPIKeyRuleDoesNotRedefineDetectionFields(t *testing.T) {
	document := readGitleaksTOML(t)
	body, ok := ruleBlockBody(document, "generic-api-key")
	if !ok {
		t.Fatal("no [[rules]] block with id = \"generic-api-key\" found")
	}
	forbidden := []string{"regex", "secretGroup", "entropy", "keywords", "disabled"}
	for _, field := range forbidden {
		if regexp.MustCompile(`(?m)^\s*` + field + `\s*=`).MatchString(body) {
			t.Errorf("[[rules]] id = \"generic-api-key\" block must not redefine %q; it may contain only id and a nested [[rules.allowlists]] entry", field)
		}
	}
}

// TestGitleaksNoUnapprovedCorpusAllowlistShape proves every allowlist entry
// anywhere in the document (global or rule-specific) that references a
// testdata/corpus path matches exactly one of the two approved shapes —
// the global canary allowlist, or the generic-api-key rule-specific golden
// allowlist — and that there is exactly one of each, never a third,
// broader, or otherwise unrecognized corpus allowlist under any rule.
func TestGitleaksNoUnapprovedCorpusAllowlistShape(t *testing.T) {
	document := readGitleaksTOML(t)
	global := parseGitleaksGlobalAllowlists(t, document)
	ruleAllowlists := parseGitleaksRuleAllowlists(t, document)

	canaryCount, unknownGlobalCount := 0, 0
	for _, allowlist := range global {
		if !containsPattern(allowlist.Paths, "testdata/corpus") {
			continue
		}
		if isCorpusCanaryShape(allowlist) {
			canaryCount++
			continue
		}
		unknownGlobalCount++
		t.Errorf("global allowlist %q references testdata/corpus but does not match the approved canary shape", allowlist.Description)
	}
	if canaryCount != 1 {
		t.Errorf("expected exactly 1 global corpus canary allowlist, found %d", canaryCount)
	}

	goldenCount, unknownRuleCount := 0, 0
	for _, ra := range ruleAllowlists {
		if !containsPattern(ra.Paths, "testdata/corpus") {
			continue
		}
		if isCorpusGeneratedGoldenSHA256Shape(ra.gitleaksAllowlist) && ra.RuleID == "generic-api-key" {
			goldenCount++
			continue
		}
		unknownRuleCount++
		t.Errorf("rule-specific allowlist %q under rule %q references testdata/corpus but does not match the approved generic-api-key golden-SHA-256 shape", ra.Description, ra.RuleID)
	}
	if goldenCount != 1 {
		t.Errorf("expected exactly 1 rule-specific corpus golden allowlist under generic-api-key, found %d", goldenCount)
	}
	if unknownGlobalCount+unknownRuleCount != 0 {
		t.Fatalf("found %d unapproved corpus allowlist shape(s)", unknownGlobalCount+unknownRuleCount)
	}
}
