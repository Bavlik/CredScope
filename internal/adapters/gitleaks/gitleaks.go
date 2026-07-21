// Package gitleaks safely imports Gitleaks JSON without retaining secret values.
package gitleaks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/Bavlik/CredScope/internal/discovery"
	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/input"
	"github.com/Bavlik/CredScope/internal/sanitizer"
)

type ErrorKind string

const (
	ErrorMalformedJSON    ErrorKind = "malformed_json"
	ErrorInvalidStructure ErrorKind = "invalid_gitleaks_structure"
	ErrorUnsafePath       ErrorKind = "unsafe_finding_path"
)

type ParseError struct {
	Kind   ErrorKind
	Path   string
	Index  int
	Offset int64
	Msg    string
}

func (e *ParseError) Error() string {
	where := e.Path
	if e.Index >= 0 {
		where += " finding " + strconv.Itoa(e.Index+1)
	}
	if e.Offset > 0 {
		where += " byte " + strconv.FormatInt(e.Offset, 10)
	}
	return fmt.Sprintf("%s: %s: %s", e.Kind, where, e.Msg)
}

type Adapter struct {
	Root       string
	Path       string
	PathPrefix string
}

var _ domain.FindingSource = (*Adapter)(nil)

func New(root, reportPath string) *Adapter { return &Adapter{Root: root, Path: reportPath} }
func NewWithPathPrefix(root, reportPath, prefix string) *Adapter {
	return &Adapter{Root: root, Path: reportPath, PathPrefix: prefix}
}

func (a *Adapter) Name() string { return "gitleaks" }

func (a *Adapter) Findings(ctx context.Context) ([]domain.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, rel, err := input.ReadFile(a.Root, a.Path, discovery.DefaultMaxFileSize)
	if err != nil {
		return nil, &ParseError{Kind: ErrorInvalidStructure, Path: "gitleaks report", Index: -1, Msg: err.Error()}
	}
	rawFindings, err := decode(data, rel)
	if err != nil {
		return nil, err
	}
	findings := make([]domain.Finding, 0, len(rawFindings))
	for index := range rawFindings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		finding, convertErr := convert(rawFindings[index], rel, index, a.PathPrefix)
		if convertErr != nil {
			return nil, convertErr
		}
		findings = append(findings, finding)
	}
	return deduplicate(findings), nil
}

type rawFinding struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	File        string   `json:"File"`
	Commit      string   `json:"Commit"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Tags        []string `json:"Tags"`
	Secret      string   `json:"Secret"`
	Match       string   `json:"Match"`
	Fingerprint string   `json:"Fingerprint"`
	Key         string   `json:"Key"`
}

func decode(data []byte, reportPath string) ([]rawFinding, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, &ParseError{Kind: ErrorMalformedJSON, Path: reportPath, Index: -1, Msg: "report is empty"}
	}
	var findings []rawFinding
	switch trimmed[0] {
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, jsonError(reportPath, err)
		}
		findings = make([]rawFinding, 0, len(items))
		for index, item := range items {
			item = bytes.TrimSpace(item)
			if len(item) == 0 || item[0] != '{' {
				return nil, &ParseError{Kind: ErrorInvalidStructure, Path: reportPath, Index: index, Msg: "finding must be a JSON object"}
			}
			var finding rawFinding
			if err := json.Unmarshal(item, &finding); err != nil {
				return nil, jsonError(reportPath, err)
			}
			findings = append(findings, finding)
		}
	case '{':
		var finding rawFinding
		if err := json.Unmarshal(trimmed, &finding); err != nil {
			return nil, jsonError(reportPath, err)
		}
		findings = []rawFinding{finding}
	default:
		return nil, &ParseError{Kind: ErrorInvalidStructure, Path: reportPath, Index: -1, Msg: "expected a JSON object or array"}
	}
	if findings == nil {
		findings = []rawFinding{}
	}
	return findings, nil
}

func jsonError(reportPath string, err error) error {
	if syntax, ok := err.(*json.SyntaxError); ok {
		return &ParseError{Kind: ErrorMalformedJSON, Path: reportPath, Index: -1, Offset: syntax.Offset, Msg: "invalid JSON syntax"}
	}
	return &ParseError{Kind: ErrorInvalidStructure, Path: reportPath, Index: -1, Msg: "finding fields have invalid JSON types"}
}

func convert(raw rawFinding, reportPath string, index int, pathPrefix ...string) (domain.Finding, error) {
	redact := func(value string) string {
		for _, sensitive := range []string{raw.Secret, raw.Match} {
			if sensitive != "" {
				value = strings.ReplaceAll(value, sensitive, "[REDACTED]")
			}
		}
		return sanitizer.TerminalText(value)
	}
	ruleID := sanitizer.Identifier(redact(raw.RuleID))
	if ruleID == "" {
		ruleID = "unknown"
	}
	prefix := ""
	if len(pathPrefix) > 0 {
		prefix = pathPrefix[0]
	}
	file, err := normalizeFindingPath(redact(raw.File), prefix)
	if err != nil {
		return domain.Finding{}, &ParseError{Kind: ErrorUnsafePath, Path: reportPath, Index: index, Msg: "finding file must be repository-relative"}
	}
	if file == "" {
		file = "(unknown)"
	}
	line := raw.StartLine
	if line < 0 {
		return domain.Finding{}, &ParseError{Kind: ErrorInvalidStructure, Path: reportPath, Index: index, Msg: "line number cannot be negative"}
	}
	secretIdentity := raw.Secret
	if secretIdentity == "" {
		secretIdentity = raw.Match
	}
	if secretIdentity == "" {
		secretIdentity = raw.Fingerprint
	}
	if secretIdentity == "" {
		secretIdentity = ruleID + "\x00" + file + "\x00" + strconv.Itoa(line)
	}
	fingerprint := sanitizer.Fingerprint(secretIdentity)
	label := sanitizer.Identifier(redact(raw.Key))
	if label == "" {
		label = ruleID
	}
	commit := sanitizer.Identifier(redact(raw.Commit))
	commitInfo := &domain.CommitMetadata{
		Author: sanitizer.TerminalText(redact(raw.Author)),
		Email:  sanitizer.TerminalText(redact(raw.Email)),
		Date:   sanitizer.TerminalText(redact(raw.Date)),
	}
	if raw.Message != "" {
		commitInfo.MessageFingerprint = sanitizer.Fingerprint(raw.Message)
	}
	if commitInfo.Author == "" && commitInfo.Email == "" && commitInfo.Date == "" && commitInfo.MessageFingerprint == "" {
		commitInfo = nil
	}
	tags := sanitizeTags(raw.Tags, raw.Secret, raw.Match)
	description := redact(raw.Description)
	if description == "" {
		description = "Gitleaks finding"
	}
	identityKey := strings.Join([]string{ruleID, file, strconv.Itoa(line), commit, fingerprint}, "\x00")
	sum := sha256.Sum256([]byte("credscope:finding:v1\x00" + identityKey))
	return domain.Finding{
		ID:          "finding:" + hex.EncodeToString(sum[:]),
		RuleID:      ruleID,
		Description: description,
		Credential: domain.CredentialIdentity{
			Label:       label,
			Fingerprint: fingerprint,
			Type:        ruleID,
		},
		Location:             domain.Location{Path: file, Line: line},
		Commit:               commit,
		CommitInfo:           commitInfo,
		Tags:                 tags,
		Source:               "gitleaks",
		TestFixtureCandidate: isTestFixturePath(file),
	}, nil
}

func normalizeFindingPath(value string, configuredPrefix ...string) (string, error) {
	if value == "" {
		return "", nil
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	prefix := ""
	if len(configuredPrefix) > 0 {
		prefix = strings.ReplaceAll(configuredPrefix[0], "\\", "/")
	}
	isAbsolute := strings.HasPrefix(normalized, "/") || (len(normalized) >= 3 && normalized[1] == ':' && normalized[2] == '/')
	if isAbsolute {
		if prefix == "" {
			return "", fmt.Errorf("absolute path without configured prefix")
		}
		if err := validateConfiguredPrefix(prefix); err != nil {
			return "", err
		}
		prefix = strings.TrimSuffix(path.Clean(prefix), "/")
		cleanValue := path.Clean(normalized)
		if cleanValue != prefix && !strings.HasPrefix(cleanValue, prefix+"/") {
			return "", fmt.Errorf("absolute path outside configured prefix")
		}
		normalized = strings.TrimPrefix(cleanValue, prefix)
		normalized = strings.TrimPrefix(normalized, "/")
	}
	normalized = path.Clean(normalized)
	if normalized == "." {
		return "", nil
	}
	if normalized == ".." || strings.HasPrefix(normalized, "../") || strings.ContainsRune(normalized, 0) {
		return "", fmt.Errorf("parent traversal")
	}
	return normalized, nil
}

func validateConfiguredPrefix(prefix string) error {
	if strings.ContainsRune(prefix, 0) {
		return fmt.Errorf("configured prefix contains NUL")
	}
	isAbsolute := strings.HasPrefix(prefix, "/") || (len(prefix) >= 3 && prefix[1] == ':' && prefix[2] == '/')
	if !isAbsolute {
		return fmt.Errorf("configured prefix is not absolute")
	}
	for _, part := range strings.Split(prefix, "/") {
		if part == ".." {
			return fmt.Errorf("configured prefix contains parent traversal")
		}
	}
	cleaned := path.Clean(prefix)
	if cleaned == "/" || (len(cleaned) == 2 && cleaned[1] == ':') || (len(cleaned) == 3 && cleaned[1:] == ":/") {
		return fmt.Errorf("configured prefix is a filesystem root")
	}
	return nil
}

func isTestFixturePath(value string) bool {
	value = strings.ToLower(strings.ReplaceAll(value, "\\", "/"))
	return strings.HasPrefix(value, "tests/") || strings.Contains(value, "/tests/") || strings.HasPrefix(value, "testdata/") || strings.Contains(value, "/testdata/")
}

func sanitizeTags(tags []string, sensitiveValues ...string) []string {
	set := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		for _, sensitive := range sensitiveValues {
			if sensitive != "" {
				tag = strings.ReplaceAll(tag, sensitive, "[REDACTED]")
			}
		}
		tag = sanitizer.Identifier(tag)
		if tag != "" {
			set[tag] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for tag := range set {
		result = append(result, tag)
	}
	sort.Strings(result)
	return result
}

func deduplicate(findings []domain.Finding) []domain.Finding {
	byID := make(map[string]domain.Finding, len(findings))
	for _, finding := range findings {
		byID[finding.ID] = finding
	}
	result := make([]domain.Finding, 0, len(byID))
	for _, finding := range byID {
		result = append(result, finding)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i], result[j]
		if left.Location.Path != right.Location.Path {
			return left.Location.Path < right.Location.Path
		}
		if left.Location.Line != right.Location.Line {
			return left.Location.Line < right.Location.Line
		}
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		return left.ID < right.ID
	})
	return result
}
