// Package discovery safely locates supported files within one repository root.
package discovery

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

const (
	DefaultMaxFileSize int64 = 10 << 20
	DefaultMaxFiles          = 10000
)

type Kind string

const (
	KindGitHubActions Kind = "github-actions"
	KindCompose       Kind = "docker-compose"
	KindGitleaks      Kind = "gitleaks"
)

type File struct {
	Path string `json:"path"`
	Kind Kind   `json:"kind"`
	Size int64  `json:"size"`
}

type Options struct {
	Includes    []string
	Excludes    []string
	MaxFileSize int64
	MaxFiles    int
}

type Finder struct {
	root        string
	includes    []matcher
	excludes    []matcher
	maxFileSize int64
	maxFiles    int
}

type matcher struct {
	pattern string
	re      *regexp.Regexp
}

func New(root string, opts Options) (*Finder, error) {
	if root == "" {
		return nil, errors.New("repository root must not be empty")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("inspect repository root %q: %w", abs, err)
	}
	unsafeRoot, err := isUnsafeLink(abs, info)
	if err != nil {
		return nil, fmt.Errorf("inspect repository root link state: %w", err)
	}
	if unsafeRoot {
		return nil, fmt.Errorf("repository root %q must not be a symbolic link or reparse point", abs)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("repository root %q is not a directory", abs)
	}
	realRoot, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root links: %w", err)
	}

	maxSize := opts.MaxFileSize
	if maxSize == 0 {
		maxSize = DefaultMaxFileSize
	}
	if maxSize < 1 {
		return nil, errors.New("maximum file size must be positive")
	}
	maxFiles := opts.MaxFiles
	if maxFiles == 0 {
		maxFiles = DefaultMaxFiles
	}
	if maxFiles < 1 {
		return nil, errors.New("maximum discovered file count must be positive")
	}
	includes, err := compilePatterns(opts.Includes)
	if err != nil {
		return nil, fmt.Errorf("include patterns: %w", err)
	}
	excludes, err := compilePatterns(opts.Excludes)
	if err != nil {
		return nil, fmt.Errorf("exclude patterns: %w", err)
	}
	return &Finder{root: realRoot, includes: includes, excludes: excludes, maxFileSize: maxSize, maxFiles: maxFiles}, nil
}

// Find walks without following directory symlinks and returns stable ordering.
func (f *Finder) Find() ([]File, error) {
	var files []File
	err := filepath.WalkDir(f.root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk %q: %w", path, walkErr)
		}
		if path == f.root {
			return nil
		}
		rel, err := filepath.Rel(f.root, path)
		if err != nil {
			return fmt.Errorf("make path relative: %w", err)
		}
		rel = filepath.ToSlash(rel)
		if !isSafeRelative(rel) {
			return fmt.Errorf("discovered path escapes repository root: %q", rel)
		}

		entryInfo, infoErr := os.Lstat(path)
		if infoErr != nil {
			return fmt.Errorf("inspect discovered path %q: %w", rel, infoErr)
		}
		unsafeLink, linkErr := isUnsafeLink(path, entryInfo)
		if linkErr != nil {
			return fmt.Errorf("inspect discovered path %q link state: %w", rel, linkErr)
		}
		if unsafeLink {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if isIgnoredDirectory(rel) || matches(f.excludes, rel) || matches(f.excludes, rel+"/") {
				return filepath.SkipDir
			}
			return nil
		}
		if !matches(f.includes, rel) || matches(f.excludes, rel) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect input %q: %w", rel, err)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > f.maxFileSize {
			return fmt.Errorf("input %q exceeds maximum size of %d bytes", rel, f.maxFileSize)
		}
		kind, ok := classify(rel)
		if !ok {
			return nil
		}
		if len(files) >= f.maxFiles {
			return fmt.Errorf("supported input count exceeds maximum of %d files", f.maxFiles)
		}
		files = append(files, File{Path: path, Kind: kind, Size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return UniqueFiles(files), nil
}

// ResolveFile confines an explicit input to the root and rejects every symlink
// component, not just a symlink at the final path.
func (f *Finder) ResolveFile(input string) (string, error) {
	if input == "" {
		return "", errors.New("path must not be empty")
	}
	candidate := input
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(f.root, candidate)
	}
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	if !withinRoot(f.root, abs) {
		return "", fmt.Errorf("path %q is outside repository root", input)
	}
	rel, err := filepath.Rel(f.root, abs)
	if err != nil || !isSafeRelative(filepath.ToSlash(rel)) {
		return "", fmt.Errorf("path %q is outside repository root", input)
	}
	current := f.root
	for _, part := range strings.Split(filepath.Clean(rel), string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return "", fmt.Errorf("inspect %q: %w", input, statErr)
		}
		unsafeLink, linkErr := isUnsafeLink(current, info)
		if linkErr != nil {
			return "", fmt.Errorf("inspect %q link state: %w", input, linkErr)
		}
		if unsafeLink {
			return "", fmt.Errorf("path %q contains a symbolic link or reparse point", input)
		}
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("inspect %q: %w", input, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("path %q is not a regular file", input)
	}
	if info.Size() > f.maxFileSize {
		return "", fmt.Errorf("input %q exceeds maximum size of %d bytes", input, f.maxFileSize)
	}
	return abs, nil
}

func UniqueFiles(files []File) []File {
	byPath := make(map[string]File, len(files))
	for _, file := range files {
		key := dedupeKey(file.Path)
		if existing, ok := byPath[key]; !ok || file.Kind < existing.Kind {
			byPath[key] = file
		}
	}
	result := make([]File, 0, len(byPath))
	for _, file := range byPath {
		result = append(result, file)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := filepath.ToSlash(result[i].Path), filepath.ToSlash(result[j].Path)
		if left == right {
			return result[i].Kind < result[j].Kind
		}
		return left < right
	})
	return result
}

func dedupeKey(filePath string) string {
	cleaned := filepath.Clean(filePath)
	isWindowsPath := len(cleaned) >= 3 &&
		((cleaned[0] >= 'a' && cleaned[0] <= 'z') || (cleaned[0] >= 'A' && cleaned[0] <= 'Z')) &&
		cleaned[1] == ':' && (cleaned[2] == '\\' || cleaned[2] == '/')
	if runtime.GOOS == "windows" || isWindowsPath {
		return strings.ToLower(strings.ReplaceAll(cleaned, "\\", "/"))
	}
	return cleaned
}

func compilePatterns(patterns []string) ([]matcher, error) {
	result := make([]matcher, 0, len(patterns))
	for _, pattern := range patterns {
		if pattern == "" || strings.ContainsRune(pattern, 0) {
			return nil, fmt.Errorf("invalid pattern %q", pattern)
		}
		normalized := filepath.ToSlash(pattern)
		if filepath.IsAbs(pattern) || filepath.VolumeName(pattern) != "" || normalized == ".." || strings.HasPrefix(normalized, "../") {
			return nil, fmt.Errorf("pattern %q must be repository-relative", pattern)
		}
		expression, err := globRegexp(normalized)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", pattern, err)
		}
		result = append(result, matcher{pattern: normalized, re: regexp.MustCompile(expression)})
	}
	return result, nil
}

func globRegexp(pattern string) (string, error) {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '[':
			return "", errors.New("character classes are not supported")
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	b.WriteByte('$')
	return b.String(), nil
}

func matches(patterns []matcher, rel string) bool {
	rel = filepath.ToSlash(rel)
	for _, pattern := range patterns {
		if pattern.re.MatchString(rel) {
			return true
		}
	}
	return false
}

func classify(rel string) (Kind, bool) {
	rel = filepath.ToSlash(rel)
	if strings.HasPrefix(rel, ".github/workflows/") && (strings.HasSuffix(rel, ".yml") || strings.HasSuffix(rel, ".yaml")) {
		return KindGitHubActions, true
	}
	switch rel {
	case "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
		return KindCompose, true
	default:
		return "", false
	}
}

func isIgnoredDirectory(rel string) bool {
	base := filepath.Base(filepath.FromSlash(strings.TrimSuffix(rel, "/")))
	switch base {
	case ".git", "vendor", "node_modules", "dist", "build", "coverage", ".tmp":
		return true
	default:
		return false
	}
}

func isSafeRelative(rel string) bool {
	return rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel) && !strings.ContainsRune(rel, 0)
}

func withinRoot(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && isSafeRelative(filepath.ToSlash(rel))
}

func isUnsafeLink(path string, info os.FileInfo) (bool, error) {
	if info.Mode()&os.ModeSymlink != 0 {
		return true, nil
	}
	return isReparsePoint(path)
}
