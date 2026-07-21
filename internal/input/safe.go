// Package input provides bounded, root-confined reads for untrusted inputs.
package input

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Bavlik/CredScope/internal/discovery"
	"github.com/Bavlik/CredScope/internal/sanitizer"
)

// ReadFile reuses Phase 1 confinement and symlink checks, then performs a
// second bounded read so a concurrently growing file cannot exceed the limit.
func ReadFile(root, file string, maxSize int64) ([]byte, string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, "", fmt.Errorf("resolve input root: %w", err)
	}
	absRoot, err = filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, "", fmt.Errorf("resolve input root links: %w", err)
	}
	finder, err := discovery.New(root, discovery.Options{MaxFileSize: maxSize})
	if err != nil {
		return nil, "", err
	}
	resolved, err := finder.ResolveFile(file)
	if err != nil {
		return nil, "", err
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, "", fmt.Errorf("open input: %w", err)
	}
	defer f.Close()
	var buffer bytes.Buffer
	if _, err := io.CopyN(&buffer, f, maxSize+1); err != nil && err != io.EOF {
		return nil, "", fmt.Errorf("read input: %w", err)
	}
	if int64(buffer.Len()) > maxSize {
		return nil, "", fmt.Errorf("input exceeds maximum size of %d bytes", maxSize)
	}
	rel, err := filepath.Rel(absRoot, resolved)
	if err != nil {
		return nil, "", fmt.Errorf("make input path relative: %w", err)
	}
	rel = sanitizer.TerminalText(filepath.ToSlash(rel))
	return buffer.Bytes(), rel, nil
}
