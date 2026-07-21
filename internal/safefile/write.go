// Package safefile contains conservative filesystem primitives for reports.
package safefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteReport stages a report in its destination directory and publishes it
// with owner-only permissions. The destination must stay beneath root, and
// existing symlinks are rejected.
func WriteReport(root, destination string, data []byte) error {
	if destination == "" {
		return errors.New("output path must not be empty")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve output root: %w", err)
	}
	absDestination := destination
	if !filepath.IsAbs(absDestination) {
		absDestination = filepath.Join(absRoot, absDestination)
	}
	absDestination, err = filepath.Abs(absDestination)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	rel, err := filepath.Rel(absRoot, absDestination)
	if err != nil || rel == ".." || strings.HasPrefix(filepath.ToSlash(rel), "../") {
		return fmt.Errorf("output path %q is outside repository root", destination)
	}

	parent := filepath.Dir(absDestination)
	if err := rejectSymlinks(absRoot, parent); err != nil {
		return err
	}
	if info, statErr := os.Lstat(absDestination); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("output path %q is a symbolic link", destination)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("output path %q is not a regular file", destination)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect output path %q: %w", destination, statErr)
	}

	temp, err := os.CreateTemp(parent, ".credscope-report-*")
	if err != nil {
		return fmt.Errorf("create temporary report: %w", err)
	}
	tempName := temp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("secure temporary report permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary report: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("flush temporary report: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary report: %w", err)
	}
	if err := publish(tempName, absDestination); err != nil {
		return fmt.Errorf("publish report: %w", err)
	}
	keep = true
	return nil
}

// publish preserves an existing report until the staged replacement succeeds.
// The short two-rename sequence is required for consistent Windows behavior,
// where os.Rename does not replace an existing file.
func publish(staged, destination string) error {
	info, err := os.Lstat(destination)
	if errors.Is(err, os.ErrNotExist) {
		return os.Rename(staged, destination)
	} else if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("existing report is not a regular non-symlink file")
	}

	backupFile, err := os.CreateTemp(filepath.Dir(destination), ".credscope-previous-*")
	if err != nil {
		return fmt.Errorf("reserve backup path: %w", err)
	}
	backup := backupFile.Name()
	if err := backupFile.Close(); err != nil {
		_ = os.Remove(backup)
		return fmt.Errorf("close backup placeholder: %w", err)
	}
	if err := os.Remove(backup); err != nil {
		return fmt.Errorf("prepare backup path: %w", err)
	}
	if err := os.Rename(destination, backup); err != nil {
		return fmt.Errorf("preserve previous report: %w", err)
	}
	if err := os.Rename(staged, destination); err != nil {
		if restoreErr := os.Rename(backup, destination); restoreErr != nil {
			return fmt.Errorf("replace report: %w (also failed to restore previous report: %v)", err, restoreErr)
		}
		return fmt.Errorf("replace report: %w", err)
	}
	if err := os.Remove(backup); err != nil {
		return fmt.Errorf("remove previous report backup %q: %w", backup, err)
	}
	return nil
}

func rejectSymlinks(root, parent string) error {
	rel, err := filepath.Rel(root, parent)
	if err != nil || rel == ".." || strings.HasPrefix(filepath.ToSlash(rel), "../") {
		return errors.New("output parent is outside repository root")
	}
	current := root
	for _, part := range strings.Split(filepath.Clean(rel), string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return fmt.Errorf("inspect output parent %q: %w", current, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("output parent %q is a symbolic link", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("output parent %q is not a directory", current)
		}
	}
	return nil
}
