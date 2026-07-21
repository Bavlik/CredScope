//go:build !windows

package safefile

func isReparsePoint(string) (bool, error) { return false, nil }
