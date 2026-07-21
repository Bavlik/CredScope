//go:build !windows

package discovery

func isReparsePoint(string) (bool, error) { return false, nil }
