//go:build windows

package discovery

import "syscall"

const fileAttributeReparsePoint = 0x400

func isReparsePoint(path string) (bool, error) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attributes, err := syscall.GetFileAttributes(pointer)
	if err != nil {
		return false, err
	}
	return attributes&fileAttributeReparsePoint != 0, nil
}
