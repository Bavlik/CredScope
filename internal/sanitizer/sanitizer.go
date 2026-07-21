// Package sanitizer provides the only approved transformations from secret or
// repository-controlled strings into identifiers and human-readable output.
package sanitizer

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

const fingerprintDomain = "credscope:fingerprint:v1\x00"

const (
	MaxTerminalTextRunes = 4096
	MaxIdentifierRunes   = 256
)

// Fingerprint produces a domain-separated irreversible identifier and never
// returns any substring of the input.
func Fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(fingerprintDomain + secret))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// RedactedReference combines a non-secret reference name with a fingerprint.
func RedactedReference(label, secret string) string {
	label = Identifier(label)
	if label == "" {
		label = "credential"
	}
	return label + " [" + Fingerprint(secret) + "]"
}

// Identifier restricts untrusted names to a stable, single-line display form.
func Identifier(value string) string {
	value = TerminalText(value)
	var b strings.Builder
	written := 0
	for _, r := range value {
		if written >= MaxIdentifierRunes {
			break
		}
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), strings.ContainsRune("._:/@+-", r):
			b.WriteRune(r)
		case unicode.IsSpace(r):
			b.WriteByte('_')
		default:
			b.WriteByte('_')
		}
		written++
	}
	return strings.Trim(b.String(), "_")
}

// TerminalText removes ANSI escape sequences and all control characters. It
// keeps ordinary Unicode and converts line-breaking controls to spaces.
func TerminalText(value string) string {
	var b strings.Builder
	written := 0
	for i := 0; i < len(value); {
		if value[i] == 0x1b {
			i++
			if i < len(value) && value[i] == '[' {
				i++
				for i < len(value) {
					c := value[i]
					i++
					if c >= 0x40 && c <= 0x7e {
						break
					}
				}
			}
			continue
		}
		r, size := utf8.DecodeRuneInString(value[i:])
		i += size
		if r == '\n' || r == '\r' || r == '\t' {
			if written >= MaxTerminalTextRunes {
				break
			}
			b.WriteByte(' ')
			written++
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == unicode.ReplacementChar {
			continue
		}
		if written >= MaxTerminalTextRunes {
			break
		}
		b.WriteRune(r)
		written++
	}
	return strings.TrimSpace(b.String())
}
