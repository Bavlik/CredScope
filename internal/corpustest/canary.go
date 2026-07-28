package corpustest

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// CanaryViolation identifies where a declared canary leaked, without ever
// carrying the canary value itself so failure output stays safe to print or
// paste into CI logs.
type CanaryViolation struct {
	CaseID         string
	Representation string // raw | json_escaped | url_encoded | base64
	Location       string // e.g. "expected.json" or "sarif rendering"
}

func (v CanaryViolation) String() string {
	return fmt.Sprintf("case %s: canary leaked (%s representation) in %s", v.CaseID, v.Representation, v.Location)
}

// representations returns the raw value plus common encoded forms an
// unredacted canary could survive as. Detecting encoded forms catches
// sanitizers that escape but do not remove secret substrings.
func representations(canary string) map[string]string {
	jsonEscaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(canary)
	return map[string]string{
		"raw":          canary,
		"json_escaped": jsonEscaped,
		"url_encoded":  url.QueryEscape(canary),
		"base64":       base64.StdEncoding.EncodeToString([]byte(canary)),
	}
}

// scanForCanaries checks content for every representation of every declared
// canary and returns one CanaryViolation per hit, never including the
// matched text itself.
func scanForCanaries(caseID, location string, canaries []string, content []byte) []CanaryViolation {
	var violations []CanaryViolation
	text := string(content)
	for _, canary := range canaries {
		for kind, form := range representations(canary) {
			if form != "" && strings.Contains(text, form) {
				violations = append(violations, CanaryViolation{CaseID: caseID, Representation: kind, Location: location})
			}
		}
	}
	return violations
}
