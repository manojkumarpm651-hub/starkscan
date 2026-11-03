// Package finding defines the result type every check emits.
package finding

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity ranks how urgently a finding deserves attention.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = map[Severity]string{
	Info:     "INFO",
	Low:      "LOW",
	Medium:   "MEDIUM",
	High:     "HIGH",
	Critical: "CRITICAL",
}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "UNKNOWN"
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// ParseSeverity converts a threshold name such as "medium" into a Severity.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "INFO":
		return Info, nil
	case "LOW":
		return Low, nil
	case "MEDIUM":
		return Medium, nil
	case "HIGH":
		return High, nil
	case "CRITICAL":
		return Critical, nil
	}
	return Info, fmt.Errorf("unknown severity %q (want info, low, medium, high, or critical)", s)
}

// Finding is a single issue located in a single file.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Check    string   `json:"check"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Path     string   `json:"path"`
	Line     int      `json:"line,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
}

// Redact masks the middle of a secret so reports can show enough to locate the
// value without reprinting a live credential into logs, terminals, or CI output.
func Redact(s string) string {
	s = strings.TrimSpace(s)
	const keepHead, keepTail = 4, 2
	if len(s) <= keepHead+keepTail {
		return strings.Repeat("*", len(s))
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s[:keepHead] + strings.Repeat("*", len(s)-keepHead-keepTail) + s[len(s)-keepTail:]
}

// Truncate shortens free-form evidence (never secret material) for display.
func Truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
