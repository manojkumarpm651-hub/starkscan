// Package report renders scan results for humans and for machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"starkscan/internal/finding"
	"starkscan/internal/scan"
)

// Report is the complete result of one scan.
type Report struct {
	Tool       string            `json:"tool"`
	Version    string            `json:"version"`
	StartedAt  time.Time         `json:"started_at"`
	DurationMS int64             `json:"duration_ms"`
	Roots      []string          `json:"scanned_roots"`
	Checks     []string          `json:"checks_run"`
	Stats      scan.Stats        `json:"stats"`
	Findings   []finding.Finding `json:"findings"`
	Notes      []string          `json:"notes,omitempty"`
	Counts     map[string]int    `json:"counts_by_severity"`
}

// Finalize sorts findings into report order and fills the severity tally.
// Call it once before rendering.
func (r *Report) Finalize() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity // most severe first
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})

	r.Counts = map[string]int{}
	for _, f := range r.Findings {
		r.Counts[f.Severity.String()]++
	}
}

// CountAtOrAbove reports how many findings meet a threshold.
func (r *Report) CountAtOrAbove(min finding.Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity >= min {
			n++
		}
	}
	return n
}

// WriteJSON emits the machine-readable form.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText emits the operator-facing form.
func (r *Report) WriteText(w io.Writer) error {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("%s %s — scan report\n", r.Tool, r.Version))
	b.WriteString(strings.Repeat("=", 60) + "\n\n")

	b.WriteString("Scope (nothing outside these paths was read):\n")
	for _, root := range r.Roots {
		b.WriteString("  - " + root + "\n")
	}
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("Checks:   %s\n", strings.Join(r.Checks, ", ")))
	b.WriteString(fmt.Sprintf("Scanned:  %d files in %d directories (%s) in %s\n",
		r.Stats.Files, r.Stats.Dirs, humanBytes(r.Stats.Bytes),
		time.Duration(r.DurationMS)*time.Millisecond))

	if r.Stats.TooBig > 0 || r.Stats.Blocked > 0 || r.Stats.Errors > 0 {
		b.WriteString("Skipped: ")
		var parts []string
		if r.Stats.TooBig > 0 {
			parts = append(parts, fmt.Sprintf("%d over size limit", r.Stats.TooBig))
		}
		if r.Stats.Blocked > 0 {
			parts = append(parts, fmt.Sprintf("%d links pointing outside the scope", r.Stats.Blocked))
		}
		if r.Stats.Errors > 0 {
			parts = append(parts, fmt.Sprintf("%d unreadable", r.Stats.Errors))
		}
		b.WriteString(" " + strings.Join(parts, ", ") + "\n")
	}
	b.WriteString("\n")

	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n\n")
		b.WriteString("A clean result means these checks found nothing, not that the\n")
		b.WriteString("files are safe. Coverage is limited to the rules listed above.\n")
		r.writeNotes(&b)
		_, err := io.WriteString(w, b.String())
		return err
	}

	b.WriteString("Summary: ")
	var sums []string
	for _, sev := range []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info} {
		if n := r.Counts[sev.String()]; n > 0 {
			sums = append(sums, fmt.Sprintf("%d %s", n, sev))
		}
	}
	b.WriteString(strings.Join(sums, ", ") + "\n\n")
	b.WriteString(strings.Repeat("-", 60) + "\n\n")

	var lastSev finding.Severity = -1
	for _, f := range r.Findings {
		if f.Severity != lastSev {
			b.WriteString(fmt.Sprintf("[ %s ]\n\n", f.Severity))
			lastSev = f.Severity
		}
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		b.WriteString(fmt.Sprintf("  %s  %s\n", f.RuleID, f.Title))
		b.WriteString(fmt.Sprintf("    %s\n", loc))
		if f.Evidence != "" {
			b.WriteString(fmt.Sprintf("    evidence: %s\n", f.Evidence))
		}
		if f.Detail != "" {
			b.WriteString(fmt.Sprintf("    %s\n", wrap(f.Detail, 72, "    ")))
		}
		b.WriteString("\n")
	}

	r.writeNotes(&b)
	_, err := io.WriteString(w, b.String())
	return err
}

func (r *Report) writeNotes(b *strings.Builder) {
	if len(r.Notes) == 0 {
		return
	}
	b.WriteString(strings.Repeat("-", 60) + "\n")
	b.WriteString("Notes:\n")
	for _, n := range r.Notes {
		b.WriteString("  - " + wrap(n, 70, "    ") + "\n")
	}
}

// wrap breaks text to width, indenting continuation lines.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, w := range words {
		if i > 0 {
			if lineLen+1+len(w) > width {
				b.WriteString("\n" + indent)
				lineLen = 0
			} else {
				b.WriteString(" ")
				lineLen++
			}
		}
		b.WriteString(w)
		lineLen += len(w)
	}
	return b.String()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
