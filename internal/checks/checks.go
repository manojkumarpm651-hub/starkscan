// Package checks holds the detection rules. Each check inspects one file at a
// time and emits findings; checks never write, move, quarantine, or modify
// anything on disk.
package checks

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"starkscan/internal/finding"
	"starkscan/internal/scan"
)

// Check is one family of detection rules.
type Check interface {
	ID() string   // stable short name used by --checks
	Name() string // human description for --list-checks
	Inspect(ctx context.Context, f *scan.File, emit func(finding.Finding))
}

// Config carries operator-supplied inputs that individual checks may need.
type Config struct {
	HashList map[string]string // sha256 (lowercase hex) -> label
}

// Registry builds the enabled check set.
type Registry struct {
	cfg Config
}

func NewRegistry(cfg Config) *Registry { return &Registry{cfg: cfg} }

// All returns every available check in a stable order.
func (r *Registry) All() []Check {
	return []Check{
		&Secrets{},
		&Malware{HashList: r.cfg.HashList},
		&Traits{},
		&Exposure{},
	}
}

// Select resolves comma-separated check IDs, or all of them when ids is empty.
func (r *Registry) Select(ids []string) ([]Check, error) {
	all := r.All()
	if len(ids) == 0 {
		return all, nil
	}
	byID := map[string]Check{}
	for _, c := range all {
		byID[c.ID()] = c
	}
	var out []Check
	seen := map[string]bool{}
	for _, raw := range ids {
		id := strings.ToLower(strings.TrimSpace(raw))
		if id == "" || seen[id] {
			continue
		}
		c, ok := byID[id]
		if !ok {
			var names []string
			for k := range byID {
				names = append(names, k)
			}
			sort.Strings(names)
			return nil, fmt.Errorf("unknown check %q (available: %s)", id, strings.Join(names, ", "))
		}
		seen[id] = true
		out = append(out, c)
	}
	return out, nil
}

// containsFold reports whether lit appears in b, ignoring ASCII case.
//
// lit must be lowercase. Nothing is allocated: candidate positions are found
// with bytes.IndexByte, which is vectorised, and only the matching window is
// compared. This is the pre-filter that lets most files skip the regex engine
// entirely, so it has to be both fast and exactly as permissive as the
// case-insensitive patterns it guards.
func containsFold(b []byte, lit string) bool {
	n := len(lit)
	if n == 0 {
		return true
	}
	if len(b) < n {
		return false
	}

	lower := lit[0]
	upper := lower
	if lower >= 'a' && lower <= 'z' {
		upper = lower - 32
	}
	limit := len(b) - n + 1

	// Each case is tracked by its own cursor that only ever moves forward.
	// Re-scanning for both cases at every candidate position would make this
	// quadratic whenever one case is common and the other never occurs — the
	// exact shape of ordinary English text.
	next := func(from int, c byte) int {
		if from >= limit {
			return -1
		}
		j := bytes.IndexByte(b[from:limit], c)
		if j < 0 {
			return -1
		}
		return from + j
	}

	iLower := next(0, lower)
	iUpper := -1
	if upper != lower {
		iUpper = next(0, upper)
	}

	for {
		i := iLower
		if i < 0 || (iUpper >= 0 && iUpper < i) {
			i = iUpper
		}
		if i < 0 {
			return false
		}
		if equalFoldASCII(b[i:i+n], lit) {
			return true
		}
		if iLower == i {
			iLower = next(i+1, lower)
		}
		if iUpper == i {
			iUpper = next(i+1, upper)
		}
	}
}

// equalFoldASCII compares a byte window against a lowercase literal.
func equalFoldASCII(b []byte, lower string) bool {
	for i := 0; i < len(lower); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// anyContainsFold reports whether any of the literals appears in b. An empty
// list means "no pre-filter", so the caller always runs its pattern.
func anyContainsFold(b []byte, literals []string) bool {
	if len(literals) == 0 {
		return true
	}
	for _, lit := range literals {
		if containsFold(b, lit) {
			return true
		}
	}
	return false
}

// shannon returns the Shannon entropy of s in bits per byte. Random-looking
// credential material scores above roughly 4.0; English prose sits near 3.0
// and repetitive placeholders far below that.
func shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]float64
	for i := 0; i < len(b); i++ {
		counts[b[i]]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// placeholderHints are substrings that mark a value as documentation rather
// than a live credential. Keeping this list tight matters: every entry is a
// potential blind spot an attacker could name a real secret after.
var placeholderHints = []string{
	"example", "changeme", "placeholder", "your_", "yourkey", "dummy",
	"sample", "redacted", "xxxxx", "<insert", "notreal", "fake",
	"todo", "replace_me", "replaceme", "abcdef", "123456", "test_key",
}

func looksLikePlaceholder(v string) bool {
	lv := strings.ToLower(v)
	for _, h := range placeholderHints {
		if strings.Contains(lv, h) {
			return true
		}
	}
	// A value made of one repeated character carries no secret.
	if len(lv) > 0 {
		uniq := map[rune]bool{}
		for _, r := range lv {
			uniq[r] = true
		}
		if len(uniq) <= 2 {
			return true
		}
	}
	return false
}
