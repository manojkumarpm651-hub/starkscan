// Package scope enforces the single hard rule of this tool: it may read only
// the files and folders the operator explicitly selected, and nothing else.
//
// Confinement is enforced in-process rather than by the OS. Every path is made
// absolute and fully symlink-resolved before it is compared against the allowed
// roots, so a symlink, junction, or "..\..\" traversal inside a selected folder
// cannot be used to reach a file outside it. Files are always opened read-only;
// this package never offers a write path.
package scope

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrOutOfScope is returned when a path resolves outside every allowed root.
var ErrOutOfScope = errors.New("path resolves outside the allowed scope")

// ErrNotRegular is returned for devices, sockets, pipes, and directories where
// a regular file was required.
var ErrNotRegular = errors.New("not a regular file")

// Root is one operator-selected directory or file.
type Root struct {
	Display string // what the operator typed, used in reports
	Real    string // absolute, symlink-resolved, cleaned
	IsDir   bool
}

// Scope is an immutable allowlist of roots. The zero value is unusable; build
// one with New.
type Scope struct {
	roots []Root
}

// New canonicalizes each selected path and builds the allowlist. It fails
// closed: any path that cannot be resolved is an error rather than a silent
// skip, so an operator never believes they scanned something they did not.
func New(paths []string) (*Scope, error) {
	if len(paths) == 0 {
		return nil, errors.New("no scan targets selected")
	}
	s := &Scope{}
	seen := map[string]bool{}
	for _, p := range paths {
		real, err := canonical(p)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", p, err)
		}
		info, err := os.Lstat(real)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", p, err)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return nil, fmt.Errorf("target %q: %w", p, ErrNotRegular)
		}
		if seen[normalize(real)] {
			continue
		}
		seen[normalize(real)] = true
		s.roots = append(s.roots, Root{Display: p, Real: real, IsDir: info.IsDir()})
	}
	if len(s.roots) == 0 {
		return nil, errors.New("no usable scan targets")
	}
	return s, nil
}

// Roots returns the allowlist. The slice is a copy; the Scope is immutable.
func (s *Scope) Roots() []Root {
	out := make([]Root, len(s.roots))
	copy(out, s.roots)
	return out
}

// Contains reports whether an already-canonical path sits inside a root.
func (s *Scope) Contains(real string) bool {
	_, ok := s.rootFor(real)
	return ok
}

func (s *Scope) rootFor(real string) (Root, bool) {
	for _, r := range s.roots {
		if within(r.Real, real) {
			return r, true
		}
	}
	return Root{}, false
}

// Resolve canonicalizes an arbitrary path and confirms it lands inside the
// scope. Every read in this program passes through here first.
func (s *Scope) Resolve(p string) (string, error) {
	real, err := canonical(p)
	if err != nil {
		return "", err
	}
	if !s.Contains(real) {
		return "", fmt.Errorf("%q: %w", p, ErrOutOfScope)
	}
	return real, nil
}

// Open returns a read-only handle to a scoped regular file.
//
// The path is re-verified at open time and the opened descriptor is stat'd
// again afterwards, so a file swapped for a symlink or device between the walk
// and the read is rejected rather than followed.
func (s *Scope) Open(p string) (*os.File, error) {
	real, err := s.Resolve(p)
	if err != nil {
		return nil, err
	}
	pre, err := os.Lstat(real)
	if err != nil {
		return nil, err
	}
	if !pre.Mode().IsRegular() {
		return nil, fmt.Errorf("%q: %w", p, ErrNotRegular)
	}
	f, err := os.OpenFile(real, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	post, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !post.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%q: %w", p, ErrNotRegular)
	}
	return f, nil
}

// Display renders a canonical path the way the operator will recognize it:
// relative to whichever root it came from.
func (s *Scope) Display(real string) string {
	r, ok := s.rootFor(real)
	if !ok {
		return real
	}
	if !r.IsDir {
		return r.Display
	}
	rel, err := filepath.Rel(r.Real, real)
	if err != nil || rel == "." {
		return r.Display
	}
	return filepath.Join(r.Display, rel)
}

// canonical makes a path absolute and resolves every symlink, junction, and
// mount point along it, which is what makes traversal escapes detectable.
func canonical(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return filepath.Clean(real), nil
}

// within reports containment by path component, never by string prefix, so
// "/data/secrets" is not treated as living inside "/data/sec".
func within(root, p string) bool {
	root, p = normalize(root), normalize(p)
	if root == p {
		return true
	}
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if filepath.IsAbs(rel) {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// normalize folds case on Windows, where NTFS treats paths case-insensitively
// and a case-varied path would otherwise slip past a case-sensitive compare.
func normalize(p string) string {
	p = filepath.Clean(p)
	if runtime.GOOS == "windows" {
		return strings.ToLower(p)
	}
	return p
}
