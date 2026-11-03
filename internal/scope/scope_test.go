package scope

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNewRejectsMissingTarget(t *testing.T) {
	_, err := New([]string{filepath.Join(t.TempDir(), "does-not-exist")})
	if err == nil {
		t.Fatal("expected an error for a missing target; a scope must fail closed rather than silently skip")
	}
}

func TestNewRejectsEmptySelection(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("expected an error when no targets are selected")
	}
}

func TestContainsRejectsSiblingWithSharedPrefix(t *testing.T) {
	// The classic containment bug: "/data/sec" must not appear to contain
	// "/data/secrets" just because one string prefixes the other.
	root := t.TempDir()
	allowed := filepath.Join(root, "sec")
	sibling := filepath.Join(root, "secrets")
	for _, d := range []string{allowed, sibling} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	s, err := New([]string{allowed})
	if err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(sibling)
	if err != nil {
		t.Fatal(err)
	}
	if s.Contains(real) {
		t.Fatalf("scope rooted at %q must not contain sibling %q", allowed, sibling)
	}
}

func TestResolveRejectsTraversalOutOfScope(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "inside")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := New([]string{inside})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Resolve(filepath.Join(inside, "..", "outside.txt"))
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("traversal out of scope should return ErrOutOfScope, got %v", err)
	}
}

func TestResolveAcceptsFileInsideScope(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "ok.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(target); err != nil {
		t.Fatalf("file inside the scope should resolve, got %v", err)
	}
}

func TestOpenRefusesDirectory(t *testing.T) {
	root := t.TempDir()
	s, err := New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(root); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("opening a directory should return ErrNotRegular, got %v", err)
	}
}

func TestOpenIsReadOnly(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "data.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if _, err := h.Write([]byte("tampered")); err == nil {
		t.Fatal("handles returned by Open must not be writable")
	}
}

func TestContainsIsCaseInsensitiveOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("case folding only applies on Windows")
	}
	root := t.TempDir()
	s, err := New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Contains(strings.ToUpper(real)) {
		t.Fatal("NTFS is case-insensitive, so a case-varied path must still be recognised as in-scope")
	}
}

func TestDisplayIsRelativeToRoot(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(sub, "c.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	real, err := s.Resolve(target)
	if err != nil {
		t.Fatal(err)
	}
	got := s.Display(real)
	if !strings.HasSuffix(filepath.ToSlash(got), "a/b/c.txt") {
		t.Fatalf("Display(%q) = %q, want it to end with a/b/c.txt", real, got)
	}
}
