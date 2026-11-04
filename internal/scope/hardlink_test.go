package scope

import (
	"os"
	"path/filepath"
	"testing"
)

// linkFixture builds a scope over "inside" and hard-links a file that lives in
// "outside" into it, which is the shape of the bypass: the link is a perfectly
// ordinary directory entry within the selected folder, and the content it
// names is not.
func linkFixture(t *testing.T) (sc *Scope, linkPath, outsidePath string) {
	t.Helper()
	root := t.TempDir()
	inside := filepath.Join(root, "inside")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{inside, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	outsidePath = filepath.Join(outside, "private.key")
	if err := os.WriteFile(outsidePath, []byte("content outside the scope"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath = filepath.Join(inside, "innocent.txt")
	if err := os.Link(outsidePath, linkPath); err != nil {
		t.Skipf("this filesystem does not support hard links: %v", err)
	}

	sc, err := New([]string{inside})
	if err != nil {
		t.Fatal(err)
	}
	return sc, linkPath, outsidePath
}

// TestInspectLinksSeesOutsideTheScope is the regression test for the bypass.
// Path canonicalization cannot catch this, because a hard link is not a
// reparse point and there is nothing to resolve.
func TestInspectLinksSeesOutsideTheScope(t *testing.T) {
	sc, linkPath, outsidePath := linkFixture(t)

	// The link resolves to a path inside the scope. That is exactly why the
	// gate alone was not enough.
	if _, err := sc.Resolve(linkPath); err != nil {
		t.Fatalf("the link itself is inside the scope and must resolve: %v", err)
	}

	h, err := sc.Open(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	rep := sc.InspectLinks(h, linkPath)
	if !rep.Multi {
		t.Fatal("a hard-linked file must be reported as having more than one name")
	}
	if !rep.Resolved {
		t.Skip("this platform cannot enumerate a file's names")
	}
	if len(rep.Outside) == 0 {
		t.Fatal("the name outside the scope was not reported; the bypass is open")
	}

	wantBase := filepath.Base(outsidePath)
	var found bool
	for _, p := range rep.Outside {
		if filepath.Base(p) == wantBase {
			found = true
		}
	}
	if !found {
		t.Errorf("Outside = %v, want an entry naming %s", rep.Outside, wantBase)
	}
}

// TestInspectLinksClearsOrdinaryFiles guards the other direction. Refusing to
// read normal files would be a worse failure than the bypass it replaced.
func TestInspectLinksClearsOrdinaryFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "plain.txt")
	if err := os.WriteFile(path, []byte("nothing unusual"), 0o600); err != nil {
		t.Fatal(err)
	}
	sc, err := New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	h, err := sc.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	rep := sc.InspectLinks(h, path)
	if rep.Multi {
		t.Error("a file with one name must not be reported as multiply named")
	}
	if len(rep.Outside) != 0 {
		t.Errorf("Outside = %v, want empty for an ordinary file", rep.Outside)
	}
	if !rep.Resolved {
		t.Error("a single-named file is answerable on every platform")
	}
}

// TestInspectLinksAllowsLinksWhollyInsideTheScope keeps the rule narrow: two
// names for the same content are fine when both are in the selected folder.
func TestInspectLinksAllowsLinksWhollyInsideTheScope(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a.txt")
	b := filepath.Join(root, "b.txt")
	if err := os.WriteFile(a, []byte("shared content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Skipf("this filesystem does not support hard links: %v", err)
	}
	sc, err := New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	h, err := sc.Open(b)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	rep := sc.InspectLinks(h, b)
	if !rep.Resolved {
		t.Skip("this platform cannot enumerate a file's names")
	}
	if len(rep.Outside) != 0 {
		t.Errorf("Outside = %v, want empty when every name is inside the scope", rep.Outside)
	}
}
