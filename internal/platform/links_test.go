package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLinkCountOnOrdinaryFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	n, ok := LinkCount(f)
	if !ok {
		t.Skip("link counts are not available on this platform")
	}
	if n != 1 {
		t.Errorf("LinkCount = %d, want 1 for a file with a single name", n)
	}
}

// TestLinkCountSeesASecondName is the detection the hardlink bypass needs:
// path resolution cannot tell that a file has another name, but the link
// count can.
func TestLinkCountSeesASecondName(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original.txt")
	alias := filepath.Join(dir, "alias.txt")
	if err := os.WriteFile(original, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, alias); err != nil {
		t.Skipf("this filesystem does not support hard links: %v", err)
	}

	f, err := os.Open(alias)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	n, ok := LinkCount(f)
	if !ok {
		t.Skip("link counts are not available on this platform")
	}
	if n < 2 {
		t.Errorf("LinkCount = %d, want at least 2 once a second name exists", n)
	}
}

func TestHardLinkPathsFindsBothNames(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("enumerating a file's names is only implemented on Windows")
	}
	dir := t.TempDir()
	original := filepath.Join(dir, "original.txt")
	alias := filepath.Join(dir, "alias.txt")
	if err := os.WriteFile(original, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, alias); err != nil {
		t.Skipf("this filesystem does not support hard links: %v", err)
	}

	names := HardLinkPaths(alias)
	if len(names) < 2 {
		t.Fatalf("HardLinkPaths returned %v, want both names", names)
	}

	// The temp directory itself may sit behind a short path such as RUNNER~1,
	// so compare on the file names rather than the full strings.
	var sawOriginal, sawAlias bool
	for _, n := range names {
		switch strings.ToLower(filepath.Base(n)) {
		case "original.txt":
			sawOriginal = true
		case "alias.txt":
			sawAlias = true
		}
		if !filepath.IsAbs(n) {
			t.Errorf("%q is not an absolute path; it cannot be tested for containment", n)
		}
	}
	if !sawOriginal || !sawAlias {
		t.Errorf("HardLinkPaths = %v, want entries for both original.txt and alias.txt", names)
	}
}

func TestHardLinkPathsOnSingleNamedFile(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("enumerating a file's names is only implemented on Windows")
	}
	path := filepath.Join(t.TempDir(), "only.txt")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if names := HardLinkPaths(path); len(names) != 1 {
		t.Errorf("HardLinkPaths = %v, want exactly the one name", names)
	}
}
