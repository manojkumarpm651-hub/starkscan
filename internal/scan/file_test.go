package scan

import "testing"

func TestLineAtMatchesNaiveCount(t *testing.T) {
	content := []byte("alpha\nbravo\ncharlie\n\ndelta")
	f := NewMemoryFile("x.txt", content)

	// Compare the indexed lookup against a direct count at every offset, so a
	// subtle off-by-one in the binary search cannot slip through.
	for off := 0; off <= len(content); off++ {
		want := 1
		for i := 0; i < off && i < len(content); i++ {
			if content[i] == '\n' {
				want++
			}
		}
		if got := f.LineAt(off); got != want {
			t.Fatalf("LineAt(%d) = %d, want %d", off, got, want)
		}
	}
}

func TestLineAtOnEmptyContent(t *testing.T) {
	f := NewMemoryFile("empty.txt", nil)
	if got := f.LineAt(0); got != 1 {
		t.Errorf("LineAt(0) on empty content = %d, want 1", got)
	}
}

func TestPermAndStreamsAreCachedNotRepeated(t *testing.T) {
	// A memory file has no real path, so both queries must fail closed and
	// stay stable across repeated calls rather than re-querying the OS.
	f := NewMemoryFile("nowhere.txt", []byte("x"))
	first := f.Perm()
	if first.PermsSupported {
		t.Error("a file with no real path cannot yield supported permissions")
	}
	if f.Perm() != first {
		t.Error("Perm must return a stable cached value")
	}
	if got := f.Streams(); len(got) != 0 {
		t.Errorf("expected no streams for a memory file, got %+v", got)
	}
}
