package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// A memory-backed file has no identity on disk. If its display name is handed
// to an OS query, that name resolves against the process working directory and
// the answer describes some unrelated real file.
func TestMemoryFileDoesNotQueryUnrelatedRealFile(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })

	// A real file that happens to share the memory file's display name.
	decoy := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(decoy, []byte("real file on disk"), 0o600); err != nil {
		t.Fatal(err)
	}

	f := NewMemoryFile("config.yml", []byte("in-memory content"))
	p := f.Perm()
	if p.PermsSupported {
		t.Errorf("memory file reported permissions from the unrelated real %s (grantee %q)", decoy, p.Grantee)
	}
}
