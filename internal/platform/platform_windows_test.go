//go:build windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestInspectOrdinaryFileIsNotWorldWritable guards the worst possible failure
// of the ACL code: mis-parsing the DACL so that every file looks exposed. A
// scanner that flags everything is worse than one that flags nothing, because
// operators stop reading it.
func TestInspectOrdinaryFileIsNotWorldWritable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ordinary.txt")
	if err := os.WriteFile(path, []byte("plain content"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}

	p := Inspect(path, info)
	if !p.PermsSupported {
		t.Fatalf("ACL reading should be supported on Windows; reason: %q", p.Reason)
	}
	if p.WorldWritable {
		t.Errorf("a file created normally must not report as writable beyond its owner (grantee %q)", p.Grantee)
	}
	if p.WorldReadable {
		t.Errorf("a file created normally must not report as readable beyond its owner (grantee %q)", p.Grantee)
	}
}

func TestInspectMissingFileReportsUnsupported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gone.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	// A path that cannot be queried must fail closed: unsupported with a
	// reason, never a confident "clean" answer.
	p := Inspect(path, info)
	if p.PermsSupported {
		t.Error("a missing file cannot yield a supported permission result")
	}
	if p.Reason == "" {
		t.Error("an unsupported result must explain why")
	}
	if p.WorldWritable || p.WorldReadable {
		t.Error("an unreadable descriptor must not produce access claims")
	}
}

func TestStreamsFindsAlternateDataStream(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "carrier.txt")
	if err := os.WriteFile(path, []byte("visible content"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Windows accepts "file:stream" as a path, so the standard library can
	// create an alternate data stream without any extra syscalls.
	if err := os.WriteFile(path+":payload", []byte("hidden"), 0o600); err != nil {
		t.Skipf("filesystem does not support alternate data streams: %v", err)
	}

	got := Streams(path)
	var found bool
	for _, s := range got {
		if s.Name == "payload" {
			found = true
			if s.Size != int64(len("hidden")) {
				t.Errorf("stream size = %d, want %d", s.Size, len("hidden"))
			}
		}
		if s.Name == "" || s.Name == "::$DATA" {
			t.Errorf("the default data stream must not be reported as alternate: %+v", s)
		}
	}
	if !found {
		t.Errorf("expected a %q stream, got %+v", "payload", got)
	}
}

func TestStreamsReturnsNothingForPlainFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(path, []byte("no streams here"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Streams(path); len(got) != 0 {
		t.Errorf("a plain file should report no alternate streams, got %+v", got)
	}
}

func TestTrimStreamName(t *testing.T) {
	cases := map[string]string{
		":Zone.Identifier:$DATA": "Zone.Identifier",
		":payload:$DATA":         "payload",
		"::$DATA":                "",
	}
	for in, want := range cases {
		if got := trimStreamName(in); got != want {
			t.Errorf("trimStreamName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestInspectDetectsBroadGrant is the positive counterpart to the test above:
// a file that really does grant Everyone write access must be reported.
//
// The grant is made with icacls using the SID form (*S-1-1-0) rather than the
// name "Everyone", which is localised and would fail on a non-English Windows.
// The fixture lives in a temp directory so no world-writable file is left
// behind on the machine running the tests.
func TestInspectDetectsBroadGrant(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.key")
	if err := os.WriteFile(path, []byte("-----BEGIN RSA PRIVATE KEY-----"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command("icacls", path, "/grant", "*S-1-1-0:(W)").CombinedOutput()
	if err != nil {
		t.Skipf("could not grant a test ACL (icacls: %v): %s", err, out)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	p := Inspect(path, info)

	if !p.PermsSupported {
		t.Fatalf("ACL should be readable; reason: %q", p.Reason)
	}
	if !p.WorldWritable {
		t.Error("a file granting Everyone write access must be reported as writable beyond its owner")
	}
	if p.Grantee != "Everyone" {
		t.Errorf("grantee = %q, want %q", p.Grantee, "Everyone")
	}
}

func TestInspectDetectsBroadReadGrant(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exposed.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN RSA PRIVATE KEY-----"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("icacls", path, "/grant", "*S-1-1-0:(R)").CombinedOutput()
	if err != nil {
		t.Skipf("could not grant a test ACL (icacls: %v): %s", err, out)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	p := Inspect(path, info)
	if !p.WorldReadable {
		t.Error("a file granting Everyone read access must be reported as readable beyond its owner")
	}
	if p.WorldWritable {
		t.Error("a read-only grant must not be reported as writable")
	}
}
