// Command starkscan scans a set of explicitly selected files and folders for
// security threats, and reads nothing outside that selection.
//
// It is read-only by design: it opens files for reading, never writes to,
// moves, or quarantines anything it scans, and never contacts the network.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"starkscan/internal/checks"
	"starkscan/internal/finding"
	"starkscan/internal/platform"
	"starkscan/internal/report"
	"starkscan/internal/scan"
	"starkscan/internal/scope"
)

const toolName = "starkscan"

// version and buildDate are stamped in at link time by build.ps1:
//
//	-ldflags "-X main.version=1.0.0 -X main.buildDate=2026-09-07"
//
// The defaults mark a binary built straight from `go build`, so a report can
// never silently claim a release version it was not built as.
var (
	version   = "dev"
	buildDate = "unknown"
)

// Exit codes are stable so the tool can gate a build step.
const (
	exitClean    = 0 // scan completed, nothing at or above the fail threshold
	exitFindings = 1 // scan completed, findings at or above the fail threshold
	exitError    = 2 // the scan could not be completed
)

type options struct {
	checks          string
	exclude         string
	maxFileSize     int64
	hashes          string
	minSeverity     string
	failOn          string
	format          string
	out             string
	workers         int
	listChecks      bool
	showVersion     bool
	quiet           bool
	followHardLinks bool
}

func main() {
	// Launched from Explorer, this process owns its console, and Windows
	// destroys the window the moment main returns. Without a pause the output
	// is unreadable: a double click looks like the program failed to start.
	if platform.OwnsConsole() {
		code := run()
		waitForKey()
		os.Exit(code)
	}
	os.Exit(run())
}

// waitForKey holds an Explorer-launched window open long enough to read.
func waitForKey() {
	fmt.Fprint(os.Stderr, "\nPress Enter to close this window...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// explorerHelp replaces the flag dump when someone double-clicks the binary.
// A wall of flags is the wrong answer to "what is this and how do I use it".
func explorerHelp() {
	fmt.Printf("%s %s\n\n", toolName, version)
	fmt.Println("This is a command-line scanner, so it needs to be told what to scan.")
	fmt.Println("Double-clicking it cannot do that on its own. Three ways to use it:")
	fmt.Println()
	fmt.Println("  1. Drag a folder onto this .exe.")
	fmt.Println("     It scans that folder and the results stay on screen.")
	fmt.Println()
	fmt.Println("  2. Use the desktop app, if this copy came with one:")
	fmt.Println("     open the gui folder and run starkscan-gui.cmd")
	fmt.Println()
	fmt.Println("  3. From a terminal, for full control:")
	fmt.Printf("     %s \"C:\\path\\to\\folder\"\n", toolName)
	fmt.Printf("     %s -h        (every option)\n", toolName)
	fmt.Println()
	fmt.Println("It only ever reads the paths you give it, and never modifies them.")
	fmt.Println("Read LIMITATIONS.txt for what it does not catch.")
}

func run() int {
	var opt options
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.StringVar(&opt.checks, "checks", "", "comma-separated checks to run (default: all)")
	fs.StringVar(&opt.exclude, "exclude", "", "comma-separated glob patterns or directory names to skip")
	fs.Int64Var(&opt.maxFileSize, "max-file-size", 32<<20, "skip files larger than this many bytes")
	fs.StringVar(&opt.hashes, "hashes", "", "path to a known-bad SHA-256 list (one hex digest per line, optional label after whitespace)")
	fs.StringVar(&opt.minSeverity, "min-severity", "low", "omit findings below this severity (info, low, medium, high, critical)")
	fs.StringVar(&opt.failOn, "fail-on", "high", "exit 1 when a finding at or above this severity is present (use 'none' to always exit 0)")
	fs.StringVar(&opt.format, "format", "text", "output format: text or json")
	fs.StringVar(&opt.out, "out", "", "write the report to this file instead of stdout")
	fs.IntVar(&opt.workers, "workers", runtime.NumCPU(), "number of concurrent file workers")
	fs.BoolVar(&opt.listChecks, "list-checks", false, "list available checks and exit")
	fs.BoolVar(&opt.showVersion, "version", false, "print the version and exit")
	fs.BoolVar(&opt.quiet, "quiet", false, "suppress progress output on stderr")
	fs.BoolVar(&opt.followHardLinks, "follow-hardlinks", false,
		"read files whose content is also reachable from outside the selected scope; off by default, such content is refused and reported as SCOPE02")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s %s — scan selected folders and files for security threats\n\n", toolName, version)
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [flags] <path> [path...]\n\n", toolName)
		fmt.Fprintf(os.Stderr, "The paths given are the only thing the tool will read. Symlinks and\n")
		fmt.Fprintf(os.Stderr, "junctions that resolve outside them are refused and reported.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExit codes:\n  0 clean   1 findings at or above --fail-on   2 error\n")
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitClean
		}
		return exitError
	}

	if opt.showVersion {
		fmt.Printf("%s %s (built %s, %s/%s, %s)\n",
			toolName, version, buildDate, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return exitClean
	}

	registry := checks.NewRegistry(checks.Config{})
	if opt.listChecks {
		fmt.Printf("Available checks:\n\n")
		for _, c := range registry.All() {
			fmt.Printf("  %-10s %s\n", c.ID(), c.Name())
		}
		return exitClean
	}

	targets := fs.Args()
	if len(targets) == 0 {
		if platform.OwnsConsole() {
			explorerHelp()
			return exitError
		}
		fmt.Fprintf(os.Stderr, "error: no paths given — you must name the folders or files to scan\n\n")
		fs.Usage()
		return exitError
	}

	if err := scanAll(opt, targets); err != nil {
		var fe *findingsError
		if errors.As(err, &fe) {
			return exitFindings
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	return exitClean
}

// findingsError signals a completed scan that met the failure threshold.
type findingsError struct{ n int }

func (e *findingsError) Error() string {
	return fmt.Sprintf("%d finding(s) at or above the failure threshold", e.n)
}

func scanAll(opt options, targets []string) error {
	minSev, err := finding.ParseSeverity(opt.minSeverity)
	if err != nil {
		return fmt.Errorf("--min-severity: %w", err)
	}

	failOn := finding.Critical
	failEnabled := true
	if strings.EqualFold(strings.TrimSpace(opt.failOn), "none") {
		failEnabled = false
	} else {
		failOn, err = finding.ParseSeverity(opt.failOn)
		if err != nil {
			return fmt.Errorf("--fail-on: %w", err)
		}
	}

	if opt.format != "text" && opt.format != "json" {
		return fmt.Errorf("--format: want text or json, got %q", opt.format)
	}

	// The scope is built before anything is read, and every later read is
	// checked against it.
	sc, err := scope.New(targets)
	if err != nil {
		return err
	}

	hashList, err := loadHashes(opt.hashes)
	if err != nil {
		return fmt.Errorf("--hashes: %w", err)
	}

	registry := checks.NewRegistry(checks.Config{HashList: hashList})
	var ids []string
	if strings.TrimSpace(opt.checks) != "" {
		ids = strings.Split(opt.checks, ",")
	}
	active, err := registry.Select(ids)
	if err != nil {
		return err
	}

	// Ctrl+C stops the walk and still prints what was found so far.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var (
		mu    sync.Mutex
		found []finding.Finding
		notes []string
	)
	emit := func(f finding.Finding) {
		if f.Severity < minSev {
			return
		}
		mu.Lock()
		found = append(found, f)
		mu.Unlock()
	}
	addNote := func(s string) {
		mu.Lock()
		notes = append(notes, s)
		mu.Unlock()
	}

	walker := &scan.Walker{
		Scope: sc,
		Opts: scan.Options{
			MaxFileSize:     opt.maxFileSize,
			Workers:         opt.workers,
			Exclude:         splitList(opt.exclude),
			FollowHardLinks: opt.followHardLinks,
		},
		OnBlocked: func(display, target string) {
			emit(finding.Finding{
				RuleID:   "SCOPE01",
				Check:    "scope",
				Severity: finding.Medium,
				Title:    "Link points outside the selected scope",
				Detail:   "The link was not followed. A link leading out of a scanned folder can be a way to reach files the scan was not meant to cover.",
				Path:     display,
				Evidence: target,
			})
		},
		OnOversize: func(display string, size int64) {
			emit(finding.Finding{
				RuleID:   "SCAN01",
				Check:    "scan",
				Severity: finding.Low,
				Title:    "File skipped: larger than the size limit",
				Detail:   "This file was never opened, so no check examined it and it was not hashed. Raise -max-file-size to include it.",
				Path:     display,
				Evidence: fmt.Sprintf("%d bytes", size),
			})
		},
		OnError: func(display string, err error) {
			if !opt.quiet {
				fmt.Fprintf(os.Stderr, "warning: %s: %v\n", display, err)
			}
		},
	}

	started := time.Now()
	stats, walkErr := walker.Run(ctx, func(f *scan.File) {
		// Settle the file's link situation before any rule reads it. A hard
		// link out of the scope is refused here, so outside content never
		// reaches a report under an inside path.
		if links := f.LinkReport(); len(links.Outside) > 0 {
			detail := "The file was not read. Path resolution cannot detect this: " +
				"a hard link is not a reparse point, so the file genuinely has " +
				"two equal directory entries and the content lives outside the " +
				"folder you selected. Pass -follow-hardlinks to scan it anyway."
			if opt.followHardLinks {
				detail = "Read anyway because -follow-hardlinks was given. The " +
					"content below comes from outside the folder you selected."
			}
			emit(finding.Finding{
				RuleID:   "SCOPE02",
				Check:    "scope",
				Severity: finding.High,
				Title:    "File content is also reachable from outside the scope",
				Detail:   detail,
				Path:     f.Disp,
				Evidence: strings.Join(links.Outside, ", "),
			})
			if !opt.followHardLinks {
				return
			}
		} else if links.Multi && !links.Resolved {
			// Known to carry another name, but this platform cannot say
			// where. Reported rather than silently trusted or refused.
			emit(finding.Finding{
				RuleID:   "SCOPE03",
				Check:    "scope",
				Severity: finding.Low,
				Title:    "File has more than one name",
				Detail: "The content is reachable under another name. This " +
					"platform offers no way to locate the other names, so " +
					"whether any lies outside the selected scope is unknown.",
				Path: f.Disp,
			})
		}

		for _, c := range active {
			if ctx.Err() != nil {
				return
			}
			c.Inspect(ctx, f, emit)
		}
	})
	elapsed := time.Since(started)

	if walkErr != nil && ctx.Err() != nil {
		addNote("Scan interrupted before completion; results below are partial.")
	} else if walkErr != nil {
		return walkErr
	}

	if !platform.SupportsPermissions() {
		addNote("File permissions were not evaluated on this platform.")
	}
	if stats.TooBig > 0 {
		addNote(fmt.Sprintf("%d file(s) exceeded --max-file-size and were not read at all.", stats.TooBig))
	}
	if minSev > finding.Info {
		addNote(fmt.Sprintf("Findings below %s were suppressed by --min-severity.", minSev))
	}

	var checkNames []string
	for _, c := range active {
		checkNames = append(checkNames, c.ID())
	}
	var rootNames []string
	for _, r := range sc.Roots() {
		rootNames = append(rootNames, r.Real)
	}

	rep := &report.Report{
		Tool:       toolName,
		Version:    version,
		StartedAt:  started,
		DurationMS: elapsed.Milliseconds(),
		Roots:      rootNames,
		Checks:     checkNames,
		Stats:      stats,
		Findings:   found,
		Notes:      notes,
	}
	rep.Finalize()

	if err := writeReport(rep, opt); err != nil {
		return err
	}

	if failEnabled {
		if n := rep.CountAtOrAbove(failOn); n > 0 {
			return &findingsError{n: n}
		}
	}
	return nil
}

func writeReport(rep *report.Report, opt options) error {
	out := os.Stdout
	if opt.out != "" {
		// Reports can contain redacted secret fragments and file paths, so the
		// file is created private to the current user where the OS honors it.
		f, err := os.OpenFile(opt.out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}

	w := bufio.NewWriter(out)
	defer w.Flush()

	if opt.format == "json" {
		return rep.WriteJSON(w)
	}
	return rep.WriteText(w)
}

// loadHashes reads a known-bad digest list. Lines are "<sha256>[ label]", and
// blank lines and # comments are ignored.
func loadHashes(path string) (map[string]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		digest, label, _ := strings.Cut(line, " ")
		digest = strings.ToLower(strings.TrimSpace(digest))
		if len(digest) != 64 {
			return nil, fmt.Errorf("line %d: %q is not a 64-character SHA-256 digest", lineNo, digest)
		}
		for _, r := range digest {
			if !strings.ContainsRune("0123456789abcdef", r) {
				return nil, fmt.Errorf("line %d: %q is not valid hex", lineNo, digest)
			}
		}
		out[digest] = strings.TrimSpace(label)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("hash list is empty")
	}
	return out, nil
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
