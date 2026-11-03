package scan

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"starkscan/internal/scope"
)

// Options tunes a walk. Zero values get sensible defaults in Run.
type Options struct {
	MaxFileSize int64    // files larger than this are recorded but not read
	Workers     int      // concurrent checkers
	Exclude     []string // glob patterns matched against base name and relative path
}

// largeFileBytes is the size at which a file's contents dominate memory and
// its read is worth throttling against the rest of the pool.
const largeFileBytes = 1 << 20 // 1 MiB

// Stats summarizes what a walk touched.
type Stats struct {
	Dirs    int64 `json:"dirs"`
	Files   int64 `json:"files_scanned"`
	Bytes   int64 `json:"bytes_read"`
	TooBig  int64 `json:"files_skipped_too_large"`
	Blocked int64 `json:"paths_blocked_out_of_scope"`
	Errors  int64 `json:"errors"`
}

// Walker traverses the allowed scope and never leaves it.
//
// Symlinks and junctions are deliberately not followed. One that points outside
// the scope is reported through OnBlocked, because an unexpected link out of a
// scanned folder is itself worth an operator's attention.
type Walker struct {
	Scope *scope.Scope
	Opts  Options

	// OnBlocked fires when a path inside the scope points outside it.
	OnBlocked func(display, target string)
	// OnError fires for unreadable entries; a walk continues past them.
	OnError func(display string, err error)
	// OnOversize fires for files skipped for exceeding MaxFileSize. These are
	// never opened, so no check ever sees them; naming each one keeps the
	// blind spot visible per file instead of only as a total.
	OnOversize func(display string, size int64)
}

// Run visits every in-scope file, calling visit concurrently. visit must be
// safe for use from multiple goroutines.
func (w *Walker) Run(ctx context.Context, visit func(*File)) (Stats, error) {
	opts := w.Opts
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 32 << 20 // 32 MiB
	}
	if opts.Workers <= 0 {
		opts.Workers = runtime.NumCPU()
	}

	var st Stats
	jobs := make(chan *File, opts.Workers*4)

	// Checks need whole file contents, so every worker holding a large file at
	// once would put Workers x MaxFileSize bytes in memory — 512 MiB at the
	// defaults on a 16-core machine. Large reads are therefore gated to a small
	// share of the pool while small files continue unthrottled. Each goroutine
	// takes at most one token and always returns it, so the gate cannot deadlock.
	largeSlots := opts.Workers / 4
	if largeSlots < 2 {
		largeSlots = 2
	}
	large := make(chan struct{}, largeSlots)

	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				if f.Size() >= largeFileBytes {
					large <- struct{}{}
					visit(f)
					<-large
				} else {
					visit(f)
				}
			}
		}()
	}

	err := w.produce(ctx, opts, &st, jobs)
	close(jobs)
	wg.Wait()
	return st, err
}

func (w *Walker) produce(ctx context.Context, opts Options, st *Stats, jobs chan<- *File) error {
	emit := func(real string, info fs.FileInfo) bool {
		if info.Size() > opts.MaxFileSize {
			atomic.AddInt64(&st.TooBig, 1)
			if w.OnOversize != nil {
				w.OnOversize(w.Scope.Display(real), info.Size())
			}
			return true
		}
		atomic.AddInt64(&st.Files, 1)
		atomic.AddInt64(&st.Bytes, info.Size())
		f := &File{
			Real:    real,
			Disp:    w.Scope.Display(real),
			Info:    info,
			sc:      w.Scope,
			maxRead: opts.MaxFileSize,
		}
		select {
		case jobs <- f:
			return true
		case <-ctx.Done():
			return false
		}
	}

	for _, root := range w.Scope.Roots() {
		if err := ctx.Err(); err != nil {
			return err
		}

		if !root.IsDir {
			info, err := os.Lstat(root.Real)
			if err != nil {
				w.reportErr(root.Display, err, st)
				continue
			}
			if !emit(root.Real, info) {
				return ctx.Err()
			}
			continue
		}

		walkErr := filepath.WalkDir(root.Real, func(p string, d fs.DirEntry, err error) error {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if err != nil {
				w.reportErr(w.Scope.Display(p), err, st)
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			display := w.Scope.Display(p)

			// A link is resolved and judged, never followed.
			if d.Type()&fs.ModeSymlink != 0 {
				target, rerr := filepath.EvalSymlinks(p)
				if rerr != nil || !w.Scope.Contains(target) {
					atomic.AddInt64(&st.Blocked, 1)
					if w.OnBlocked != nil {
						if rerr != nil {
							target = "<unresolvable>"
						}
						w.OnBlocked(display, target)
					}
				}
				return nil
			}

			if d.IsDir() {
				if p != root.Real && excluded(opts.Exclude, d.Name(), display) {
					return filepath.SkipDir
				}
				atomic.AddInt64(&st.Dirs, 1)
				return nil
			}

			if !d.Type().IsRegular() {
				return nil // devices, sockets, pipes
			}
			if excluded(opts.Exclude, d.Name(), display) {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil {
				w.reportErr(display, ierr, st)
				return nil
			}
			if !emit(p, info) {
				return ctx.Err()
			}
			return nil
		})
		if walkErr != nil && ctx.Err() != nil {
			return walkErr
		}
	}
	return nil
}

func (w *Walker) reportErr(display string, err error, st *Stats) {
	atomic.AddInt64(&st.Errors, 1)
	if w.OnError != nil {
		w.OnError(display, err)
	}
}

func excluded(patterns []string, name, display string) bool {
	if len(patterns) == 0 {
		return false
	}
	slashed := filepath.ToSlash(display)
	for _, pat := range patterns {
		if ok, _ := filepath.Match(pat, name); ok {
			return true
		}
		if ok, _ := filepath.Match(pat, slashed); ok {
			return true
		}
		// Bare directory names exclude everything beneath them.
		if !strings.ContainsAny(pat, "*?[") {
			for _, seg := range strings.Split(slashed, "/") {
				if seg == pat {
					return true
				}
			}
		}
	}
	return false
}
