// Package scan walks the allowed scope and hands each file to the checks.
package scan

import (
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"starkscan/internal/platform"
	"starkscan/internal/scope"
)

// File is one candidate file plus its lazily-read contents.
//
// Contents are read at most once per file no matter how many checks ask for
// them, which keeps a scan to a single pass over the disk.
type File struct {
	Real string      // canonical absolute path
	Disp string      // path as the operator will recognize it
	Info fs.FileInfo // from Lstat, so symlink bits survive

	sc      *scope.Scope
	maxRead int64

	once      sync.Once
	content   []byte
	readErr   error
	truncated bool

	// Each OS query below is made at most once per file and shared by every
	// check that asks. Before this, reading a file's ACL happened once in the
	// traits check and again in the exposure check, doubling the security
	// descriptor allocations for every file in a scan.
	permOnce   sync.Once
	perm       platform.Perm
	streamOnce sync.Once
	streamList []platform.Stream
	lineOnce   sync.Once
	memory     bool // content came from NewMemoryFile; it has no path on disk
	lineIndex  []int

	textOnce sync.Once
	text     []byte
	encoding Encoding

	links        scope.LinkReport
	followLinked bool // read content even when it is reachable from outside
}

// LinkReport describes the other names this file's content is reachable by.
// Reading it loads the file, which is where the check happens.
func (f *File) LinkReport() scope.LinkReport {
	f.Content()
	return f.links
}

// Text returns the content decoded to UTF-8, which is what every rule that
// matches text should look at.
//
// For the common case it is the same bytes as Content, returned without
// copying. For UTF-16 it is the decoded form, which is the only way those
// files get scanned at all: their raw bytes are half NULs and would be judged
// binary. Offsets into this view are what LineAt converts, so a reported line
// number matches what a person sees opening the file in an editor.
func (f *File) Text() []byte {
	f.textOnce.Do(func() {
		c, err := f.Content()
		if err != nil {
			return
		}
		f.text, f.encoding = DecodeText(c)
	})
	return f.text
}

// Encoding reports how the file's bytes spell out text. Worth surfacing in a
// finding: "this was UTF-16" explains why a line number will not match a naive
// byte offset into the file.
func (f *File) Encoding() Encoding {
	f.Text()
	return f.encoding
}

// Perm returns the file's OS permission attributes, querying the OS once.
//
// A memory-backed file is never queried: its name is a label, not a path, and
// passing it to the OS would resolve it against the working directory and
// describe whatever unrelated file happened to sit there.
func (f *File) Perm() platform.Perm {
	f.permOnce.Do(func() {
		if f.memory {
			f.perm = platform.Perm{Reason: "content supplied in memory; there is no path to query"}
			return
		}
		f.perm = platform.Inspect(f.Real, f.Info)
	})
	return f.perm
}

// Hidden reports whether the file is marked hidden.
//
// This comes straight out of the stat result the walk already performed, so it
// costs nothing. It is deliberately separate from Perm: a check that only wants
// the hidden flag should not trigger a security-descriptor query it never reads.
func (f *File) Hidden() bool {
	if f.memory {
		return false
	}
	return platform.Hidden(f.Info)
}

// Streams returns the file's alternate data streams, querying the OS once.
// Memory-backed content has none, and is never looked up on disk.
func (f *File) Streams() []platform.Stream {
	f.streamOnce.Do(func() {
		if f.memory {
			return
		}
		f.streamList = platform.Streams(f.Real)
	})
	return f.streamList
}

// LineAt converts a byte offset into a 1-based line number.
//
// The newline positions are indexed once per file and then binary-searched, so
// reporting many findings in one large file costs a single pass rather than one
// full rescan per finding.
func (f *File) LineAt(offset int) int {
	f.lineOnce.Do(func() {
		// Indexed over the decoded text, not the raw bytes, so a line number
		// reported for a UTF-16 file means the same thing as for any other.
		content := f.Text()
		for i, b := range content {
			if b == '\n' {
				f.lineIndex = append(f.lineIndex, i)
			}
		}
	})
	// Entries strictly below offset are the newlines preceding it.
	return sort.SearchInts(f.lineIndex, offset) + 1
}

// NewMemoryFile builds a File from bytes already held in memory, for content
// that never touched disk: an archive member, a stream, or a test fixture.
// It carries no scope because there is nothing to confine — no path is opened.
func NewMemoryFile(display string, content []byte) *File {
	f := &File{
		Real:    display,
		Disp:    display,
		Info:    memInfo{name: filepath.Base(display), size: int64(len(content))},
		maxRead: int64(len(content)),
		content: content,
		memory:  true,
	}
	// Mark the lazy read as already satisfied so Content never tries to open
	// a path that does not exist.
	f.once.Do(func() {})
	return f
}

// memInfo is the minimal fs.FileInfo a memory-backed File needs.
type memInfo struct {
	name string
	size int64
}

func (m memInfo) Name() string       { return m.name }
func (m memInfo) Size() int64        { return m.size }
func (m memInfo) Mode() fs.FileMode  { return 0o644 }
func (m memInfo) ModTime() time.Time { return time.Time{} }
func (m memInfo) IsDir() bool        { return false }
func (m memInfo) Sys() any           { return nil }

// Content returns the file bytes, capped at the configured read limit. The
// first caller pays for the read; the rest share the result.
func (f *File) Content() ([]byte, error) {
	f.once.Do(func() {
		h, err := f.sc.Open(f.Real)
		if err != nil {
			f.readErr = err
			return
		}
		defer h.Close()

		// Judged before a single byte is read. A hard link reaching out of the
		// scope would otherwise pull outside content into the report under an
		// inside path, which is precisely what the scope gate exists to stop.
		f.links = f.sc.InspectLinks(h, f.Real)
		if len(f.links.Outside) > 0 && !f.followLinked {
			f.readErr = fmt.Errorf("%q is also named %s: %w",
				f.Disp, f.links.Outside[0], scope.ErrOutOfScope)
			return
		}

		limit := f.maxRead
		buf, err := io.ReadAll(io.LimitReader(h, limit+1))
		if err != nil {
			f.readErr = err
			return
		}
		if int64(len(buf)) > limit {
			buf = buf[:limit]
			f.truncated = true
		}
		f.content = buf
	})
	return f.content, f.readErr
}

// Header returns up to n leading bytes, for magic-byte identification.
func (f *File) Header(n int) []byte {
	b, err := f.Content()
	if err != nil || len(b) == 0 {
		return nil
	}
	if len(b) > n {
		return b[:n]
	}
	return b
}

// Ext is the lowercase extension including the dot, or "" if there is none.
func (f *File) Ext() string { return strings.ToLower(filepath.Ext(f.Real)) }

// Name is the base filename, lowercased for matching.
func (f *File) Name() string { return strings.ToLower(filepath.Base(f.Real)) }

// Size is the on-disk size in bytes.
func (f *File) Size() int64 { return f.Info.Size() }

// IsBinary uses the same heuristic as git - a NUL byte in the leading block -
// but applies it to the decoded text rather than the raw bytes.
//
// That distinction is the whole fix for UTF-16: those files are half NUL bytes
// on disk and the raw test called every one of them binary, which silently
// skipped every text rule on them while still counting them as scanned. Once
// decoded, real text has no NULs and real binaries still do.
func (f *File) IsBinary() bool {
	return looksBinary(f.Text())
}
