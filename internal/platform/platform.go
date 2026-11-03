// Package platform isolates the per-OS file metadata the checks need, so the
// detection rules stay portable and testable.
package platform

import "io/fs"

// Perm describes exposure-relevant attributes of a file.
//
// PermsSupported distinguishes "checked and found nothing" from "could not
// check on this OS". A security tool must never let those two look alike.
type Perm struct {
	Hidden         bool
	WorldWritable  bool
	WorldReadable  bool
	PermsSupported bool

	// Grantee names the principal responsible for the broad access, so the
	// report can say who can reach the file rather than only that someone can.
	Grantee string
	// Reason carries a short explanation when permissions could not be read.
	Reason string
}

// Inspect reads OS-specific attributes. path must be the canonical path of the
// already-stat'd file; it is used only for read-only permission queries.
func Inspect(path string, info fs.FileInfo) Perm { return inspect(path, info) }

// Hidden reports the OS "hidden" attribute from an already-stat'd file. It
// performs no syscall of its own, unlike Inspect.
func Hidden(info fs.FileInfo) bool { return hidden(info) }

// OwnsConsole reports whether this process is the only one attached to its
// console. On Windows that means it was launched from Explorer - a double
// click, or a folder dropped onto the executable - rather than from a shell
// that stays open afterwards. Output would otherwise vanish the instant the
// program exits.
func OwnsConsole() bool { return ownsConsole() }

// Stream is one alternate data stream attached to a file.
type Stream struct {
	Name string
	Size int64
}

// Streams lists the alternate data streams on a file. Only NTFS supports them,
// so this returns nothing at all on other platforms. The default (unnamed)
// stream that holds the file's ordinary contents is never included.
func Streams(path string) []Stream { return streams(path) }

// SupportsPermissions reports whether this build can evaluate file permissions,
// so callers can describe their own coverage honestly.
func SupportsPermissions() bool { return supportsPermissions }
