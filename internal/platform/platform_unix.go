//go:build !windows

package platform

import "io/fs"

const supportsPermissions = true

// inspect reads POSIX mode bits. The "other" triad is what makes a file
// reachable by every local account. path is unused here: mode bits travel with
// the stat result, unlike Windows ACLs which need a separate query.
func inspect(_ string, info fs.FileInfo) Perm {
	mode := info.Mode().Perm()
	return Perm{
		WorldWritable:  mode&0o002 != 0,
		WorldReadable:  mode&0o004 != 0,
		PermsSupported: true,
		Grantee:        "other",
	}
}

// hidden has no equivalent attribute on Unix; a leading dot is a naming
// convention the caller already checks, not a filesystem flag.
func hidden(_ fs.FileInfo) bool { return false }

// ownsConsole is always false: there is no Explorer-style launch to detect,
// and a terminal stays open on its own.
func ownsConsole() bool { return false }

// streams returns nothing: alternate data streams are an NTFS feature.
func streams(_ string) []Stream { return nil }
