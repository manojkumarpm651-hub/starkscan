//go:build !windows

package platform

import (
	"os"
	"syscall"
)

// linkCount reads st_nlink from the open file.
func linkCount(f *os.File) (uint32, bool) {
	info, err := f.Stat()
	if err != nil {
		return 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint32(st.Nlink), true
}

// hardLinkPaths returns nil: POSIX offers no way to go from an inode back to
// its names without walking every directory on the filesystem, which is far
// too expensive to do per file. Callers read nil as "cannot tell".
func hardLinkPaths(_ string) []string { return nil }
