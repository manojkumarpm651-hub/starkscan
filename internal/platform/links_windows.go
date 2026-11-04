//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	procGetFileInformationByHandle = modkernel32.NewProc("GetFileInformationByHandle")
	procFindFirstFileNameW         = modkernel32.NewProc("FindFirstFileNameW")
	procFindNextFileNameW          = modkernel32.NewProc("FindNextFileNameW")
)

const (
	errorMoreData      = 234
	errorHandleEOFLink = 38
)

// byHandleFileInformation mirrors BY_HANDLE_FILE_INFORMATION. Only the link
// count and the file identity are used here.
type byHandleFileInformation struct {
	FileAttributes     uint32
	CreationTime       syscall.Filetime
	LastAccessTime     syscall.Filetime
	LastWriteTime      syscall.Filetime
	VolumeSerialNumber uint32
	FileSizeHigh       uint32
	FileSizeLow        uint32
	NumberOfLinks      uint32
	FileIndexHigh      uint32
	FileIndexLow       uint32
}

// linkCount asks the already-open handle how many names the file has. Taking
// it from the handle costs one call with no extra open, and answers for the
// exact file that is about to be read rather than whatever the path resolves
// to a moment later.
func linkCount(f *os.File) (uint32, bool) {
	var info byHandleFileInformation
	ret, _, _ := procGetFileInformationByHandle.Call(
		f.Fd(), uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		return 0, false
	}
	return info.NumberOfLinks, true
}

// hardLinkPaths enumerates every name the file has on its volume.
//
// FindFirstFileNameW yields volume-relative paths, so the volume of the path
// we arrived by is prefixed back on. Only called when the link count is
// already known to exceed one, which is rare, so the cost does not land on
// ordinary files.
func hardLinkPaths(path string) []string {
	namePtr, err := syscall.UTF16PtrFromString(longPath(path))
	if err != nil {
		return nil
	}

	// MAX_PATH is not a real ceiling on NTFS; grow on ERROR_MORE_DATA.
	buf := make([]uint16, 1024)
	length := uint32(len(buf))

	handle, _, _ := procFindFirstFileNameW.Call(
		uintptr(unsafe.Pointer(namePtr)), 0,
		uintptr(unsafe.Pointer(&length)),
		uintptr(unsafe.Pointer(&buf[0])))

	if handle == invalidHandleValue {
		if length > uint32(len(buf)) {
			buf = make([]uint16, length)
			handle, _, _ = procFindFirstFileNameW.Call(
				uintptr(unsafe.Pointer(namePtr)), 0,
				uintptr(unsafe.Pointer(&length)),
				uintptr(unsafe.Pointer(&buf[0])))
		}
		if handle == invalidHandleValue {
			return nil
		}
	}
	defer procFindCloseWin.Call(handle)

	volume := filepath.VolumeName(path)
	var out []string
	for {
		rel := syscall.UTF16ToString(buf)
		if rel != "" {
			out = append(out, filepath.Clean(volume+rel))
		}
		// A file with an implausible number of names is not worth walking
		// further; stop rather than let a crafted layout spin the scan.
		if len(out) >= 64 {
			break
		}

		length = uint32(len(buf))
		ret, _, errno := procFindNextFileNameW.Call(handle,
			uintptr(unsafe.Pointer(&length)),
			uintptr(unsafe.Pointer(&buf[0])))
		if ret == 0 {
			e, ok := errno.(syscall.Errno)
			if ok && uintptr(e) == errorMoreData && length > uint32(len(buf)) {
				buf = make([]uint16, length)
				continue
			}
			break // ERROR_HANDLE_EOF: no further names
		}
	}
	return out
}
