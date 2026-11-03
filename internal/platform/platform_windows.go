//go:build windows

package platform

import (
	"io/fs"
	"strings"
	"syscall"
	"unsafe"
)

const supportsPermissions = true

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetNamedSecurityInfoW = modadvapi32.NewProc("GetNamedSecurityInfoW")
	procGetAclInformation     = modadvapi32.NewProc("GetAclInformation")
	procGetAce                = modadvapi32.NewProc("GetAce")

	procLocalFree             = modkernel32.NewProc("LocalFree")
	procFindFirstStreamW      = modkernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW       = modkernel32.NewProc("FindNextStreamW")
	procFindCloseWin          = modkernel32.NewProc("FindClose")
	procGetConsoleProcessList = modkernel32.NewProc("GetConsoleProcessList")
)

// Win32 constants. Named here rather than inlined so the access-mask maths
// below can be read against the SDK documentation.
const (
	seFileObject            = 1 // SE_OBJECT_TYPE.SE_FILE_OBJECT
	daclSecurityInformation = 0x00000004
	aclSizeInformationClass = 2
	accessAllowedAceType    = 0
	invalidHandleValue      = ^uintptr(0)
	errorHandleEOF          = 38
)

// Access-mask bits that let a principal change a file's contents, its
// permissions, or its existence.
const (
	fileWriteData       = 0x00000002
	fileAppendData      = 0x00000004
	fileWriteEA         = 0x00000010
	fileWriteAttributes = 0x00000100
	deleteAccess        = 0x00010000
	writeDAC            = 0x00040000
	writeOwner          = 0x00080000
	genericWrite        = 0x40000000
	genericAll          = 0x10000000

	fileReadData = 0x00000001
	genericRead  = 0x80000000
)

const writeMask = fileWriteData | fileAppendData | fileWriteEA | fileWriteAttributes |
	deleteAccess | writeDAC | writeOwner | genericWrite | genericAll

const readMask = fileReadData | genericRead | genericAll

// broadPrincipals are SIDs that stand for "effectively anyone on this machine".
// An ACE granting one of these is what turns a private file into a shared one.
var broadPrincipals = map[string]string{
	"S-1-1-0":      "Everyone",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-546": "BUILTIN\\Guests",
	"S-1-5-7":      "Anonymous Logon",
	"S-1-5-32-547": "BUILTIN\\Power Users",
}

type aclSizeInformation struct {
	AceCount      uint32
	AclBytesInUse uint32
	AclBytesFree  uint32
}

type aceHeader struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
}

// accessAllowedACE mirrors the Win32 struct. SidStart is the first dword of a
// variable-length SID that continues past the end of this struct.
type accessAllowedACE struct {
	Header   aceHeader
	Mask     uint32
	SidStart uint32
}

// win32FindStreamData mirrors WIN32_FIND_STREAM_DATA. The name buffer is
// MAX_PATH + 36 wide characters, per the SDK.
type win32FindStreamData struct {
	StreamSize int64
	StreamName [296]uint16
}

// ownsConsole asks how many processes share this console. Exactly one means
// nothing else is holding the window open, so the program was started by
// Explorer rather than from a shell.
func ownsConsole() bool {
	var pids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

// hidden reads the attribute Go's stat already returned; no syscall is made.
func hidden(info fs.FileInfo) bool {
	d, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&syscall.FILE_ATTRIBUTE_HIDDEN != 0
}

// inspect reads Windows file attributes and the file's DACL.
func inspect(path string, info fs.FileInfo) Perm {
	p := Perm{Hidden: hidden(info)}
	applyDACL(&p, path)
	return p
}

// applyDACL queries the file's discretionary ACL and records whether a broad
// principal is granted read or write access.
//
// Only the DACL is requested, which needs READ_CONTROL on the object and no
// special privilege, so this works as an ordinary user and never elevates.
func applyDACL(p *Perm, path string) {
	namePtr, err := syscall.UTF16PtrFromString(longPath(path))
	if err != nil {
		p.Reason = "path could not be encoded for the security API"
		return
	}

	var pDACL uintptr
	var pSecurityDescriptor uintptr

	ret, _, _ := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(seFileObject),
		uintptr(daclSecurityInformation),
		0, // owner SID, not requested
		0, // group SID, not requested
		uintptr(unsafe.Pointer(&pDACL)),
		0, // SACL, needs SeSecurityPrivilege and is not requested
		uintptr(unsafe.Pointer(&pSecurityDescriptor)),
	)
	if ret != 0 {
		p.Reason = "the file's security descriptor could not be read"
		return
	}
	// The descriptor owns the DACL memory, so it must outlive the walk below.
	defer procLocalFree.Call(pSecurityDescriptor)

	// A present-but-NULL DACL grants everyone full control. That is a real
	// finding, not an absence of one.
	if pDACL == 0 {
		p.PermsSupported = true
		p.WorldWritable = true
		p.WorldReadable = true
		p.Grantee = "Everyone (no DACL present)"
		return
	}

	var sizeInfo aclSizeInformation
	ret, _, _ = procGetAclInformation.Call(
		pDACL,
		uintptr(unsafe.Pointer(&sizeInfo)),
		unsafe.Sizeof(sizeInfo),
		uintptr(aclSizeInformationClass),
	)
	if ret == 0 {
		p.Reason = "the access control list could not be enumerated"
		return
	}

	p.PermsSupported = true

	for i := uint32(0); i < sizeInfo.AceCount; i++ {
		// GetAce writes the ACE address into this already-typed pointer, so
		// the address never passes through uintptr and no pointer has to be
		// reconstructed from an integer.
		var ace *accessAllowedACE
		ret, _, _ = procGetAce.Call(pDACL, uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if ret == 0 || ace == nil {
			continue
		}
		// Deny ACEs and the callback/object ACE variants are skipped: this
		// reports granted breadth, and mis-parsing an unfamiliar ACE layout
		// would be worse than not reading it.
		if ace.Header.AceType != accessAllowedAceType {
			continue
		}

		// unsafe.Add keeps this a single pointer expression. Going via uintptr
		// arithmetic would briefly hold the address as an integer, which is
		// not a valid way to derive a pointer.
		sid := (*syscall.SID)(unsafe.Add(unsafe.Pointer(ace),
			unsafe.Offsetof(accessAllowedACE{}.SidStart)))
		sidStr, err := sid.String()
		if err != nil {
			continue
		}
		name, broad := broadPrincipals[sidStr]
		if !broad {
			continue
		}

		if ace.Mask&writeMask != 0 {
			p.WorldWritable = true
			p.Grantee = name
		}
		if ace.Mask&readMask != 0 {
			p.WorldReadable = true
			if p.Grantee == "" {
				p.Grantee = name
			}
		}
	}
}

// streams enumerates NTFS alternate data streams attached to a file.
func streams(path string) []Stream {
	namePtr, err := syscall.UTF16PtrFromString(longPath(path))
	if err != nil {
		return nil
	}

	var data win32FindStreamData
	handle, _, _ := procFindFirstStreamW.Call(
		uintptr(unsafe.Pointer(namePtr)),
		0, // FindStreamInfoStandard
		uintptr(unsafe.Pointer(&data)),
		0,
	)
	if handle == invalidHandleValue || handle == 0 {
		return nil
	}
	defer procFindCloseWin.Call(handle)

	var out []Stream
	for {
		name := syscall.UTF16ToString(data.StreamName[:])
		// The unnamed stream holding the file's ordinary contents is
		// reported as "::$DATA" and is not an alternate stream.
		if name != "" && name != "::$DATA" {
			out = append(out, Stream{Name: trimStreamName(name), Size: data.StreamSize})
		}

		ret, _, errno := procFindNextStreamW.Call(handle, uintptr(unsafe.Pointer(&data)))
		if ret == 0 {
			// ERROR_HANDLE_EOF is the normal end of enumeration.
			if e, ok := errno.(syscall.Errno); ok && uintptr(e) != errorHandleEOF {
				return out
			}
			break
		}
		// A file with an implausible number of streams is not worth walking
		// further; stop rather than let a crafted file spin the scan.
		if len(out) >= 64 {
			break
		}
	}
	return out
}

// trimStreamName turns ":Zone.Identifier:$DATA" into "Zone.Identifier".
func trimStreamName(s string) string {
	s = strings.TrimPrefix(s, ":")
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

// longPath prefixes paths that exceed the legacy MAX_PATH limit, which the raw
// Win32 calls do not handle on their own the way the os package does.
func longPath(p string) string {
	if len(p) < 240 || strings.HasPrefix(p, `\\?\`) {
		return p
	}
	if strings.HasPrefix(p, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(p, `\\`)
	}
	return `\\?\` + p
}
