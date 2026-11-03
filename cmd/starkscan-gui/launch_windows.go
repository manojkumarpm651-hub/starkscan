//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

// createNoWindow keeps PowerShell's own console from appearing behind the
// interface. Without it the user sees a black window flash and linger.
const createNoWindow = 0x08000000

// launch starts the interface next to this executable and returns immediately.
// Anything passed on the command line is forwarded, so dropping a folder onto
// this binary opens the interface with that folder already loaded.
func launch(args []string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(self)

	// Look beside the launcher first, then in gui/, so the package layout can
	// change without breaking the shortcut a user may have made.
	var script string
	for _, c := range []string{
		filepath.Join(dir, "starkscan-gui.ps1"),
		filepath.Join(dir, "gui", "starkscan-gui.ps1"),
	} {
		if _, err := os.Stat(c); err == nil {
			script = c
			break
		}
	}
	if script == "" {
		return errors.New("starkscan-gui.ps1 was not found next to this program " +
			"or in a gui folder beside it.\n\nThe package may be incomplete. " +
			"Re-extract it, keeping all files together.")
	}

	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		return errors.New("Windows PowerShell was not found on this system, " +
			"so the desktop interface cannot start.\n\nThe command-line " +
			"scanner (starkscan.exe) does not need it and still works.")
	}

	// -STA is required by Windows Forms. The execution-policy bypass applies
	// to this one process only and changes no machine or user setting.
	argv := []string{
		"-NoProfile", "-NoLogo", "-STA",
		"-ExecutionPolicy", "Bypass",
		"-File", script,
	}
	if len(args) > 0 {
		// Explorer passes dropped paths as bare arguments; the interface
		// expects them under -Target.
		argv = append(argv, "-Target")
		argv = append(argv, args...)
	}

	cmd := exec.Command(ps, argv...)
	cmd.Dir = dir
	// CREATE_NO_WINDOW suppresses PowerShell's console. HideWindow is
	// deliberately NOT set: it passes SW_HIDE as the process's initial
	// show-state, which Windows Forms applies to the interface itself, so the
	// app starts up invisible.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Deliberately not waited on: the launcher's job is done once the
	// interface is up, and holding the process open would serve no purpose.
	return cmd.Process.Release()
}

var (
	moduser32      = syscall.NewLazyDLL("user32.dll")
	procMessageBox = moduser32.NewProc("MessageBoxW")
)

// fail reports a startup problem in a dialog. With no console attached there
// is nowhere else for the message to go, and exiting silently would leave the
// user with a program that appears to do nothing at all.
func fail(msg string) {
	title, err1 := syscall.UTF16PtrFromString("starkscan")
	text, err2 := syscall.UTF16PtrFromString(msg)
	if err1 != nil || err2 != nil {
		return
	}
	const mbIconError = 0x00000010
	procMessageBox.Call(0,
		uintptr(unsafe.Pointer(text)),
		uintptr(unsafe.Pointer(title)),
		uintptr(mbIconError))
}
