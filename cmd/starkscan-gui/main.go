// Command starkscan-gui opens the desktop front end.
//
// It is the double-click target of the Windows package. All it does is start
// the interface and get out of the way; the scanning engine remains a separate
// process, so nothing here can change what a scan reads or how it behaves.
//
// This exists as a compiled binary rather than a .cmd file for one reason: a
// batch file flashes a console window before the interface appears, which
// looks like a fault. Built with -H windowsgui, this has no console at all.
package main

import "os"

func main() {
	if err := launch(os.Args[1:]); err != nil {
		fail(err.Error())
		os.Exit(1)
	}
}
