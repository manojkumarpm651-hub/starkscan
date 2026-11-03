starkscan __VERSION__
=====================================================================
A read-only security scanner that inspects only the folders and files
you name, and refuses to read anything else.

Built __BUILDDATE__.  No installer. No runtime to install. No network
access. Nothing is written except the report you ask for.


WHAT IS IN THIS PACKAGE
---------------------------------------------------------------------
  starkscan-gui.exe      START HERE. The desktop app. Double-click it.
  starkscan.exe          the same scanner, for the command line.
  gui/                   files the desktop app uses. Ignore them.
  README.txt             this file.
  LIMITATIONS.txt        what it does NOT catch. Please read it.
  SHA256SUMS.txt         checksums for everything above.

(The Linux and macOS packages contain the command-line scanner only;
the desktop app is Windows-only.)


VERIFY BEFORE YOU RUN IT
---------------------------------------------------------------------
You are about to run a security tool someone sent you. Check it.

  Windows (PowerShell):
      Get-FileHash .\starkscan.exe -Algorithm SHA256

  Linux / macOS:
      shasum -a 256 starkscan

Compare against SHA256SUMS.txt. If they differ, stop.

These binaries are NOT code-signed. Signing needs a paid certificate.
That means your OS will warn you, and it is right to:

  Windows: SmartScreen may block it on first run. If the files came
           from another machine, clear the mark-of-the-web first:
               Get-ChildItem -Recurse | Unblock-File

  macOS:   Gatekeeper will quarantine it:
               xattr -d com.apple.quarantine ./starkscan
               chmod +x ./starkscan

  Linux:   chmod +x ./starkscan


EASIEST WAY TO USE IT
---------------------------------------------------------------------
DOUBLE-CLICK starkscan-gui.exe.

Pick a folder, choose which checks to run, press Scan. Results appear
in a sortable table; click any row for the detail, and export to JSON
or text when you are done.

You can also drag a folder straight onto starkscan-gui.exe and it
opens with that folder already loaded.

The desktop app does no scanning itself. It runs starkscan.exe and
shows what that reports, so every result can be reproduced on the
command line - and a fault in the interface cannot change what a scan
is allowed to read.


QUICK START (COMMAND LINE)
---------------------------------------------------------------------
  starkscan ./some/folder                    scan a folder
  starkscan ./a ./b file.docx                several targets
  starkscan -format json -out report.json ./x
  starkscan -checks secrets,exposure ./repo  pick checks
  starkscan -list-checks                     what is available
  starkscan -h                               all flags

Exit codes:  0 = clean
             1 = findings at or above -fail-on (default: high)
             2 = the scan could not be completed

So it can gate a build step:
  starkscan -fail-on critical ./src || echo "blocked"


DESKTOP APP - NOTES
---------------------------------------------------------------------
Needs nothing installed: it uses the Windows Forms libraries already
present on Windows 10 and later. It applies a PowerShell execution
policy bypass to its OWN process only; no machine or user setting is
changed.

If it will not start, run gui\starkscan-gui.cmd instead. That is the
same interface launched through a console window, so any error is
visible rather than swallowed.


WHAT IT READS
---------------------------------------------------------------------
Only the paths you pass on the command line.

  - Every path is fully resolved before it is used, and every file is
    checked for containment by path component, so ".." traversal and
    a shared name prefix cannot widen the scope.
  - Symlinks and Windows junctions are resolved but never followed. One
    that points outside the scope is refused and reported (SCOPE01).
  - Files are opened read-only. There is no code path that writes to,
    moves, quarantines, or deletes anything it scans.
  - No network access of any kind: no telemetry, no update check, no
    reputation lookup. It works fully offline and always has.

One documented exception: a HARDLINK inside the scope pointing at a
file outside it WILL be read. See LIMITATIONS.txt.


SUPPORT MATRIX
---------------------------------------------------------------------
  windows/amd64   Windows 10 or later. Full feature set, including
                  NTFS permission (ACL) and alternate-data-stream
                  checks, plus the GUI.
  linux/amd64     static binary, no libc dependency.
  linux/arm64     static binary, no libc dependency.
  darwin/arm64    Apple Silicon.

On Linux and macOS the permission check reads POSIX mode bits; the
alternate-data-stream check does not apply and reports nothing. The
GUI is Windows only; every other platform uses the command line, which
has the full feature set.


LICENSING
---------------------------------------------------------------------
Released under the MIT licence. The full text ships in the repository
as LICENSE: https://github.com/manojkumarpm651-hub/starkscan
