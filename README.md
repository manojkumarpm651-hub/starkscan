# starkscan

A read-only security scanner that inspects **only the folders and files you name**
and refuses to read anything else.

Written in Go against the standard library only — **no third-party dependencies**,
so the supply-chain surface of the tool itself is zero. It builds to a single
static binary with no interpreter, no runtime, and no C toolchain to install.

## Install

Grab a binary from `dist/`, put it anywhere, and run it. Nothing else is needed —
no Go installation, no source tree, no DLLs beyond the Windows core.

```powershell
.\build.ps1 -Version 1.0.0 -All
```

That runs `go vet` and the tests first and refuses to produce a release if
either fails, then writes binaries for Windows, Linux (amd64 + arm64), and macOS
(arm64) to `dist/`, along with `SHA256SUMS.txt`.

Builds use `-trimpath` (so the build machine's paths are not embedded in the
binary), `-s -w` (no symbol table or debug info), and `CGO_ENABLED=0` (a genuinely
static binary).

The binaries are **unsigned**. Windows SmartScreen will warn on first run, and a
binary copied from another machine may need `Unblock-File`. Code signing needs a
certificate you'd have to buy.

## Usage

```bash
starkscan ./some/folder
starkscan -format json -out report.json ./folder-a ./file-b.docx
starkscan -checks secrets,exposure -min-severity high ./repo
starkscan -hashes known-bad.txt -fail-on critical ./downloads
```

Exit codes: **0** clean · **1** findings at or above `-fail-on` · **2** error.

| Flag | Default | Purpose |
|---|---|---|
| `-checks` | all | comma-separated check IDs to run |
| `-exclude` | none | glob patterns or directory names to skip |
| `-max-file-size` | 32 MiB | files above this are recorded but not read |
| `-hashes` | none | known-bad SHA-256 list (`<digest> [label]` per line, `#` comments) |
| `-min-severity` | `low` | omit findings below this level |
| `-fail-on` | `high` | exit 1 at or above this level (`none` to always exit 0) |
| `-format` | `text` | `text` or `json` |
| `-out` | stdout | write the report to a file, created mode `0600` |
| `-workers` | NumCPU | concurrent file workers |

Nothing is excluded by default — not even `node_modules`. That is deliberate:
skipping dependency trees is how a malicious package goes unnoticed. Use
`-exclude` when you want the speed and accept the blind spot.

## Desktop GUI

```
dist\gui\starkscan-gui.cmd
dist\gui\starkscan-gui.cmd -Target "C:\some\folder"
```

A Windows Forms front end: pick folders and files, choose which checks run, set
the severity floor and size limit, and read results in a sortable grid with a
detail pane and JSON/text export. `-Target` pre-loads paths so the GUI can be
launched straight at a folder from a shortcut; Enter runs the scan.

Blues carry structure (header, grid, section labels), greens carry action (the
Scan button, a clean result). Severity keeps its conventional red-to-blue scale
rather than being themed: recolouring a CRITICAL finding to match a palette
would make the report lie. Only the severity cell is tinted, not the whole row,
so a long report stays readable.

**The GUI does no scanning.** It builds a command line, runs the engine as a
separate process, and renders the JSON report. Nothing in the GUI can change
what a scan reads or how it behaves, and deleting it leaves the tool untouched.
That separation is the point: the confinement guarantee lives in the engine,
which stays independently testable and fully usable headless.

It needs only the Windows Forms assemblies that ship with Windows - no modules
to install. The `.cmd` launcher supplies `-STA` (required by Windows Forms) and
applies `-ExecutionPolicy Bypass` **to that one process only**; no machine or
user policy is changed.

Two details worth knowing, because both are easy to get wrong:

- Arguments are quoted with the exact `CommandLineToArgvW` rules rather than
  `ProcessStartInfo.ArgumentList`, which does not exist on the .NET Framework
  that Windows PowerShell 5.1 runs on. A path such as `C:\Project Stark\x`
  reaches the engine as a single argument.
- The report is written to a temp file, not a redirected pipe. Waiting on a
  process while its stdout pipe fills is a deadlock; the temp file avoids it
  entirely and is deleted as soon as it has been read.

## What the application accesses

Audited, and deliberately small:

| Resource | Used | Notes |
|---|---|---|
| Network | **never** | no `net/http`, no sockets, no telemetry, no update check |
| Subprocesses | **never** | the engine spawns nothing; only the GUI spawns the engine |
| Registry | **never** | |
| Elevation | **never** | reading a DACL needs only `READ_CONTROL` |
| File writes | report only | `-out` path, created mode `0600`; scanned files open `O_RDONLY` |
| Win32 calls | 7 | `GetNamedSecurityInfoW`, `GetAclInformation`, `GetAce`, `LocalFree`, `FindFirstStreamW`, `FindNextStreamW`, `FindClose` |

Each OS query is made **once per file** and shared by every check that needs it.
Reading a file's ACL previously happened twice - once in the traits check and
again in the exposure check - doubling the security-descriptor allocations for
every file scanned. Line numbers are likewise indexed once per file and binary
searched, rather than rescanning the file from byte zero for every finding.

## The confinement guarantee

This is the tool's central design constraint, enforced in
[`internal/scope`](internal/scope/scope.go):

- Every selected path is made absolute and **fully symlink-resolved** before it
  becomes a root.
- Every candidate file is canonicalized the same way and checked for containment
  **by path component**, never by string prefix — a scope rooted at `/data/sec`
  does not swallow `/data/secrets`.
- Symlinks and Windows junctions are **resolved but never followed**. One
  pointing outside the scope is refused and reported (`SCOPE01`), because an
  unexpected link out of a scanned folder is itself worth knowing about.
- Files are opened `O_RDONLY` and re-stat'd after opening, so a file swapped for
  a symlink or device mid-scan is rejected. The package exposes no write path.
- Path comparison folds case on Windows, where NTFS would otherwise let a
  case-varied path slip past a case-sensitive check.

### Hardlinks

A hardlink inside a selected folder can name content that lives outside it.
Path canonicalization cannot catch that: a hardlink is not a reparse point, so
the file genuinely has two equal directory entries and there is nothing to
resolve or refuse. Reading the inside entry would pull outside content into the
report, under the inside path, where the substitution is invisible.

So the check is not a path check. Every file is asked how many names it has
before a byte is read — one call on the handle already open, so ordinary files
cost nothing extra. Only a file claiming more than one name is enumerated
(`FindFirstFileNameW`), and each name is tested for containment:

- **A name outside the scope** → the content is **not read**, and `SCOPE02`
  reports the outside path. Pass `-follow-hardlinks` to scan it anyway; the
  finding is still raised, so the report always says where the content came
  from.
- **Every name inside the scope** → scanned normally. Two names for the same
  content are unremarkable when both are in the folder you chose.
- **More than one name, locations unknowable** → `SCOPE03`, and the file is
  scanned. This is the Unix case: POSIX offers no way to map an inode back to
  its names without walking the whole filesystem, so the honest answer is that
  the file has another name and this build cannot say where.

Nothing needs elevation. On a 263-file sample of ordinary trees this produced
no findings at all, which is the behaviour that matters — refusing to read
normal files would be a worse failure than the bypass it replaced.

**What this is not:** OS-level sandboxing. Confinement is enforced in-process.
A bug in this program could still read outside the scope, and a compromised
*process* is not contained. Real OS confinement on Windows means AppContainer or
a job object, which this build does not use. The scope gate is a correctness
boundary, not a barrier against hostile code running as this binary.

## Checks

Run `starkscan -list-checks`. Rule IDs are stable.

### `secrets` — credential material in files
AWS keys, GitHub / Slack / Stripe / SendGrid / Anthropic / OpenAI-style tokens,
npm tokens, private key blocks (PEM and PuTTY), JWTs, and credentials embedded in
connection strings. A generic `key = "value"` rule is gated on Shannon entropy
and a placeholder filter so documentation examples do not flood the report.

**Secret material is always redacted.** Evidence appears as `ghp_****…Ol` —
enough to locate the value, never enough to reuse it. The one deliberate
exception is a public format banner such as `-----BEGIN RSA PRIVATE KEY-----`,
which is shown verbatim: masking it would hide which key type was found while
concealing nothing, since the banner is not secret.

Where two rules match the same bytes, the more specific one reports and the
other stays quiet, so one credential never appears twice.

### `malware` — known-bad files and malicious behaviour
SHA-256 matching against a list you supply (`-hashes`), the EICAR test string,
macro-enabled Office documents (OOXML is a ZIP, so `archive/zip` reads it without
a third-party parser), remote-template injection, high-entropy (possibly packed)
executables, encoded PowerShell, download-and-execute cradles, living-off-the-land
download utilities, obfuscated JavaScript, persistence, and defence evasion.

### `traits` — files disguised as something harmless
Double extensions (`invoice.pdf.exe`), bidirectional-override characters in
filenames, space-padded executable names, executable content behind a document
extension, hidden executables, `.lnk` shortcuts that launch an interpreter, and
**NTFS alternate data streams** (`TRT008`) — content that never appears in a
directory listing and does not count toward the file's reported size.

`Zone.Identifier` streams are ignored: Windows attaches one to nearly every
downloaded file, and reporting them would bury the streams that matter.

### `exposure` — sensitive material reachable by others
Key and certificate files, credential stores (`.npmrc`, `.netrc`, `id_rsa`, shell
history), `.env` files, git metadata holding a remote URL with an embedded
password, and editor backups of config files.

**File permissions are evaluated on both platforms**: POSIX mode bits on Unix,
and the **discretionary ACL** on Windows, read through `advapi32` via
`GetNamedSecurityInfoW`. A file granting write or read access to a broad
principal — Everyone, Authenticated Users, BUILTIN\Users, Guests, Anonymous,
Power Users — is reported as `EXP006`/`EXP007`, naming which principal holds it.
A file with a present-but-NULL DACL (which grants everyone full control) is
reported too.

Only `READ_CONTROL` is needed, so this runs as an ordinary user and never elevates.

## Encodings

Text rules match the file **decoded to UTF-8**, not the raw bytes.

That distinction is the whole of the UTF-16 fix. A NUL byte is the usual signal
that a file is binary, and UTF-16 text is half NUL bytes, so judging by the raw
bytes wrote off every UTF-16 file as binary and skipped every text rule on it
while still counting it as scanned. Windows produces UTF-16 routinely, so those
were everyday misses rather than exotic ones.

Detection takes the byte-order mark when there is one, and the position of the
NUL bytes when there is not. Neither is sufficient on its own: an ELF image, a
zip header, or any run of 16-bit little-endian fields puts a zero in every
other byte exactly as Latin UTF-16 does. So a candidate encoding is only
accepted if decoding actually yields text, measured as the proportion of plain
ASCII. Tests assert that PE, ELF, zip and all-zero content are still classified
as bytes, because promoting a binary to text would hand every rule nonsense.

Line numbers index the decoded view, so a reported line means the same thing
whatever the encoding — the line you would count opening the file in an editor,
not a byte offset doubled by UTF-16.

Hashing, archive parsing, magic bytes and entropy all still read the raw bytes,
because those describe the file as stored rather than what it says.

## Performance

Roughly **0.7 ms per file**, dominated by I/O and per-file syscalls rather than
by matching. Two things get it there:

- **Every OS query and file read is made once per file** and shared by all four
  checks. Running all four costs barely more than the slowest single check,
  because none of them repeats the others' work.
- **Each pattern is guarded by a required-literal pre-filter.** Patterns that
  begin with `\b(` or `(?i)` give the regex engine nothing to anchor on, so it
  examines every byte position - the slowest rule measured 3.6 MB/s. A
  vectorised substring check runs first, and the overwhelming majority of files
  contain none of the literals, so the engine is never entered. This is worth
  about 27x end to end.

A pre-filter narrower than its pattern would silence a rule, which is a worse
failure than being slow, so `TestPrefiltersAcceptEveryKnownPositive` asserts
that every rule's filter accepts content its own pattern matches, and every rule
must carry a sample.

Peak memory is bounded: checks need whole file contents, so large reads are
gated to a quarter of the worker pool. Without that, the default 16 workers
could hold 16 x 32 MiB at once.

## Honest limitations

**ACL analysis is deliberately shallow.** It reports *granted breadth*, not
*effective access*:

- Only `ACCESS_ALLOWED` ACEs are read. **Deny ACEs are skipped**, so a file that
  grants Everyone write but separately denies it will still be reported. Deny
  entries take precedence in Windows' real evaluation; mis-parsing an unfamiliar
  ACE layout seemed worse than not reading it.
- Inherited and explicit ACEs are treated alike, and group membership is not
  resolved — no `AuthzAccessCheck` is performed.
- Only the fixed list of well-known broad SIDs above is matched. A custom group
  that happens to contain everyone will not be flagged.
- The SACL is never requested; that would need `SeSecurityPrivilege`.

**Everything else:**

- **Heuristics, not signatures.** Outside the hash list this is pattern and
  behaviour matching. It complements an endpoint AV product with a maintained
  feed; it does not replace one.
- **High-entropy executables produce false positives.** Installers and
  self-extracting archives look exactly like packed malware to an entropy test.
  That finding stays at Medium and says so in its own text.
- **Files above `-max-file-size` are not read at all** and are not hashed. Each
  one is named as `SCAN01` rather than passing quietly.
- **A clean report means these rules found nothing** — not that the files are safe.
- **ADS enumeration costs roughly 0.5 ms per file** on Windows, the largest
  single per-file cost. It is the price of the `TRT008` check; disable the
  `traits` check if you are scanning a very large tree and do not need it.

**Verified blind spots.** These were each demonstrated against the shipping
build, not inferred from the code:

- **A UTF-16 document in a non-Latin script is skipped by the text rules.**
  UTF-16 itself is now decoded and scanned — see Encodings below — but the
  detector requires the decoded sample to be mostly ASCII, because deciding a
  binary is text would feed every rule nonsense. A file written wholly in, say,
  Chinese fails that bar. It carries nothing the rules match anyway, since
  credentials and command lines are ASCII, but the gap is real.
- **A real credential whose value contains a word from the placeholder list**
  (`example`, `sample`, `test`, `fake`, `dummy`, …) is dropped. A structurally
  valid `AKIA…` key is skipped if it happens to spell one of them.
- **Archive contents are not inspected.** Only OOXML macro and remote-template
  checks look inside a ZIP; a `.zip`, `.tar.gz`, or `.7z` holding secrets is
  opaque.
- **Secrets inside binaries are not found** — the whole secrets check is skipped
  for binary content.
- **Only 15 findings per rule per file are reported**, and the report does not
  say when more were withheld.
- **`SCAN01` and `SCOPE01` are subject to `-min-severity`.** At `-min-severity
  high` a run that skipped files, or refused an out-of-scope link, says nothing
  about it. Keep the threshold at `low` if you need the coverage notices.
- **Directory permissions are never inspected**, only files'. A directory that
  grants a broad principal write access — letting anyone plant or replace files
  in it — produces no finding.
- **`-exclude` matching is case-sensitive**, including on Windows, where the
  filesystem is not. `-exclude node_modules` does not exclude `Node_Modules`.
- **`-out` file permissions are not enforced on Windows.** The `0600` mode is a
  no-op there; the report inherits the destination directory's ACL, so a report
  written into a shared folder is shared.
- **Split or encoded secrets are out of reach** by construction: string
  concatenation, base64 wrapping, and low-entropy passphrases all evade byte
  pattern matching. So does a download cradle split across two files.

## Layout

```
cmd/starkscan/main.go      CLI, flags, exit codes
build.ps1                  release build: vet + test gated, multi-platform
gui/                       Windows Forms front end (separate process)
internal/scope/            the confinement gate — read this first
internal/scan/             walker, worker pool, lazily-read file abstraction
internal/checks/           the four detection engines
internal/finding/          Finding type, severity, redaction
internal/report/           text and JSON rendering
internal/platform/         build-tagged OS access: Windows ACLs + ADS, Unix modes
```

## Tests

```bash
go test ./...
```

Scope tests cover the containment cases that matter: shared-prefix siblings,
`..` traversal, directory refusal, read-only handles, and Windows case folding.

The race detector runs clean over a concurrency test that walks 240 files with
16 workers and all four checks sharing instances (`go test -race ./...`, needs
cgo and a C compiler).

Windows platform tests verify ACL reading against real files — including that an
ordinary file is **not** reported as world-writable, since a scanner that flags
everything is worse than one that flags nothing.

Detection fixtures run in memory via `scan.NewMemoryFile`, which keeps signature
strings off disk: a real EICAR file gets quarantined by the host antivirus before
a test can read it.

## Licence

MIT. See [LICENSE](LICENSE).
