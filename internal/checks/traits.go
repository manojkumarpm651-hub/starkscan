package checks

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"starkscan/internal/finding"
	"starkscan/internal/scan"
)

// Traits finds files whose name or shape is designed to be mistaken for
// something harmless. These rules judge presentation, not content.
type Traits struct{}

func (*Traits) ID() string { return "traits" }
func (*Traits) Name() string {
	return "Disguised filenames, extension/content mismatches, and misleading file shapes"
}

// dangerousExts are extensions the OS will execute or interpret.
var dangerousExts = map[string]bool{
	".exe": true, ".scr": true, ".bat": true, ".cmd": true, ".com": true,
	".pif": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true,
	".wsf": true, ".wsh": true, ".hta": true, ".ps1": true, ".jar": true,
	".msi": true, ".lnk": true, ".reg": true, ".dll": true, ".cpl": true,
}

// harmlessLookingExts are what a disguised file pretends to be.
var harmlessLookingExts = map[string]bool{
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".ppt": true, ".pptx": true, ".txt": true, ".csv": true, ".rtf": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
	".mp3": true, ".mp4": true, ".avi": true, ".log": true, ".md": true,
	".json": true, ".xml": true, ".html": true,
}

// doubleExt catches "invoice.pdf.exe": a harmless-looking extension followed by
// an executable one. Windows hides known extensions by default, so the user
// sees only the first half.
var doubleExt = regexp.MustCompile(`(?i)\.(pdf|docx?|xlsx?|pptx?|txt|csv|rtf|jpe?g|png|gif|bmp|mp[34]|avi|log|zip|rar)\.(exe|scr|bat|cmd|com|pif|vbs|vbe|jse?|wsf|wsh|hta|ps1|jar|msi|lnk|reg)$`)

// bidiControls are invisible characters that reverse the display order of a
// filename, so "annexe[U+202E]cod.exe" renders as "annexeexe.doc".
var bidiControls = []rune{
	'‪', '‫', '‬', '‭', '‮',
	'⁦', '⁧', '⁨', '⁩', '‏', '‎',
}

func (t *Traits) Inspect(ctx context.Context, f *scan.File, emit func(finding.Finding)) {
	name := filepath.Base(f.Real)
	ext := f.Ext()

	t.checkDoubleExtension(f, name, emit)
	t.checkBidiOverride(f, name, emit)
	t.checkTrailingSpace(f, name, ext, emit)
	t.checkContentMismatch(f, ext, emit)
	t.checkHidden(f, name, emit)
	t.checkShortcut(f, ext, emit)
	t.checkStreams(f, emit)
}

func (t *Traits) checkDoubleExtension(f *scan.File, name string, emit func(finding.Finding)) {
	if !doubleExt.MatchString(name) {
		return
	}
	emit(finding.Finding{
		RuleID: "TRT001", Check: t.ID(), Severity: finding.High,
		Title:    "Executable disguised with a double extension",
		Detail:   "Windows hides known extensions by default, so this displays as a document while remaining executable. Treat it as hostile unless you can account for it.",
		Path:     f.Disp,
		Evidence: name,
	})
}

func (t *Traits) checkBidiOverride(f *scan.File, name string, emit func(finding.Finding)) {
	for _, r := range bidiControls {
		if !strings.ContainsRune(name, r) {
			continue
		}
		emit(finding.Finding{
			RuleID: "TRT002", Check: t.ID(), Severity: finding.High,
			Title:    "Filename contains a bidirectional override character",
			Detail:   "An invisible control character reverses how the rest of the name is displayed, which is used to make executables look like documents. There is no legitimate reason for one here.",
			Path:     f.Disp,
			Evidence: strings.ToValidUTF8(name, "?"),
		})
		return
	}
}

func (t *Traits) checkTrailingSpace(f *scan.File, name, ext string, emit func(finding.Finding)) {
	// Many spaces before the real extension push it off the end of a
	// fixed-width display, hiding what the file actually is.
	if !dangerousExts[ext] {
		return
	}
	stem := strings.TrimSuffix(name, ext)
	if !strings.HasSuffix(stem, "  ") {
		return
	}
	emit(finding.Finding{
		RuleID: "TRT003", Check: t.ID(), Severity: finding.Medium,
		Title:    "Executable filename padded with spaces",
		Detail:   "Padding pushes the real extension out of view in narrow file listings and dialogs.",
		Path:     f.Disp,
		Evidence: strings.ReplaceAll(name, " ", "·"),
	})
}

// checkContentMismatch compares what the file claims to be against its magic
// bytes. Only the dangerous direction is reported: content that executes while
// the name says it does not.
func (t *Traits) checkContentMismatch(f *scan.File, ext string, emit func(finding.Finding)) {
	header := f.Header(512)
	if len(header) < 4 {
		return
	}

	if kind := executableKind(header); kind != "" && harmlessLookingExts[ext] {
		emit(finding.Finding{
			RuleID: "TRT004", Check: t.ID(), Severity: finding.High,
			Title:    "File contents are executable but the extension says otherwise",
			Detail:   "The name claims " + ext + " but the file begins with " + kind + " headers. Renaming an executable is a common way to slip it past filters.",
			Path:     f.Disp,
			Evidence: kind,
		})
		return
	}

	// A PDF that is not a PDF is worth a look, though a corrupted or
	// truncated download produces the same signal.
	if ext == ".pdf" && !bytes.HasPrefix(header, []byte("%PDF")) {
		emit(finding.Finding{
			RuleID: "TRT005", Check: t.ID(), Severity: finding.Medium,
			Title:  "File named .pdf does not begin with a PDF header",
			Detail: "This may simply be a truncated or corrupted download, but confirm what it actually is before opening it.",
			Path:   f.Disp,
		})
	}
}

// checkStreams reports NTFS alternate data streams, which hold content that
// never appears in a directory listing and does not count toward the file size.
func (t *Traits) checkStreams(f *scan.File, emit func(finding.Finding)) {
	for _, s := range f.Streams() {
		// Zone.Identifier is attached to virtually every downloaded file by
		// Windows itself. Reporting it would bury the streams that matter.
		if strings.EqualFold(s.Name, "Zone.Identifier") {
			continue
		}
		sev := finding.Medium
		if s.Size > 4096 {
			sev = finding.High
		}
		emit(finding.Finding{
			RuleID: "TRT008", Check: t.ID(), Severity: sev,
			Title:    "File carries a hidden alternate data stream",
			Detail:   "Alternate streams are invisible to directory listings and do not change the reported file size, which makes them a long-standing place to stash payloads. Inspect it with: more < \"" + f.Disp + ":" + s.Name + "\"",
			Path:     f.Disp,
			Evidence: fmt.Sprintf("%s (%d bytes)", s.Name, s.Size),
		})
	}
}

func (t *Traits) checkHidden(f *scan.File, name string, emit func(finding.Finding)) {
	dotfile := strings.HasPrefix(name, ".") && name != "." && name != ".."
	if !f.Hidden() && !dotfile {
		return
	}
	// A hidden dotfile is unremarkable; a hidden *executable* is not.
	kind := executableKind(f.Header(512))
	if kind == "" && !dangerousExts[f.Ext()] {
		return
	}
	emit(finding.Finding{
		RuleID: "TRT006", Check: t.ID(), Severity: finding.Medium,
		Title:    "Hidden executable file",
		Detail:   "The file is marked hidden and is executable. Hiding is how dropped payloads stay out of casual view.",
		Path:     f.Disp,
		Evidence: name,
	})
}

// checkShortcut looks inside Windows .lnk files for an embedded interpreter
// invocation, the standard way a shortcut is turned into a launcher.
func (t *Traits) checkShortcut(f *scan.File, ext string, emit func(finding.Finding)) {
	if ext != ".lnk" {
		return
	}
	content, err := f.Content()
	if err != nil {
		return
	}
	// .lnk stores strings as UTF-16, so match on the ASCII-with-NUL form too.
	needles := []string{"powershell", "cmd.exe", "mshta", "wscript", "cscript", "rundll32", "certutil"}
	low := bytes.ToLower(content)
	stripped := bytes.ReplaceAll(low, []byte{0}, nil)
	for _, n := range needles {
		if !bytes.Contains(low, []byte(n)) && !bytes.Contains(stripped, []byte(n)) {
			continue
		}
		emit(finding.Finding{
			RuleID: "TRT007", Check: t.ID(), Severity: finding.High,
			Title:    "Shortcut launches a command interpreter",
			Detail:   "A .lnk that invokes an interpreter is a launcher, not a shortcut to a document. Inspect its target before double-clicking.",
			Path:     f.Disp,
			Evidence: n,
		})
		return
	}
}
