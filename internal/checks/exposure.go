package checks

import (
	"bytes"
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"starkscan/internal/finding"
	"starkscan/internal/scan"
)

// Exposure reports sensitive material sitting somewhere it can be read, and
// permissions that widen who can read or change it.
type Exposure struct{}

func (*Exposure) ID() string { return "exposure" }
func (*Exposure) Name() string {
	return "Key files, credential stores, git secrets, and overly permissive file modes"
}

// keyFileExts are extensions that normally carry private key material.
var keyFileExts = map[string]string{
	".pem":      "PEM key or certificate bundle",
	".key":      "private key",
	".pfx":      "PKCS#12 key store",
	".p12":      "PKCS#12 key store",
	".jks":      "Java key store",
	".ppk":      "PuTTY private key",
	".keystore": "Java key store",
}

// credentialFiles are well-known paths whose whole purpose is holding secrets.
var credentialFiles = map[string]string{
	"credentials":             "cloud provider credential file",
	".npmrc":                  "npm registry configuration (may hold an auth token)",
	".pypirc":                 "PyPI upload configuration (may hold a password)",
	".netrc":                  "netrc login file",
	"_netrc":                  "netrc login file",
	".git-credentials":        "stored git credentials",
	".dockercfg":              "Docker registry credentials",
	".bash_history":           "shell history (often contains pasted secrets)",
	".zsh_history":            "shell history (often contains pasted secrets)",
	"consolehost_history.txt": "PowerShell history (often contains pasted secrets)",
	"id_rsa":                  "SSH private key",
	"id_dsa":                  "SSH private key",
	"id_ecdsa":                "SSH private key",
	"id_ed25519":              "SSH private key",
}

// backupSuffixes mark editor and tooling leftovers, which routinely preserve a
// config file's secrets while escaping the ignore rules that covered the original.
var backupSuffixes = []string{".bak", ".old", ".orig", ".save", ".swp", ".tmp", "~"}

// gitCredentialURL matches a remote URL with an inline username and password.
var gitCredentialURL = regexp.MustCompile(`(?i)://[^:/\s]+:[^@/\s]+@`)

func (e *Exposure) Inspect(ctx context.Context, f *scan.File, emit func(finding.Finding)) {
	name := f.Name()
	ext := f.Ext()

	e.checkKeyFile(f, name, ext, emit)
	e.checkCredentialFile(f, name, emit)
	e.checkEnvFile(f, name, emit)
	e.checkGitExposure(f, emit)
	e.checkBackupOfConfig(f, name, emit)
	e.checkPermissions(f, emit)
}

func (e *Exposure) checkKeyFile(f *scan.File, name, ext string, emit func(finding.Finding)) {
	desc, isKeyExt := keyFileExts[ext]
	if !isKeyExt {
		return
	}
	// A .pem holding only a certificate is public material, so confirm there
	// is actually a private key inside before raising the severity.
	hasPrivate := bytes.Contains(f.Text(), []byte("PRIVATE KEY"))

	sev := finding.Medium
	detail := "Confirm whether this holds private key material and whether it belongs in a working folder."
	if hasPrivate || ext == ".pfx" || ext == ".p12" || ext == ".ppk" {
		sev = finding.High
		detail = "Private key material in a working folder is easy to copy, sync, or commit by accident. Move it to a key store."
	}
	emit(finding.Finding{
		RuleID: "EXP001", Check: e.ID(), Severity: sev,
		Title:    "Key or certificate file present",
		Detail:   detail,
		Path:     f.Disp,
		Evidence: desc,
	})
}

func (e *Exposure) checkCredentialFile(f *scan.File, name string, emit func(finding.Finding)) {
	desc, known := credentialFiles[name]
	if !known {
		// SSH keys are also named id_<type> with no extension variants.
		if strings.HasPrefix(name, "id_") && f.Ext() == "" {
			desc, known = "SSH private key", true
		}
	}
	if !known {
		return
	}
	emit(finding.Finding{
		RuleID: "EXP002", Check: e.ID(), Severity: finding.High,
		Title:    "Credential store in scanned folder",
		Detail:   "Identified as a " + desc + ". Anything that reads this folder — a backup client, a sync agent, a build step — reads this too.",
		Path:     f.Disp,
		Evidence: name,
	})
}

func (e *Exposure) checkEnvFile(f *scan.File, name string, emit func(finding.Finding)) {
	if name != ".env" && !strings.HasPrefix(name, ".env.") {
		return
	}
	// .env.example files exist to be committed and hold no real values.
	if strings.Contains(name, "example") || strings.Contains(name, "sample") || strings.Contains(name, "template") {
		return
	}
	emit(finding.Finding{
		RuleID: "EXP003", Check: e.ID(), Severity: finding.Medium,
		Title:  "Environment file present",
		Detail: "Environment files hold live configuration secrets. Confirm this one is covered by .gitignore and excluded from backups. The secrets check reports the individual values.",
		Path:   f.Disp,
	})
}

// checkGitExposure looks for credentials committed into git's own metadata,
// which survives even after the working tree is cleaned.
func (e *Exposure) checkGitExposure(f *scan.File, emit func(finding.Finding)) {
	slashed := filepath.ToSlash(strings.ToLower(f.Real))
	if !strings.Contains(slashed, "/.git/") {
		return
	}
	base := f.Name()
	if base != "config" && base != "fetch_head" && base != "packed-refs" {
		return
	}
	content := f.Text()
	if !gitCredentialURL.Match(content) {
		return
	}
	loc := gitCredentialURL.FindIndex(content)
	emit(finding.Finding{
		RuleID: "EXP004", Check: e.ID(), Severity: finding.Critical,
		Title:  "Git metadata contains a remote URL with an embedded password",
		Detail: "The credential is stored in plaintext inside the repository's own files and travels with any copy of it. Rotate it and switch the remote to SSH or a credential helper.",
		Path:   f.Disp,
		Line:   f.LineAt(loc[0]),
	})
}

func (e *Exposure) checkBackupOfConfig(f *scan.File, name string, emit func(finding.Finding)) {
	var matched string
	for _, sfx := range backupSuffixes {
		if strings.HasSuffix(name, sfx) {
			matched = sfx
			break
		}
	}
	if matched == "" {
		return
	}
	stem := strings.TrimSuffix(name, matched)
	interesting := strings.Contains(stem, "env") || strings.Contains(stem, "config") ||
		strings.Contains(stem, "secret") || strings.Contains(stem, "credential") ||
		strings.Contains(stem, "settings")
	if !interesting {
		return
	}
	emit(finding.Finding{
		RuleID: "EXP005", Check: e.ID(), Severity: finding.Medium,
		Title:    "Backup copy of a configuration file",
		Detail:   "Editor and tooling backups keep the original's secrets but rarely match the ignore rules that protected it. Delete it or bring it under the same rules.",
		Path:     f.Disp,
		Evidence: name,
	})
}

// checkPermissions reports access granted beyond the file's owner: POSIX mode
// bits on Unix, and the discretionary ACL on Windows.
func (e *Exposure) checkPermissions(f *scan.File, emit func(finding.Finding)) {
	p := f.Perm()
	if !p.PermsSupported {
		return
	}

	grantee := p.Grantee
	if grantee == "" {
		grantee = "a broad group"
	}

	if p.WorldWritable {
		emit(finding.Finding{
			RuleID: "EXP006", Check: e.ID(), Severity: finding.High,
			Title:    "File is writable beyond its owner",
			Detail:   "Any account in this group can replace the file's contents. If anything executes or trusts the file, that is a privilege escalation path.",
			Path:     f.Disp,
			Evidence: grantee + " has write access",
		})
	}
	if p.WorldReadable && e.isSensitive(f) {
		emit(finding.Finding{
			RuleID: "EXP007", Check: e.ID(), Severity: finding.High,
			Title:    "Sensitive file is readable beyond its owner",
			Detail:   "Restrict this file to its owner: chmod 600 on Unix, or remove the broad grant from its Security tab on Windows.",
			Path:     f.Disp,
			Evidence: grantee + " has read access",
		})
	}
}

func (e *Exposure) isSensitive(f *scan.File) bool {
	if _, ok := keyFileExts[f.Ext()]; ok {
		return true
	}
	if _, ok := credentialFiles[f.Name()]; ok {
		return true
	}
	return strings.HasPrefix(f.Name(), ".env")
}

// Compile-time confirmation that every check satisfies the interface.
var (
	_ Check = (*Secrets)(nil)
	_ Check = (*Malware)(nil)
	_ Check = (*Traits)(nil)
	_ Check = (*Exposure)(nil)
)

var _ = context.Background
