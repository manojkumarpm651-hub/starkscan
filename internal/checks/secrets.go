package checks

import (
	"context"
	"regexp"
	"strings"

	"starkscan/internal/finding"
	"starkscan/internal/scan"
)

// Secrets finds credential material committed into files.
type Secrets struct{}

func (*Secrets) ID() string { return "secrets" }
func (*Secrets) Name() string {
	return "Hardcoded credentials, API keys, private keys, and connection strings"
}

// secretRule pairs a pattern with how to judge what it captured.
type secretRule struct {
	id    string
	title string
	sev   finding.Severity
	re    *regexp.Regexp
	// group is the submatch holding the secret itself; 0 means the whole match.
	group int
	// minEntropy, when non-zero, rejects matches whose captured value looks
	// too structured to be a real key. This is what keeps generic
	// "password = ..." patterns from drowning the report in false positives.
	minEntropy float64
	// publicMarker means the match is a format banner rather than the secret
	// itself, so redacting it would hide useful information and reveal nothing.
	publicMarker bool
	// prefilter lists lowercase literals, at least one of which the pattern
	// cannot match without. Checking them with a vectorised substring scan is
	// orders of magnitude cheaper than running the regex, and the overwhelming
	// majority of files contain none of them.
	//
	// Every literal here must be REQUIRED by the pattern. A prefilter narrower
	// than its regex would silently stop detections, which is worse than being
	// slow, so TestPrefiltersAcceptEveryKnownPositive guards the invariant.
	prefilter []string
}

var secretRules = []secretRule{
	{
		id: "SEC001", title: "AWS access key ID", sev: finding.Critical,
		re: regexp.MustCompile(`\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|APKA)[0-9A-Z]{16})\b`), group: 1,
		prefilter: []string{"akia", "asia", "agpa", "aida", "aroa", "anpa", "anva", "apka"},
	},
	{
		id: "SEC002", title: "AWS secret access key", sev: finding.Critical,
		re:    regexp.MustCompile(`(?i)aws_?secret_?access_?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
		group: 1, minEntropy: 4.0,
		prefilter: []string{"aws"},
	},
	{
		id: "SEC003", title: "GitHub token", sev: finding.Critical,
		re: regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,251})\b`), group: 1,
		prefilter: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
	},
	{
		id: "SEC004", title: "Slack token", sev: finding.High,
		re: regexp.MustCompile(`\b(xox[baprse]-[A-Za-z0-9-]{10,})`), group: 1,
		prefilter: []string{"xox"},
	},
	{
		id: "SEC005", title: "Slack incoming webhook", sev: finding.High,
		re: regexp.MustCompile(`(https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,})`), group: 1,
		prefilter: []string{"hooks.slack.com"},
	},
	{
		id: "SEC006", title: "Stripe live secret key", sev: finding.Critical,
		re: regexp.MustCompile(`\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b`), group: 1,
		prefilter: []string{"sk_live_", "rk_live_"},
	},
	{
		id: "SEC007", title: "Google API key", sev: finding.High,
		re: regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`), group: 1,
		prefilter: []string{"aiza"},
	},
	{
		id: "SEC008", title: "Private key block", sev: finding.Critical,
		re: regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`), group: 0,
		publicMarker: true,
	},
	{
		id: "SEC009", title: "SendGrid API key", sev: finding.Critical,
		re: regexp.MustCompile(`\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b`), group: 1,
		prefilter: []string{"sg."},
	},
	{
		id: "SEC010", title: "Anthropic API key", sev: finding.Critical,
		re: regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_-]{24,})\b`), group: 1,
		prefilter: []string{"sk-ant-"},
	},
	{
		id: "SEC011", title: "OpenAI-style API key", sev: finding.Critical,
		re: regexp.MustCompile(`\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,})\b`), group: 1,
		prefilter: []string{"sk-"},
	},
	{
		id: "SEC012", title: "npm access token", sev: finding.High,
		re: regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`), group: 1,
		prefilter: []string{"npm_"},
	},
	{
		id: "SEC013", title: "Twilio account SID paired with auth token", sev: finding.High,
		re:    regexp.MustCompile(`(?i)twilio[_a-z]*(?:auth|token|secret)[_a-z]*\s*[:=]\s*["']?([A-Za-z0-9]{32})["']?`),
		group: 1, minEntropy: 3.5,
		prefilter: []string{"twilio"},
	},
	{
		id: "SEC014", title: "Credentials embedded in a connection string", sev: finding.Critical,
		re:        regexp.MustCompile(`\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|ftp|https?)://[^:/\s]+:([^@/\s]{4,})@`),
		group:     1,
		prefilter: []string{"://"},
	},
	{
		id: "SEC015", title: "JSON Web Token", sev: finding.Medium,
		re: regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b`), group: 1,
		prefilter: []string{"eyj"},
	},
	{
		id: "SEC016", title: "Registry auth token", sev: finding.High,
		re:    regexp.MustCompile(`(?i)_auth(?:Token)?\s*=\s*["']?([A-Za-z0-9+/=_-]{16,})["']?`),
		group: 1, minEntropy: 3.5,
		prefilter: []string{"_auth"},
	},
	{
		id: "SEC017", title: "Generic hardcoded secret", sev: finding.Medium,
		re:    regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd)\s*[:=]\s*["']([^"'\s]{12,120})["']`),
		group: 1, minEntropy: 3.6,
		prefilter: []string{"apikey", "api_key", "api-key", "secretkey", "secret_key", "secret-key",
			"accesstoken", "access_token", "access-token", "authtoken", "auth_token",
			"auth-token", "clientsecret", "client_secret", "client-secret",
			"password", "passwd"},
	},
	{
		id: "SEC018", title: "Private key file contents (PuTTY)", sev: finding.Critical,
		re: regexp.MustCompile(`PuTTY-User-Key-File-\d`), group: 0,
		publicMarker: true,
	},
}

// maxPerRule caps how many hits one rule reports per file, so a generated file
// full of tokens produces a usable report instead of thousands of lines.
const maxPerRule = 15

func (s *Secrets) Inspect(ctx context.Context, f *scan.File, emit func(finding.Finding)) {
	// Credential material is text; skipping binaries avoids megabytes of
	// regex work per executable for no detection value.
	if f.IsBinary() {
		return
	}
	content, err := f.Content()
	if err != nil || len(content) == 0 {
		return
	}

	// claimed records the byte ranges already reported. Rules are ordered
	// most-specific first, so when two patterns cover the same bytes — an
	// "sk-ant-…" key matches both the Anthropic and the generic OpenAI-style
	// rule — the specific one wins and the value is reported exactly once.
	var claimed []span

	for _, rule := range secretRules {
		if ctx.Err() != nil {
			return
		}
		if !anyContainsFold(content, rule.prefilter) {
			continue
		}
		hits := rule.re.FindAllSubmatchIndex(content, -1)
		seenLines := map[int]bool{}
		count := 0
		for _, m := range hits {
			if count >= maxPerRule {
				break
			}
			start, end := m[0], m[1]
			if rule.group > 0 && len(m) > 2*rule.group+1 && m[2*rule.group] >= 0 {
				start, end = m[2*rule.group], m[2*rule.group+1]
			}
			value := string(content[start:end])

			if looksLikePlaceholder(value) {
				continue
			}
			if rule.minEntropy > 0 && shannon([]byte(value)) < rule.minEntropy {
				continue
			}
			if overlaps(claimed, start, end) {
				continue
			}

			line := f.LineAt(start)
			if seenLines[line] {
				continue
			}
			seenLines[line] = true
			count++
			claimed = append(claimed, span{start, end})

			// A format banner such as "-----BEGIN RSA PRIVATE KEY-----" is not
			// itself secret; masking it would only hide which key type was found.
			evidence := finding.Redact(value)
			if rule.publicMarker {
				evidence = finding.Truncate(value, 60)
			}

			emit(finding.Finding{
				RuleID:   rule.id,
				Check:    s.ID(),
				Severity: rule.sev,
				Title:    rule.title,
				Detail:   secretAdvice(rule.id),
				Path:     f.Disp,
				Line:     line,
				Evidence: evidence,
			})
		}
	}
}

// span is a half-open byte range within one file's contents.
type span struct{ start, end int }

func overlaps(claimed []span, start, end int) bool {
	for _, c := range claimed {
		if start < c.end && c.start < end {
			return true
		}
	}
	return false
}

func secretAdvice(ruleID string) string {
	switch ruleID {
	case "SEC008", "SEC018":
		return "Private key material should never sit in a scanned working folder. Move it to a key store and rotate it if this copy was ever shared."
	case "SEC015":
		return "Tokens are often pasted into code during debugging. Confirm whether this one is still valid before dismissing it."
	default:
		return "Treat this credential as compromised: rotate it at the provider, then move the value into an environment variable or secret manager."
	}
}

// init guards against a rule being added with a capture group the pattern does
// not define, which would silently report the wrong span.
func init() {
	for _, r := range secretRules {
		if r.group > r.re.NumSubexp() {
			panic("secret rule " + r.id + " references a capture group it does not define")
		}
	}
}

var _ = strings.TrimSpace
