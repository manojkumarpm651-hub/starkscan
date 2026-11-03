package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"starkscan/internal/finding"
	"starkscan/internal/scan"
)

// benchBody is a realistic "clean" text file: prose and code with none of the
// indicators any rule is looking for. Most files in a real scan look like this,
// so this is the case worth optimising.
func benchBody(kb int) []byte {
	var b strings.Builder
	line := "the quick brown fox jumps over the lazy dog and keeps running onward\n"
	for b.Len() < kb*1024 {
		b.WriteString(line)
	}
	return []byte(b.String())
}

func benchCheck(b *testing.B, c Check, name string, body []byte) {
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f := scan.NewMemoryFile(name, body)
		c.Inspect(context.Background(), f, func(finding.Finding) {})
	}
}

func BenchmarkSecretsCleanFile(b *testing.B) {
	benchCheck(b, &Secrets{}, "clean.txt", benchBody(64))
}

func BenchmarkMalwareCleanFile(b *testing.B) {
	benchCheck(b, &Malware{}, "clean.txt", benchBody(64))
}

func BenchmarkTraitsCleanFile(b *testing.B) {
	benchCheck(b, &Traits{}, "clean.txt", benchBody(64))
}

func BenchmarkExposureCleanFile(b *testing.B) {
	benchCheck(b, &Exposure{}, "clean.txt", benchBody(64))
}

// BenchmarkSecretRulesIndividually shows which patterns cost the most over a
// clean file, which is where a pre-filter would pay off.
func BenchmarkSecretRulesIndividually(b *testing.B) {
	body := benchBody(64)
	for _, rule := range secretRules {
		b.Run(fmt.Sprintf("%s_%s", rule.id, strings.ReplaceAll(rule.title, " ", "_")), func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = rule.re.FindAllSubmatchIndex(body, -1)
			}
		})
	}
}

// BenchmarkScriptRulesIndividually does the same for the malware patterns.
func BenchmarkScriptRulesIndividually(b *testing.B) {
	body := benchBody(64)
	for _, rule := range scriptRules {
		b.Run(rule.id, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = rule.re.FindIndex(body)
			}
		})
	}
}
