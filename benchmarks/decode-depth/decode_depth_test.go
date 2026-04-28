package decodedepth

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func TestSyntheticDecodeFixtureContainsNoProviderPrefixes(t *testing.T) {
	fixture := syntheticFixture(128)
	for _, prefix := range []string{"ghp_", "glpat-", "AKIA", "sk_live_", "xoxb-"} {
		if strings.Contains(fixture, prefix) {
			t.Fatalf("synthetic benchmark fixture contains provider-looking prefix %q", prefix)
		}
	}
}

func BenchmarkSyntheticDecodeDepth(b *testing.B) {
	cfg := benchmarkConfig()
	fixture := syntheticFixture(2048)

	for _, depth := range []int{0, 1, 2, 5} {
		b.Run(fmt.Sprintf("depth_%d", depth), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				detector := detect.NewDetector(cfg)
				detector.MaxDecodeDepth = depth
				findings, err := detector.DetectSource(context.Background(), &sources.File{
					Content: strings.NewReader(fixture),
					Path:    "synthetic-decode-depth.txt",
					Config:  &cfg,
				})
				if err != nil {
					b.Fatal(err)
				}
				if depth > 0 && len(findings) == 0 {
					b.Fatalf("expected decoded findings at depth %d", depth)
				}
				b.ReportMetric(float64(len(findings)), "findings/op")
				b.ReportMetric(float64(len(fixture)), "bytes/input")
			}
		})
	}
}

func benchmarkConfig() config.Config {
	rule := config.Rule{
		RuleID:      "synthetic-demo-secret",
		Description: "Synthetic demo secret",
		Regex:       regexp.MustCompile(`demo_secret_[a-z]{24}`),
		Keywords:    []string{"demo"},
		Tags:        []string{"synthetic", "benchmark"},
	}
	return config.Config{
		Rules: map[string]config.Rule{
			rule.RuleID: rule,
		},
		Keywords: map[string]struct{}{
			"demo": {},
		},
	}
}

func syntheticFixture(lines int) string {
	var b strings.Builder
	for i := 0; i < lines; i++ {
		plain := fmt.Sprintf("line_%06d demo_secret_%s", i, strings.Repeat("a", 24))
		encoded := base64.StdEncoding.EncodeToString([]byte(plain))
		b.WriteString(encoded)
		b.WriteByte('\n')
	}
	return b.String()
}
