package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteGitLabCodeQuality(t *testing.T) {
	findings := []Finding{
		{
			RuleID:      "generic-api-key",
			Description: "Generic API Key",
			Match:       "synthetic field contains report fixture value",
			Secret:      "synthetic report fixture value",
			StartLine:   12,
			EndLine:     12,
			StartColumn: 11,
			EndColumn:   34,
			File:        "./src/settings.py",
			Fingerprint: "src/settings.py:generic-api-key:12",
		},
		{
			RuleID:      "private-key",
			Description: "Private Key",
			Match:       "synthetic private material marker",
			Secret:      "synthetic private material marker",
			StartLine:   3,
			File:        "keys/id_demo",
			SymlinkFile: "linked/id_demo",
			Fingerprint: "linked/id_demo:private-key:3",
		},
	}

	var buf bytes.Buffer
	reporter := GitLabCodeQualityReporter{}
	require.NoError(t, reporter.Write(testWriter{&buf}, findings))

	var got []GitLabCodeQualityIssue
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Len(t, got, 2)

	assert.Equal(t, "Secret detected by Gitleaks rule: generic-api-key", got[0].Description)
	assert.Equal(t, "gitleaks/generic-api-key", got[0].CheckName)
	assert.Equal(t, "src/settings.py:generic-api-key:12", got[0].Fingerprint)
	assert.Equal(t, "critical", got[0].Severity)
	assert.Equal(t, "src/settings.py", got[0].Location.Path)
	assert.Equal(t, 12, got[0].Location.Lines.Begin)

	assert.Equal(t, "linked/id_demo", got[1].Location.Path)
	assert.Equal(t, 3, got[1].Location.Lines.Begin)

	output := buf.String()
	assert.NotContains(t, output, "synthetic report fixture value")
	assert.NotContains(t, output, "synthetic private material marker")
	assert.NotContains(t, output, `"match"`)
	assert.NotContains(t, output, `"secret"`)
	assert.False(t, strings.HasPrefix(output, "\ufeff"), "GitLab report must not start with a BOM")
}

func TestWriteGitLabCodeQualityEmptyReport(t *testing.T) {
	var buf bytes.Buffer
	reporter := GitLabCodeQualityReporter{}
	require.NoError(t, reporter.Write(testWriter{&buf}, []Finding{}))

	assert.Equal(t, "[]\n", buf.String())
}

func TestWriteGitLabCodeQualityFallbackFingerprint(t *testing.T) {
	finding := Finding{
		RuleID:    "demo-rule",
		File:      "./demo/config.txt",
		StartLine: 7,
		Secret:    "not-in-output",
		Match:     "not-in-output",
	}

	var buf bytes.Buffer
	reporter := GitLabCodeQualityReporter{}
	require.NoError(t, reporter.Write(testWriter{&buf}, []Finding{finding}))

	var got []GitLabCodeQualityIssue
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Len(t, got, 1)
	assert.Equal(t, "demo/config.txt:demo-rule:7", got[0].Fingerprint)
}
