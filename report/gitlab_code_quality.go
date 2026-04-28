package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

const gitLabCodeQualitySeverity = "critical"

type GitLabCodeQualityReporter struct{}

var _ Reporter = (*GitLabCodeQualityReporter)(nil)

type GitLabCodeQualityIssue struct {
	Description string                 `json:"description"`
	CheckName   string                 `json:"check_name"`
	Fingerprint string                 `json:"fingerprint"`
	Severity    string                 `json:"severity"`
	Location    GitLabCodeQualityPlace `json:"location"`
}

type GitLabCodeQualityPlace struct {
	Path  string                   `json:"path"`
	Lines GitLabCodeQualityLineMap `json:"lines"`
}

type GitLabCodeQualityLineMap struct {
	Begin int `json:"begin"`
}

func (r *GitLabCodeQualityReporter) Write(w io.WriteCloser, findings []Finding) error {
	issues := make([]GitLabCodeQualityIssue, 0, len(findings))
	for _, finding := range findings {
		issues = append(issues, newGitLabCodeQualityIssue(finding))
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(issues)
}

func newGitLabCodeQualityIssue(f Finding) GitLabCodeQualityIssue {
	path := gitLabCodeQualityPath(f)
	line := gitLabCodeQualityLine(f)
	return GitLabCodeQualityIssue{
		Description: fmt.Sprintf("Secret detected by Gitleaks rule: %s", f.RuleID),
		CheckName:   fmt.Sprintf("gitleaks/%s", f.RuleID),
		Fingerprint: gitLabCodeQualityFingerprint(f, path, line),
		Severity:    gitLabCodeQualitySeverity,
		Location: GitLabCodeQualityPlace{
			Path: path,
			Lines: GitLabCodeQualityLineMap{
				Begin: line,
			},
		},
	}
}

func gitLabCodeQualityPath(f Finding) string {
	path := f.File
	if f.SymlinkFile != "" {
		path = f.SymlinkFile
	}
	path = filepath.ToSlash(filepath.Clean(path))
	return strings.TrimPrefix(path, "./")
}

func gitLabCodeQualityLine(f Finding) int {
	if f.StartLine < 1 {
		return 1
	}
	return f.StartLine
}

func gitLabCodeQualityFingerprint(f Finding, path string, line int) string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	return fmt.Sprintf("%s:%s:%d", path, f.RuleID, line)
}
