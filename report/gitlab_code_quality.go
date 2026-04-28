package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

const gitLabCodeQualitySeverity = "critical"

type GitLabCodeQualityReporter struct {
	BasePath string
}

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
		issues = append(issues, newGitLabCodeQualityIssue(finding, r.BasePath))
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(issues)
}

func newGitLabCodeQualityIssue(f Finding, basePath string) GitLabCodeQualityIssue {
	path := gitLabCodeQualityPath(f, basePath)
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

func gitLabCodeQualityPath(f Finding, basePath string) string {
	path := f.File
	if f.SymlinkFile != "" {
		path = f.SymlinkFile
	}
	path = gitLabCodeQualityRelativePath(path, basePath)
	path = filepath.ToSlash(filepath.Clean(path))
	return strings.TrimPrefix(path, "./")
}

func gitLabCodeQualityRelativePath(path, basePath string) string {
	if path == "" || basePath == "" || !filepath.IsAbs(path) {
		return path
	}

	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return path
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	rel, err := filepath.Rel(absBase, absPath)
	if err != nil || !gitLabCodeQualityPathIsBelowBase(rel) {
		return path
	}
	return rel
}

func gitLabCodeQualityPathIsBelowBase(rel string) bool {
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func gitLabCodeQualityLine(f Finding) int {
	if f.StartLine < 1 {
		return 1
	}
	return f.StartLine
}

func gitLabCodeQualityFingerprint(f Finding, path string, line int) string {
	if f.Commit != "" {
		return fmt.Sprintf("%s:%s:%s:%d", f.Commit, path, f.RuleID, line)
	}
	return fmt.Sprintf("%s:%s:%d", path, f.RuleID, line)
}
