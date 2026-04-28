package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zricethezav/gitleaks/v8/report"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitConfigLoadsPyprojectToolGitleaks(t *testing.T) {
	source := t.TempDir()
	writeFile(t, filepath.Join(source, "pyproject.toml"), `
[tool.gitleaks]
title = "pyproject config"

[[tool.gitleaks.rules]]
id = "pyproject-demo"
description = "Pyproject demo"
regex = '''demo_secret_[a-z]{24}'''
keywords = ["demo"]
`)

	resetConfigTestState(t)
	initConfig(source)

	cfg := Config(rootCmd)
	require.Contains(t, cfg.Rules, "pyproject-demo")
	assert.Equal(t, filepath.Join(source, "pyproject.toml"), cfg.Path)
}

func TestInitConfigPrefersDotGitleaksTomlOverPyproject(t *testing.T) {
	source := t.TempDir()
	writeFile(t, filepath.Join(source, ".gitleaks.toml"), `
title = "dotfile config"

[[rules]]
id = "dotfile-demo"
description = "Dotfile demo"
regex = '''dotfile_secret_[a-z]{24}'''
keywords = ["dotfile"]
`)
	writeFile(t, filepath.Join(source, "pyproject.toml"), `
[tool.gitleaks]
title = "pyproject config"

[[tool.gitleaks.rules]]
id = "pyproject-demo"
description = "Pyproject demo"
regex = '''demo_secret_[a-z]{24}'''
keywords = ["demo"]
`)

	resetConfigTestState(t)
	initConfig(source)

	cfg := Config(rootCmd)
	require.Contains(t, cfg.Rules, "dotfile-demo")
	assert.NotContains(t, cfg.Rules, "pyproject-demo")
	assert.Equal(t, filepath.Join(source, ".gitleaks.toml"), cfg.Path)
}

func TestInitConfigIgnoresPyprojectWithoutToolGitleaks(t *testing.T) {
	source := t.TempDir()
	writeFile(t, filepath.Join(source, "pyproject.toml"), `
[project]
name = "demo"
`)

	resetConfigTestState(t)
	initConfig(source)

	cfg := Config(rootCmd)
	assert.NotEmpty(t, cfg.Rules)
	assert.NotContains(t, cfg.Rules, "pyproject-demo")
	assert.Empty(t, cfg.Path)
}

func TestDetectorAcceptsGitLabCodeQualityReportFormats(t *testing.T) {
	for _, reportFormat := range []string{"gitlab-code-quality", "gcq"} {
		t.Run(reportFormat, func(t *testing.T) {
			source := t.TempDir()
			reportPath := filepath.Join(t.TempDir(), "gl-code-quality-report.json")

			resetConfigTestState(t)
			require.NoError(t, rootCmd.PersistentFlags().Set("report-path", reportPath))
			require.NoError(t, rootCmd.PersistentFlags().Set("report-format", reportFormat))
			initConfig(source)

			cfg := Config(rootCmd)
			detector := Detector(rootCmd, cfg, source)

			reporter, ok := detector.Reporter.(*report.GitLabCodeQualityReporter)
			require.True(t, ok)
			assert.Equal(t, source, reporter.BasePath)
		})
	}
}

func resetConfigTestState(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		activeConfig = nil
		activeConfigPath = ""
		_ = rootCmd.PersistentFlags().Set("config", "")
		_ = rootCmd.PersistentFlags().Set("no-banner", "false")
		_ = rootCmd.PersistentFlags().Set("report-path", "")
		_ = rootCmd.PersistentFlags().Set("report-format", "")
		viper.Reset()
	})

	activeConfig = nil
	activeConfigPath = ""
	viper.Reset()
	require.NoError(t, rootCmd.PersistentFlags().Set("config", ""))
	require.NoError(t, rootCmd.PersistentFlags().Set("no-banner", "true"))
	require.NoError(t, rootCmd.PersistentFlags().Set("report-path", ""))
	require.NoError(t, rootCmd.PersistentFlags().Set("report-format", ""))
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}
