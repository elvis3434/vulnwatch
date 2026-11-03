package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) (cfgPath, reportDir string) {
	t.Helper()
	dir := t.TempDir()
	reportDir = filepath.Join(dir, "reports")
	cacheDir := filepath.Join(dir, "cache")
	cfgPath = filepath.Join(dir, "vulnwatch.toml")

	src := "[general]\n" +
		"report_dir = '" + reportDir + "'\n" +
		"cache_dir  = '" + cacheDir + "'\n" +
		body
	if err := os.WriteFile(cfgPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfgPath, reportDir
}

func TestVersionCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, &out, &errOut); code != exitOK {
		t.Fatalf("exit code = %d，預期 0", code)
	}
	if !strings.Contains(out.String(), "vulnwatch") {
		t.Errorf("輸出 = %q", out.String())
	}
}

func TestNoArgsShowsUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(nil, &out, &errOut); code != exitConfigError {
		t.Errorf("exit code = %d，預期 2", code)
	}
	if !strings.Contains(errOut.String(), "用法") {
		t.Errorf("應該顯示用法說明：%q", errOut.String())
	}
}

func TestUnknownSubcommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"scam"}, &out, &errOut); code != exitConfigError {
		t.Errorf("exit code = %d，預期 2", code)
	}
}

// TestCheckReportsFieldAndLine 是規劃 §9 第一條驗收標準：
// vulnwatch check 能指出設定檔錯誤的具體欄位與行號。
func TestCheckReportsFieldAndLine(t *testing.T) {
	cfgPath, _ := writeConfig(t, `min_severity = "URGENT"

[[packages]]
ecosystem = "Golang"
name      = "github.com/gin-gonic/gin"
version   = "v1.9.1"
`)
	var out, errOut bytes.Buffer
	code := run([]string{"check", "-c", cfgPath}, &out, &errOut)
	if code != exitConfigError {
		t.Fatalf("exit code = %d，預期 2（設定錯誤）", code)
	}
	s := errOut.String()
	if !strings.Contains(s, "general.min_severity") {
		t.Errorf("應指出欄位 general.min_severity：\n%s", s)
	}
	if !strings.Contains(s, "packages.ecosystem") {
		t.Errorf("應指出欄位 packages.ecosystem：\n%s", s)
	}
	if !strings.Contains(s, "vulnwatch.toml:4") {
		t.Errorf("應指出 min_severity 在第 4 行：\n%s", s)
	}
	if !strings.Contains(s, "vulnwatch.toml:7") {
		t.Errorf("應指出 ecosystem 在第 7 行：\n%s", s)
	}
}

func TestCheckPassesAndShowsWarnings(t *testing.T) {
	cfgPath, _ := writeConfig(t, `timezone       = "Asia/Taipei"
report_formats = ["md", "json", "html"]

[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"
`)
	var out, errOut bytes.Buffer
	code := run([]string{"check", "-c", cfgPath}, &out, &errOut)
	if code != exitOK {
		t.Fatalf("exit code = %d，預期 0。stderr:\n%s", code, errOut.String())
	}
	s := out.String()
	if !strings.Contains(s, "沒有錯誤") {
		t.Errorf("輸出應說明沒有錯誤：\n%s", s)
	}
	// Asia/Taipei 必須能載入 —— 這驗證了 import _ "time/tzdata"（規劃 §6 / §9）
	if !strings.Contains(s, "Asia/Taipei") {
		t.Errorf("應顯示時區 Asia/Taipei：\n%s", s)
	}
	if !strings.Contains(s, "警告") || !strings.Contains(s, "html") {
		t.Errorf("應顯示 html 格式的警告：\n%s", s)
	}
}

func TestCheckMissingConfigFile(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"check", "-c", filepath.Join(t.TempDir(), "nope.toml")}, &out, &errOut)
	if code != exitConfigError {
		t.Errorf("exit code = %d，預期 2", code)
	}
}

// TestScanOfflineWithEmptyCacheStillWritesReport 驗證排程情境下的健壯性：
// 就算完全沒有快取，--offline 也要產出報表（標示無資料），而不是整個失敗。
func TestScanOfflineWithEmptyCacheStillWritesReport(t *testing.T) {
	cfgPath, reportDir := writeConfig(t, `timezone = "Asia/Taipei"
log_file = ""

[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"
`)
	var out, errOut bytes.Buffer
	code := run([]string{"scan", "-c", cfgPath, "--offline"}, &out, &errOut)
	// fail_on 未設定 → 即使有發現也 exit 0；OSV 的 offline 未命中不算來源失敗
	if code != exitOK {
		t.Fatalf("exit code = %d，預期 0。stdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
	}

	for _, name := range []string{"latest.md", "latest.json"} {
		if _, err := os.Stat(filepath.Join(reportDir, name)); err != nil {
			t.Errorf("缺少 %s: %v", name, err)
		}
	}
	md, err := os.ReadFile(filepath.Join(reportDir, "latest.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "不等於沒有弱點") {
		t.Error("offline 未命中必須標示「無資料」而非「無弱點」")
	}
	if !strings.Contains(string(md), "requests") {
		t.Error("報表應列出未命中的對象")
	}
}

func TestScanWritesLogWithResultLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "logs", "vulnwatch.log")
	reportDir := filepath.Join(dir, "reports")
	cfgPath := filepath.Join(dir, "vulnwatch.toml")
	src := "[general]\n" +
		"report_dir = '" + reportDir + "'\n" +
		"cache_dir  = '" + filepath.Join(dir, "cache") + "'\n" +
		"log_file   = '" + logPath + "'\n" +
		`
[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"
`
	if err := os.WriteFile(cfgPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := run([]string{"scan", "-c", cfgPath, "--offline"}, &out, &errOut); code != exitOK {
		t.Fatalf("exit code = %d。stderr:\n%s", code, errOut.String())
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("應該寫出 log 檔: %v", err)
	}
	if !strings.Contains(string(raw), "RESULT:") {
		t.Errorf("log 必須含 RESULT 行（規劃 §8）：\n%s", raw)
	}
}
