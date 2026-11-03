package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elvis3434/vulnwatch/internal/model"
)

func parseErrors(t *testing.T, src string) *Errors {
	t.Helper()
	_, err := Parse([]byte(src), "vulnwatch.toml")
	if err == nil {
		t.Fatal("預期有設定檔錯誤，但沒有")
	}
	var cerrs *Errors
	if !errors.As(err, &cerrs) {
		t.Fatalf("錯誤型別 = %T，預期 *config.Errors", err)
	}
	return cerrs
}

func mustParse(t *testing.T, src string) *Config {
	t.Helper()
	cfg, err := Parse([]byte(src), "vulnwatch.toml")
	if err != nil {
		t.Fatalf("設定檔不該有錯誤，但得到：%v", err)
	}
	return cfg
}

const minimalGeneral = `
[general]
report_dir = "/tmp/vw/reports"
cache_dir  = "/tmp/vw/cache"
`

// TestExampleConfigIsValid 驗證 repo 裡的 vulnwatch.example.toml 可以通過驗證。
func TestExampleConfigIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "vulnwatch.example.toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取範例設定檔失敗: %v", err)
	}
	cfg, err := Parse(raw, path)
	if err != nil {
		t.Fatalf("vulnwatch.example.toml 必須能通過驗證，但得到：\n%v", err)
	}

	// 對照規劃 §3.4 的範例內容
	if cfg.General.Timezone != "Asia/Taipei" {
		t.Errorf("timezone = %q，預期 Asia/Taipei", cfg.General.Timezone)
	}
	if cfg.Location == nil || cfg.Location.String() != "Asia/Taipei" {
		t.Errorf("時區未正確載入（需要 import _ \"time/tzdata\"）: %v", cfg.Location)
	}
	if cfg.General.FailOn != "" || cfg.FailOnSet {
		t.Errorf("fail_on 預設必須是空字串（規劃 §3.4 / §8），目前 %q", cfg.General.FailOn)
	}
	if len(cfg.Formats) != 2 || cfg.Formats[0] != "md" || cfg.Formats[1] != "json" {
		t.Errorf("report_formats = %v，預期 [md json]", cfg.Formats)
	}
	if cfg.General.KeepReports != 30 {
		t.Errorf("keep_reports = %d，預期 30", cfg.General.KeepReports)
	}
	if cfg.MinLevel != model.LevelLow {
		t.Errorf("min_severity = %v，預期 LOW", cfg.MinLevel)
	}
	if cfg.HTTPTimeoutD != 30*time.Second {
		t.Errorf("http_timeout = %v，預期 30s", cfg.HTTPTimeoutD)
	}
	if cfg.CacheTTLD != 12*time.Hour {
		t.Errorf("cache_ttl = %v，預期 12h", cfg.CacheTTLD)
	}
	if len(cfg.Languages) != 3 {
		t.Errorf("languages 數量 = %d，預期 3", len(cfg.Languages))
	}
	if len(cfg.Packages) != 4 {
		t.Errorf("packages 數量 = %d，預期 4", len(cfg.Packages))
	}

	// purl 應該已經被展開成 ecosystem + name + version
	last := cfg.Packages[3]
	if last.Ecosystem != model.EcosystemGo || last.Name != "golang.org/x/net" || last.Version != "v0.20.0" {
		t.Errorf("purl 展開結果 = %+v，預期 Go/golang.org/x/net@v0.20.0", last)
	}

	// ignore 的三個字串欄位（規劃 §3.4）
	if len(cfg.Ignore) != 1 {
		t.Fatalf("ignore 數量 = %d，預期 1", len(cfg.Ignore))
	}
	ig := cfg.Ignore[0]
	if ig.ID != "GO-2024-0000" || ig.Ecosystem != "Go" ||
		ig.Name != "golang.org/x/net" || ig.Expires != "2026-12-31" {
		t.Errorf("ignore = %+v，與規劃 §3.4 的範例不符", ig)
	}
	if _, err := ig.ExpiresTime(); err != nil {
		t.Errorf("expires 應該能被程式自行 parse: %v", err)
	}

	// [sources] 預設全部啟用
	if !cfg.Sources.OSV || !cfg.Sources.NVD || !cfg.Sources.EOL {
		t.Errorf("sources = %+v，範例中應全部啟用", cfg.Sources)
	}
}

// TestUnknownEcosystemReportsLine 是驗收標準第一條：
// check 必須指出錯誤的具體欄位與行號（規劃 §9）。
func TestUnknownEcosystemReportsLine(t *testing.T) {
	src := minimalGeneral + `
[[packages]]
ecosystem = "Golang"
name      = "github.com/gin-gonic/gin"
version   = "v1.9.1"
`
	cerrs := parseErrors(t, src)
	if len(cerrs.Diags) != 1 {
		t.Fatalf("錯誤數量 = %d，預期 1：\n%v", len(cerrs.Diags), cerrs)
	}
	d := cerrs.Diags[0]
	if d.Line != 7 {
		t.Errorf("行號 = %d，預期 7（ecosystem = \"Golang\" 那一行）", d.Line)
	}
	if d.Field != "packages.ecosystem" {
		t.Errorf("欄位 = %q，預期 packages.ecosystem", d.Field)
	}
	if !strings.Contains(d.Msg, "Golang") || !strings.Contains(d.Msg, "Go") {
		t.Errorf("訊息應該指出錯誤的值與支援清單：%q", d.Msg)
	}
	if !strings.Contains(d.String(), "vulnwatch.toml:7") {
		t.Errorf("String() = %q，應該含 檔名:行號", d.String())
	}
}

func TestInvalidMinSeverityReportsLine(t *testing.T) {
	src := `
[general]
report_dir   = "/tmp/vw/reports"
cache_dir    = "/tmp/vw/cache"
min_severity = "UNKNOWN"

[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"
`
	cerrs := parseErrors(t, src)
	d := cerrs.Diags[0]
	if d.Line != 5 {
		t.Errorf("行號 = %d，預期 5", d.Line)
	}
	if d.Field != "general.min_severity" {
		t.Errorf("欄位 = %q", d.Field)
	}
	// 規劃 §3.4：min_severity / fail_on 不接受 UNKNOWN
	if !strings.Contains(d.Msg, "UNKNOWN") {
		t.Errorf("訊息應該說明不接受 UNKNOWN：%q", d.Msg)
	}
}

func TestInvalidFailOnReportsLine(t *testing.T) {
	src := minimalGeneral + `fail_on = "SEVERE"

[[packages]]
ecosystem = "PyPI"
name      = "requests"
`
	cerrs := parseErrors(t, src)
	if cerrs.Diags[0].Field != "general.fail_on" || cerrs.Diags[0].Line != 5 {
		t.Errorf("診斷 = %+v，預期 general.fail_on 第 5 行", cerrs.Diags[0])
	}
}

func TestIgnoreMissingIDAndBadExpires(t *testing.T) {
	src := minimalGeneral + `
[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"

[[ignore]]
reason = "沒有 id"

[[ignore]]
id      = "CVE-2024-0001"
expires = "2026/12/31"
`
	cerrs := parseErrors(t, src)
	if len(cerrs.Diags) != 2 {
		t.Fatalf("錯誤數量 = %d，預期 2：\n%v", len(cerrs.Diags), cerrs)
	}
	if cerrs.Diags[0].Field != "ignore.id" {
		t.Errorf("第 1 個錯誤 = %+v，預期 ignore.id", cerrs.Diags[0])
	}
	if cerrs.Diags[1].Field != "ignore.expires" || cerrs.Diags[1].Line != 16 {
		t.Errorf("第 2 個錯誤 = %+v，預期 ignore.expires 第 16 行", cerrs.Diags[1])
	}
}

func TestUnsupportedLanguageReportsLine(t *testing.T) {
	src := minimalGeneral + `
[[languages]]
name    = "cobol"
version = "1.0"
`
	cerrs := parseErrors(t, src)
	d := cerrs.Diags[0]
	if d.Field != "languages.name" || d.Line != 7 {
		t.Errorf("診斷 = %+v，預期 languages.name 第 7 行", d)
	}
	for _, want := range []string{"go", "python", "rust"} {
		if !strings.Contains(d.Msg, want) {
			t.Errorf("訊息應該列出支援的語言 %q：%q", want, d.Msg)
		}
	}
}

func TestUnknownFieldIsReported(t *testing.T) {
	// 拼錯的設定項目不可被靜默忽略。
	src := `
[general]
report_dir   = "/tmp/vw/reports"
cache_dir    = "/tmp/vw/cache"
min_severty  = "HIGH"

[[packages]]
ecosystem = "PyPI"
name      = "requests"
`
	cerrs := parseErrors(t, src)
	found := false
	for _, d := range cerrs.Diags {
		if strings.Contains(d.Field, "min_severty") {
			found = true
			if d.Line != 5 {
				t.Errorf("行號 = %d，預期 5", d.Line)
			}
		}
	}
	if !found {
		t.Errorf("應該指出拼錯的 min_severty：\n%v", cerrs)
	}
}

func TestTOMLSyntaxErrorHasLine(t *testing.T) {
	src := `
[general]
report_dir = "/tmp/vw/reports
cache_dir  = "/tmp/vw/cache"
`
	cerrs := parseErrors(t, src)
	if cerrs.Diags[0].Line == 0 {
		t.Errorf("TOML 格式錯誤必須帶行號：%+v", cerrs.Diags[0])
	}
}

func TestMissingReportDirAndCacheDir(t *testing.T) {
	src := `
[general]
timezone = "Asia/Taipei"

[[packages]]
ecosystem = "PyPI"
name      = "requests"
`
	cerrs := parseErrors(t, src)
	fields := map[string]bool{}
	for _, d := range cerrs.Diags {
		fields[d.Field] = true
	}
	if !fields["general.report_dir"] || !fields["general.cache_dir"] {
		t.Errorf("report_dir / cache_dir 必填：\n%v", cerrs)
	}
}

func TestBadTimezoneReportsLine(t *testing.T) {
	src := `
[general]
report_dir = "/tmp/vw/reports"
cache_dir  = "/tmp/vw/cache"
timezone   = "Mars/Olympus_Mons"

[[packages]]
ecosystem = "PyPI"
name      = "requests"
`
	cerrs := parseErrors(t, src)
	if cerrs.Diags[0].Field != "general.timezone" || cerrs.Diags[0].Line != 5 {
		t.Errorf("診斷 = %+v，預期 general.timezone 第 5 行", cerrs.Diags[0])
	}
}

func TestAsiaTaipeiLoadsWithEmbeddedTZData(t *testing.T) {
	// 這是規劃 §6 / §9 的驗收項目：Windows 沒有系統 tzdata，
	// 靠 cmd/vulnwatch 的 import _ "time/tzdata" 才能載入。
	src := minimalGeneral + `timezone = "Asia/Taipei"

[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"
`
	cfg := mustParse(t, src)
	if cfg.Location.String() != "Asia/Taipei" {
		t.Fatalf("時區 = %v，預期 Asia/Taipei", cfg.Location)
	}
}

func TestHTMLFormatProducesWarning(t *testing.T) {
	// 規劃 §3.4：尚未支援的格式 → 明確 warning，不可靜默忽略。
	src := minimalGeneral + `report_formats = ["md", "html", "pdf"]

[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"
`
	cfg := mustParse(t, src)
	if len(cfg.Formats) != 1 || cfg.Formats[0] != "md" {
		t.Errorf("Formats = %v，預期只有 md", cfg.Formats)
	}
	var sawHTML, sawPDF bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w.Msg, "html") {
			sawHTML = true
		}
		if strings.Contains(w.Msg, "pdf") {
			sawPDF = true
		}
	}
	if !sawHTML || !sawPDF {
		t.Errorf("應該對 html 與 pdf 都發出警告：%+v", cfg.Warnings)
	}
}

func TestGoVersionPrefixWarningAndFix(t *testing.T) {
	src := minimalGeneral + `
[[packages]]
ecosystem = "Go"
name      = "github.com/gin-gonic/gin"
version   = "1.9.1"
`
	cfg := mustParse(t, src)
	if cfg.Packages[0].Version != "v1.9.1" {
		t.Errorf("Go 版本 = %q，預期自動補上 v 前綴", cfg.Packages[0].Version)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("自動補 v 前綴時應該發出警告")
	}
}

func TestBadPyPIVersionReportsLine(t *testing.T) {
	src := minimalGeneral + `
[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "latest"
`
	cerrs := parseErrors(t, src)
	if cerrs.Diags[0].Field != "packages.version" || cerrs.Diags[0].Line != 9 {
		t.Errorf("診斷 = %+v，預期 packages.version 第 9 行", cerrs.Diags[0])
	}
}

func TestPurlAndEcosystemConflict(t *testing.T) {
	src := minimalGeneral + `
[[packages]]
ecosystem = "Go"
name      = "golang.org/x/net"
purl      = "pkg:golang/golang.org/x/net@v0.20.0"
`
	cerrs := parseErrors(t, src)
	if cerrs.Diags[0].Field != "packages.purl" {
		t.Errorf("診斷 = %+v，預期 packages.purl", cerrs.Diags[0])
	}
}

func TestNoTargetsIsError(t *testing.T) {
	cerrs := parseErrors(t, minimalGeneral)
	if !strings.Contains(cerrs.Error(), "packages") {
		t.Errorf("沒有任何掃描對象時應該報錯：\n%v", cerrs)
	}
}

func TestMissingVersionWarns(t *testing.T) {
	src := minimalGeneral + `
[[packages]]
ecosystem = "PyPI"
name      = "requests"
`
	cfg := mustParse(t, src)
	if len(cfg.Warnings) == 0 {
		t.Fatal("未指定版本應該發出警告（規劃 §3.1）")
	}
	if !strings.Contains(cfg.Warnings[0].Msg, "無法判定") {
		t.Errorf("警告內容 = %q，應說明無法判定是否受影響", cfg.Warnings[0].Msg)
	}
}

func TestMavenWarnsAboutNoVersionCompare(t *testing.T) {
	src := minimalGeneral + `
[[packages]]
ecosystem = "Maven"
name      = "org.apache.logging.log4j:log4j-core"
version   = "2.14.1"
`
	cfg := mustParse(t, src)
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w.Msg, "不做版本比較") {
			found = true
		}
	}
	if !found {
		t.Errorf("Maven 應該警告不做版本比較（規劃 §3.3）：%+v", cfg.Warnings)
	}
}

func TestManifestsWarnPhase3(t *testing.T) {
	src := minimalGeneral + `
[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"

[[manifests]]
path = "/src/go.mod"
`
	cfg := mustParse(t, src)
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w.Msg, "Phase 3") {
			found = true
		}
	}
	if !found {
		t.Errorf("manifests 應該警告是 Phase 3 功能：%+v", cfg.Warnings)
	}
}

func TestIgnoreExpired(t *testing.T) {
	ig := Ignore{ID: "CVE-2024-1", Expires: "2026-12-31"}
	if ig.Expired(time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC)) {
		t.Error("expires 當天應該仍然有效")
	}
	if !ig.Expired(time.Date(2027, 1, 1, 0, 0, 1, 0, time.UTC)) {
		t.Error("隔天應該已到期")
	}
	noExpiry := Ignore{ID: "CVE-2024-2"}
	if noExpiry.Expired(time.Now()) {
		t.Error("沒有 expires 不該被視為到期")
	}
}

func TestIgnoreMatches(t *testing.T) {
	// 省略 ecosystem / name = 對所有套件忽略此 ID（規劃 §3.4）
	global := Ignore{ID: "CVE-2024-1"}
	if !global.Matches("Go", "golang.org/x/net", "CVE-2024-1", nil) {
		t.Error("全域忽略應該命中")
	}
	// 指定套件
	scoped := Ignore{ID: "GO-2024-0000", Ecosystem: "Go", Name: "golang.org/x/net"}
	if !scoped.Matches("Go", "golang.org/x/net", "GO-2024-0000", nil) {
		t.Error("指定套件的忽略應該命中")
	}
	if scoped.Matches("Go", "golang.org/x/text", "GO-2024-0000", nil) {
		t.Error("不同套件不該命中")
	}
	// 以 alias 命中（使用者填 CVE，OSV 主 ID 是 GHSA）
	aliased := Ignore{ID: "CVE-2024-37891"}
	if !aliased.Matches("PyPI", "urllib3", "GHSA-34jh-p97f-mpxf", []string{"CVE-2024-37891"}) {
		t.Error("應該能用 alias CVE 命中")
	}
	// PyPI 名稱經過 PEP 503 正規化
	pypi := Ignore{ID: "CVE-1", Ecosystem: "PyPI", Name: "Zope.Interface"}
	if !pypi.Matches("PyPI", "zope-interface", "CVE-1", nil) {
		t.Error("PyPI 名稱應該正規化後比較")
	}
}

func TestParsePurl(t *testing.T) {
	cases := []struct {
		in                 string
		eco, name, version string
	}{
		{"pkg:golang/golang.org/x/net@v0.20.0", model.EcosystemGo, "golang.org/x/net", "v0.20.0"},
		{"pkg:golang/github.com%2Fgin-gonic%2Fgin@v1.9.1", model.EcosystemGo, "github.com/gin-gonic/gin", "v1.9.1"},
		{"pkg:pypi/requests@2.31.0", model.EcosystemPyPI, "requests", "2.31.0"},
		{"pkg:cargo/tokio@1.38.0", model.EcosystemCrates, "tokio", "1.38.0"},
		{"pkg:npm/lodash@4.17.21", model.EcosystemNPM, "lodash", "4.17.21"},
		{"pkg:npm/%40angular/core@17.0.0", model.EcosystemNPM, "@angular/core", "17.0.0"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", model.EcosystemMaven, "org.apache.logging.log4j:log4j-core", "2.14.1"},
		{"pkg:nuget/Newtonsoft.Json@13.0.1", model.EcosystemNuGet, "Newtonsoft.Json", "13.0.1"},
		{"pkg:pypi/requests", model.EcosystemPyPI, "requests", ""},
		{"pkg:pypi/requests@2.31.0?arch=any#sub", model.EcosystemPyPI, "requests", "2.31.0"},
	}
	for _, c := range cases {
		eco, name, ver, err := ParsePurl(c.in)
		if err != nil {
			t.Errorf("ParsePurl(%q) 錯誤: %v", c.in, err)
			continue
		}
		if eco != c.eco || name != c.name || ver != c.version {
			t.Errorf("ParsePurl(%q) = %q, %q, %q；預期 %q, %q, %q",
				c.in, eco, name, ver, c.eco, c.name, c.version)
		}
	}

	for _, bad := range []string{"", "golang/x@v1", "pkg:unknown/x@1.0", "pkg:pypi", "pkg:maven/onlyone@1.0"} {
		if _, _, _, err := ParsePurl(bad); err == nil {
			t.Errorf("ParsePurl(%q) 應該回傳錯誤", bad)
		}
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.toml")); err == nil {
		t.Fatal("檔案不存在應該回傳錯誤")
	}
}

func TestLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "vulnwatch.toml")
	src := minimalGeneral + `
[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"
`
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if cfg.Path != p {
		t.Errorf("Path = %q，預期 %q", cfg.Path, p)
	}
	targets := cfg.Targets()
	if len(targets) != 1 || targets[0].Name != "requests" {
		t.Errorf("Targets = %+v", targets)
	}
	if targets[0].Kind != model.TargetKindPackage {
		t.Errorf("Target.Kind = %q", targets[0].Kind)
	}
}

func TestRelativePathWarns(t *testing.T) {
	src := `
[general]
report_dir = "reports"
cache_dir  = "cache"

[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"
`
	cfg := mustParse(t, src)
	n := 0
	for _, w := range cfg.Warnings {
		if strings.Contains(w.Msg, "絕對路徑") {
			n++
		}
	}
	if n < 2 {
		t.Errorf("report_dir 與 cache_dir 都應該警告相對路徑（規劃 §8）：%+v", cfg.Warnings)
	}
}

// TestLanguageVersionShapeValidation 是回歸測試：
// 版本線與 patch 落後數都是從 [[languages]].version 算出來的，
// 所以 1.x 這種寫法必須報錯，不可默默接受。
func TestLanguageVersionShapeValidation(t *testing.T) {
	good := []string{"1.27.3", "3.12.7", "1.82.0", "1.82", "1.27.3-rc1", "v1.27.3", "2"}
	for _, v := range good {
		if !looksLikeDottedVersion(v) {
			t.Errorf("looksLikeDottedVersion(%q) = false，預期 true", v)
		}
	}
	bad := []string{"", "latest", "1.x", "1.", ".1", "abc", "1.latest", "go1.27"}
	for _, v := range bad {
		if looksLikeDottedVersion(v) {
			t.Errorf("looksLikeDottedVersion(%q) = true，預期 false", v)
		}
	}
}

func TestBadLanguageVersionReportsLine(t *testing.T) {
	src := minimalGeneral + `
[[languages]]
name    = "go"
version = "1.x"
`
	cerrs := parseErrors(t, src)
	d := cerrs.Diags[0]
	if d.Field != "languages.version" || d.Line != 8 {
		t.Errorf("診斷 = %+v，預期 languages.version 第 8 行", d)
	}
}

func TestDiagLocationSeparatesPositionFromMessage(t *testing.T) {
	d := Diag{Path: "vulnwatch.toml", Line: 7, Field: "packages.ecosystem", Msg: "不支援的生態系"}
	if got := d.Location(); got != "vulnwatch.toml:7 packages.ecosystem" {
		t.Errorf("Location() = %q", got)
	}
	if got := d.String(); got != "vulnwatch.toml:7: packages.ecosystem: 不支援的生態系" {
		t.Errorf("String() = %q", got)
	}
	// 沒有行號 / 欄位時也要可讀
	if got := (Diag{Msg: "x"}).Location(); got != "設定檔" {
		t.Errorf("Location() = %q", got)
	}
}
