package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elvis3434/vulnwatch/internal/model"
)

func sampleReport() *model.Report {
	return &model.Report{
		Tool:          "vulnwatch",
		ToolVersion:   "test",
		SchemaVersion: model.SchemaVersion,
		GeneratedAt:   time.Date(2026, 11, 3, 8, 30, 0, 0, time.UTC),
		Timezone:      "Asia/Taipei",
		ConfigPath:    `D:\vulnwatch\vulnwatch.toml`,
		MinSeverity:   "HIGH",
		Summary: model.Summary{
			Targets: 2, Packages: 2, TotalFindings: 3,
			ByLevel:      map[string]int{"CRITICAL": 1, "MEDIUM": 1, "UNKNOWN": 1},
			UnknownCount: 2, FilteredCount: 1, IgnoredCount: 1,
			AllSourcesOK: false,
		},
		Findings: []model.Finding{{
			Target:   model.Target{Kind: model.TargetKindPackage, Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1"},
			ID:       "GHSA-jfh8-c2jp-5v3q",
			Aliases:  []string{"CVE-2021-44228"},
			Summary:  "Remote code injection in Log4j",
			Severity: model.Severity{Level: model.LevelCritical, Score: 10.0, HasScore: true, Source: model.SevSourceCVSS31OSV, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", VectorType: "CVSS_V3"},
			Fix:      model.Fix{Kind: model.FixKindCandidates, Candidates: []string{"2.3.1", "2.12.2", "2.15.0"}, Note: "Maven 不做版本比較"},
			Source:   "OSV",
			New:      model.NewStateYes,
		}},
		Unknown: []model.Finding{{
			Target:   model.Target{Kind: model.TargetKindPackage, Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.20.0"},
			ID:       "GO-2024-2687",
			Aliases:  []string{"CVE-2023-45288"},
			Summary:  "HTTP/2 CONTINUATION flood",
			Severity: model.UnknownSeverity(),
			Fix:      model.Fix{Kind: model.FixKindFixed, Version: "0.23.0"},
			Source:   "OSV",
			New:      model.NewStateUndetermined,
		}, {
			Target:   model.Target{Kind: model.TargetKindLanguage, Ecosystem: model.EcosystemLanguage, Name: "go", Version: "1.27.3"},
			ID:       "GO-2026-5027",
			Summary:  "尚未修復的 stdlib 問題",
			Severity: model.UnknownSeverity(),
			Fix:      model.Fix{Kind: model.FixKindNone, Note: "目前版本所在的版本線尚無修正版本"},
			Source:   "OSV",
			New:      model.NewStateNo,
		}},
		Filtered: []model.Finding{{
			Target:   model.Target{Ecosystem: "PyPI", Name: "requests", Version: "2.31.0"},
			ID:       "GHSA-9hjg-9r4m-mvj7",
			Severity: model.Severity{Level: model.LevelMedium, Score: 5.3, HasScore: true, Source: model.SevSourceCVSS31OSV},
			Fix:      model.Fix{Kind: model.FixKindFixed, Version: "2.32.4"},
			Source:   "OSV",
		}},
		Ignored: []model.Finding{{
			Target:   model.Target{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.20.0"},
			ID:       "GO-2024-0000",
			Severity: model.UnknownSeverity(),
			Fix:      model.Fix{Kind: model.FixKindNone},
			Source:   "OSV",
			Ignore:   &model.IgnoreState{ID: "GO-2024-0000", Reason: "未使用受影響的函式", Expires: "2026-12-31"},
		}},
		Languages: []model.LanguageStatus{{
			Name: "go", Version: "1.27.3", ReleaseLine: "1.27",
			LatestInLine: "1.27.3", PatchesBehind: 0, PatchesBehindKnown: true,
			EOL: "no", Recommended: "1.27.3", VulnScanned: true,
		}},
		NoData: []model.NoDataItem{{
			Target: model.Target{Ecosystem: "PyPI", Name: "pydantic", Version: "2.5.0"},
			Source: "OSV",
			Reason: "--offline 且快取未命中，本次無法判斷是否有弱點",
		}},
		Sources: []model.SourceStatus{
			{Name: "OSV", Enabled: true, OK: true, Queries: 3},
			{Name: "NVD", Enabled: true, OK: false, Queries: 1, Errors: 1, Message: "速率限制"},
		},
		Problems: []model.Problem{
			{Level: model.ProblemError, Where: "PyPI/pydantic", Message: "OSV 查詢失敗"},
			{Level: model.ProblemWarning, Where: "vulnwatch.toml:7", Message: "設定檔警告"},
		},
		Baseline:    &model.BaselineInfo{Path: "2026-11-02_0830/report.json", GeneratedAt: "2026-11-02T08:30:00+08:00", AllSourcesOK: true},
		Limitations: []string{"各弱點資料庫的覆蓋範圍不同，本報表不保證弱點清單完整。"},
	}
}

func TestMarkdownHasAllRequiredSections(t *testing.T) {
	md := Markdown(sampleReport())

	// 規劃 §5 要求的區塊
	for _, want := range []string{
		"## 1. 摘要",
		"### 資料來源狀態",
		"## 2. 需處理清單",
		"## 3. 無嚴重度評級（UNKNOWN）",
		"## 4. 程式語言執行環境",
		"## 6. 已忽略項目",
		"## 7. 錯誤 / 警告",
		"## 8. 已知限制",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown 缺少區塊 %q", want)
		}
	}
}

func TestMarkdownUnknownBlockIsProminentAndExplained(t *testing.T) {
	md := Markdown(sampleReport())

	// UNKNOWN 區塊必須在「低於 min_severity」區塊之前（規劃 §5 第 3 點：不是次要區塊）
	iUnknown := strings.Index(md, "## 3. 無嚴重度評級")
	iFiltered := strings.Index(md, "## 5. 低於 min_severity")
	if iUnknown < 0 || iFiltered < 0 || iUnknown > iFiltered {
		t.Error("UNKNOWN 區塊必須放在醒目位置（在被濾掉的項目之前）")
	}
	if !strings.Contains(md, "不受 min_severity 影響") {
		t.Error("UNKNOWN 區塊必須說明不受 min_severity 影響")
	}
	if !strings.Contains(md, "GO-2024-2687") {
		t.Error("UNKNOWN 區塊必須列出 GO-* 項目")
	}
}

func TestMarkdownShowsSeveritySource(t *testing.T) {
	md := Markdown(sampleReport())
	// 規劃 §3.2：報表需標明嚴重度的來源，讓使用者知道分數可不可信
	if !strings.Contains(md, "CVSS3.1(OSV)") {
		t.Error("報表必須標明嚴重度來源 CVSS3.1(OSV)")
	}
	if !strings.Contains(md, "UNKNOWN (—)") {
		t.Error("無評級項目必須顯示來源為 —")
	}
}

func TestMarkdownShowsFixStates(t *testing.T) {
	md := Markdown(sampleReport())
	// 規劃 §3.3：三種狀態都要能表達
	if !strings.Contains(md, "未做版本比較") {
		t.Error("候選版本狀態必須標註未做版本比較")
	}
	if !strings.Contains(md, "0.23.0") {
		t.Error("確定值狀態必須顯示版本")
	}
	if !strings.Contains(md, "尚無修正版本") {
		t.Error("尚無修正版本狀態必須顯示")
	}
}

func TestMarkdownShowsNoDataNotNoVulns(t *testing.T) {
	md := Markdown(sampleReport())
	if !strings.Contains(md, "不等於沒有弱點") {
		t.Error("「無資料」區塊必須明確說明不等於沒有弱點（規劃 §2.2）")
	}
	if !strings.Contains(md, "pydantic") {
		t.Error("無資料的對象必須列出")
	}
}

func TestMarkdownShowsIncompleteWarning(t *testing.T) {
	md := Markdown(sampleReport())
	if !strings.Contains(md, "本次結果可能不完整") {
		t.Error("有來源失敗時，報表必須明確標示結果可能不完整（規劃 §5 第 7 點）")
	}
	if !strings.Contains(md, "速率限制") {
		t.Error("來源失敗的說明必須顯示")
	}
}

func TestMarkdownNewFlag(t *testing.T) {
	md := Markdown(sampleReport())
	if !strings.Contains(md, "**NEW**") {
		t.Error("本次新增的項目必須有 NEW 標記")
	}
	if !strings.Contains(md, "無法判定是否新增") {
		t.Error("無法判定是否新增的項目必須明確標示（規劃 §5.1）")
	}
}

func TestMarkdownEscapesPipes(t *testing.T) {
	rep := sampleReport()
	rep.Findings[0].Summary = "a | b | c"
	md := Markdown(rep)
	if strings.Contains(md, "| a | b | c |") {
		t.Error("摘要中的 | 必須轉義，否則會破壞 Markdown 表格")
	}
}

func TestMarkdownEmptyReport(t *testing.T) {
	rep := &model.Report{
		Tool: "vulnwatch", GeneratedAt: time.Now(),
		MinSeverity: "LOW",
		Summary:     model.Summary{ByLevel: map[string]int{}, AllSourcesOK: true},
		Findings:    []model.Finding{},
		Unknown:     []model.Finding{},
		Sources:     []model.SourceStatus{{Name: "OSV", Enabled: true, OK: true, Queries: 1}},
	}
	md := Markdown(rep)
	if !strings.Contains(md, "沒有達到 min_severity") {
		t.Error("無弱點時應該明確說明")
	}
	if !strings.Contains(md, "沒有無評級的弱點") {
		t.Error("UNKNOWN 區塊為空時也要有說明")
	}
	// 無弱點也要提醒看 UNKNOWN 區塊
	if !strings.Contains(md, "一併看第 3 節") {
		t.Error("需處理清單為空時應提醒檢視 UNKNOWN 區塊")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	rep := sampleReport()
	raw, err := MarshalJSON(rep)
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalJSON(raw)
	if err != nil {
		t.Fatalf("JSON 必須能讀回來做 NEW 判定: %v", err)
	}

	if back.SchemaVersion != model.SchemaVersion {
		t.Errorf("SchemaVersion = %d", back.SchemaVersion)
	}
	if len(back.Findings) != 1 || back.Findings[0].ID != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("Findings 未正確還原: %+v", back.Findings)
	}
	if back.Findings[0].Severity.Level != model.LevelCritical {
		t.Errorf("Severity.Level 未正確還原: %v", back.Findings[0].Severity.Level)
	}
	if len(back.Unknown) != 2 || back.Unknown[0].Severity.Level != model.LevelUnknown {
		t.Errorf("Unknown 未正確還原: %+v", back.Unknown)
	}
	// filtered_out 必須保留，否則調整 min_severity 後會誤判成 NEW
	if len(back.Filtered) != 1 {
		t.Error("JSON 必須保留 filtered_out")
	}
	if !back.HasSource("NVD") || back.SourceOK("NVD") {
		t.Error("來源狀態未正確還原（NEW 判定需要）")
	}
}

func TestJSONLevelNames(t *testing.T) {
	raw, err := MarshalJSON(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{`"level": "CRITICAL"`, `"level": "UNKNOWN"`, `"source": "CVSS3.1(OSV)"`} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON 缺少 %s", want)
		}
	}
}

func TestWriteCreatesTimestampDirAndLatest(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 11, 3, 8, 30, 0, 0, time.UTC)

	written, err := Write(sampleReport(), dir, []string{"md", "json"}, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 4 {
		t.Errorf("寫出 %d 個檔案，預期 4（report.md/json + latest.md/json）", len(written))
	}

	for _, rel := range []string{
		filepath.Join("2026-11-03_0830", "report.md"),
		filepath.Join("2026-11-03_0830", "report.json"),
		"latest.md",
		"latest.json",
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Errorf("缺少 %s: %v", rel, err)
		}
	}

	// latest.json 必須與當次的 report.json 相同
	a, _ := os.ReadFile(filepath.Join(dir, "2026-11-03_0830", "report.json"))
	b, _ := os.ReadFile(filepath.Join(dir, "latest.json"))
	if string(a) != string(b) {
		t.Error("latest.json 應該與當次報表相同")
	}
}

func TestWriteOnlyRequestedFormats(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	if _, err := Write(sampleReport(), dir, []string{"json"}, at); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "latest.md")); err == nil {
		t.Error("只要求 json 時不該寫出 md")
	}
}

// TestCleanupOnlyTouchesTimestampDirs 是規劃 §5.2 的要求：
// 絕不對整個 report_dir 做 glob 刪除（使用者可能在裡面放自己的東西）。
func TestCleanupOnlyTouchesTimestampDirs(t *testing.T) {
	dir := t.TempDir()

	stamps := []string{
		"2026-10-30_0830", "2026-10-31_0830", "2026-11-01_0830",
		"2026-11-02_0830", "2026-11-03_0830",
	}
	for _, s := range stamps {
		if err := os.MkdirAll(filepath.Join(dir, s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// 使用者自己的東西
	mustWrite(t, filepath.Join(dir, "latest.md"), "x")
	mustWrite(t, filepath.Join(dir, "latest.json"), "{}")
	mustWrite(t, filepath.Join(dir, "我的筆記.txt"), "重要")
	if err := os.MkdirAll(filepath.Join(dir, "archive"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "archive", "old.json"), "{}")
	if err := os.MkdirAll(filepath.Join(dir, "2026-11-03"), 0o755); err != nil {
		t.Fatal(err)
	}

	removed, err := Cleanup(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Fatalf("刪除 %v，預期 3 個最舊的報表目錄", removed)
	}

	// 最新兩份仍在
	for _, s := range []string{"2026-11-02_0830", "2026-11-03_0830"} {
		if _, err := os.Stat(filepath.Join(dir, s)); err != nil {
			t.Errorf("%s 應該保留", s)
		}
	}
	// 使用者的東西一個都不能動
	for _, p := range []string{"latest.md", "latest.json", "我的筆記.txt", "archive", "2026-11-03"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("不可刪除使用者的 %s: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "archive", "old.json")); err != nil {
		t.Error("archive 內的檔案不可被刪除")
	}
}

func TestCleanupKeepZeroDoesNothing(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "2026-11-01_0830"), 0o755); err != nil {
		t.Fatal(err)
	}
	removed, err := Cleanup(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Errorf("keep_reports = 0 應該不清理，但刪除了 %v", removed)
	}
}

func TestReportDirsSortedNewestFirst(t *testing.T) {
	dir := t.TempDir()
	for _, s := range []string{"2026-11-01_0830", "2026-11-03_0830", "2026-11-02_1200"} {
		if err := os.MkdirAll(filepath.Join(dir, s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(dir, "notadir"), "x")

	got, err := ReportDirs(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2026-11-03_0830", "2026-11-02_1200", "2026-11-01_0830"}
	if len(got) != len(want) {
		t.Fatalf("ReportDirs = %v，預期 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ReportDirs[%d] = %q，預期 %q", i, got[i], want[i])
		}
	}
}

func TestReportDirsMissingDir(t *testing.T) {
	got, err := ReportDirs(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("目錄不存在不該是錯誤: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ReportDirs = %v", got)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
