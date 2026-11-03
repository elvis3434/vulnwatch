package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elvis3434/vulnwatch/internal/httpx"
	"github.com/elvis3434/vulnwatch/internal/model"
	"github.com/elvis3434/vulnwatch/internal/report"
)

func langStatus(rep *model.Report, name string) *model.LanguageStatus {
	for i := range rep.Languages {
		if rep.Languages[i].Name == name {
			return &rep.Languages[i]
		}
	}
	return nil
}

// TestGoRuntimeScansStdlibAndToolchain 驗證規劃 §4.1：
// go 執行環境要查 OSV 的 stdlib 與 toolchain 兩個 package，版本加 v 前綴。
func TestGoRuntimeScansStdlibAndToolchain(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = false

[[languages]]
name    = "go"
version = "1.21.0"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	// 兩個 package 的弱點都要出現，且都在 UNKNOWN 區塊（GO-* 沒有 CVSS）
	for _, id := range []string{"GO-2024-2600", "GO-2024-2611"} {
		f := findFinding(rep.Unknown, id)
		if f == nil {
			t.Fatalf("UNKNOWN 區塊缺少 %s；Unknown=%d", id, len(rep.Unknown))
		}
		if f.Target.Kind != model.TargetKindLanguage {
			t.Errorf("%s 的 target.kind = %q，預期 language", id, f.Target.Kind)
		}
		if f.Target.Version != "v1.21.0" {
			t.Errorf("%s 查詢用的版本 = %q，預期帶 v 前綴（規劃 §4.1）", id, f.Target.Version)
		}
	}

	if f := findFinding(rep.Unknown, "GO-2024-2600"); f.Target.Name != "stdlib" {
		t.Errorf("GO-2024-2600 應來自 stdlib，實際 %q", f.Target.Name)
	}
	if f := findFinding(rep.Unknown, "GO-2024-2611"); f.Target.Name != "toolchain" {
		t.Errorf("GO-2024-2611 應來自 toolchain，實際 %q", f.Target.Name)
	}

	// 修正版本要挑對版本線
	if f := findFinding(rep.Unknown, "GO-2024-2600"); f.Fix.Version != "1.21.8" {
		t.Errorf("stdlib@v1.21.0 的修正版本 = %q，預期 1.21.8", f.Fix.Version)
	}
}

// TestEOLStatusForGo 驗證 endoflife.date v1 的解析（規劃 §5 第 4 點）。
func TestEOLStatusForGo(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = false

[[languages]]
name    = "go"
version = "1.27.3"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	st := langStatus(rep, "go")
	if st == nil {
		t.Fatal("報表缺少 go 的語言狀態")
	}
	if st.ReleaseLine != "1.27" {
		t.Errorf("版本線 = %q，預期 1.27", st.ReleaseLine)
	}
	if st.LatestInLine != "1.27.3" {
		t.Errorf("該版本線最新 = %q，預期 1.27.3", st.LatestInLine)
	}
	if !st.PatchesBehindKnown || st.PatchesBehind != 0 {
		t.Errorf("落後 patch = %d (known=%v)，預期 0", st.PatchesBehind, st.PatchesBehindKnown)
	}
	if st.EOL != "no" {
		t.Errorf("EOL = %q，預期 no", st.EOL)
	}
	if !strings.Contains(st.Note, "最新修補版") {
		t.Errorf("說明 = %q，預期指出已是最新修補版", st.Note)
	}
	if !st.VulnScanned {
		t.Error("go 這個階段應該有掃弱點清單")
	}
}

// TestEOLStatusDetectsEndOfLife 驗證已 EOL 的版本線（規劃 §11：go 1.25 已 EOL）。
func TestEOLStatusDetectsEndOfLife(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = false

[[languages]]
name    = "go"
version = "1.25.4"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	st := langStatus(rep, "go")
	if st.EOL != "yes" {
		t.Fatalf("EOL = %q，預期 yes（go 1.25 已 EOL）", st.EOL)
	}
	if st.EOLFrom != "2026-08-19" {
		t.Errorf("EOLFrom = %q，預期 2026-08-19", st.EOLFrom)
	}
	// 已 EOL → 建議升到最新一個還在維護的版本線
	if st.Recommended != "1.27.3" {
		t.Errorf("建議版本 = %q，預期 1.27.3", st.Recommended)
	}
	if st.PatchesBehind != 8 {
		t.Errorf("落後 patch = %d，預期 8（1.25.4 → 1.25.12）", st.PatchesBehind)
	}
}

// TestEOLUnknownReleaseLineWarns 驗證版本線查不到時不猜，並留警告。
func TestEOLUnknownReleaseLineWarns(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = false

[[languages]]
name    = "go"
version = "1.19.5"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	st := langStatus(rep, "go")
	if st.EOL != "unknown" {
		t.Errorf("EOL = %q，預期 unknown", st.EOL)
	}
	if st.PatchesBehindKnown {
		t.Error("查不到版本線時不該給出落後 patch 數")
	}
	found := false
	for _, p := range rep.Problems {
		if strings.Contains(p.Message, "1.19") {
			found = true
		}
	}
	if !found {
		t.Errorf("查不到版本線應該留警告：%+v", rep.Problems)
	}
}

// TestPythonRustEOLOnlyNoVulnScan 驗證 python / rust 這個階段只輸出 EOL 狀態
// （規劃 §4.2 / §4.3：弱點清單是 Phase 2）。
func TestPythonRustEOLOnlyNoVulnScan(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = false

[[languages]]
name    = "python"
version = "3.12.7"

[[languages]]
name    = "rust"
version = "1.82.0"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	py := langStatus(rep, "python")
	if py == nil {
		t.Fatal("報表缺少 python 的語言狀態")
	}
	if py.LatestInLine != "3.12.12" {
		t.Errorf("python 3.12 的最新 = %q，預期 3.12.12", py.LatestInLine)
	}
	if py.PatchesBehind != 5 {
		t.Errorf("python 落後 patch = %d，預期 5（3.12.7 → 3.12.12）", py.PatchesBehind)
	}
	if py.VulnScanned {
		t.Error("python 的弱點清單是 Phase 2，不該標記為已掃描")
	}

	rs := langStatus(rep, "rust")
	if rs == nil {
		t.Fatal("報表缺少 rust 的語言狀態")
	}
	// rust 1.82 未 EOL 但已不再維護
	if rs.EOL != "no" {
		t.Errorf("rust EOL = %q，預期 no", rs.EOL)
	}
	if rs.Recommended != "1.90.0" {
		t.Errorf("rust 建議版本 = %q，預期 1.90.0", rs.Recommended)
	}
	if rs.VulnScanned {
		t.Error("rust 的弱點清單是 Phase 2，不該標記為已掃描")
	}

	// 兩者都不該產生弱點項目（沒有對它們打 OSV）
	for _, f := range rep.AllFindings() {
		if f.Target.Kind == model.TargetKindLanguage &&
			(f.Target.Note == "python 執行環境" || f.Target.Note == "rust 執行環境") {
			t.Errorf("這個階段不該為 %s 產生弱點項目：%s", f.Target.Note, f.ID)
		}
	}

	// 報表的已知限制與警告都要說明
	for _, want := range []string{"python", "rust"} {
		found := false
		for _, l := range rep.Limitations {
			if strings.HasPrefix(l, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("已知限制應說明 %s 的弱點清單是 Phase 2：%v", want, rep.Limitations)
		}
	}
}

// TestNVDFillsSeverityForGoAdvisory 驗證規劃 §3.2 的第 3 層回退：
// 用 aliases 中的 CVE 向 NVD 補分數。
func TestNVDFillsSeverityForGoAdvisory(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = true

[[packages]]
ecosystem = "Go"
name      = "golang.org/x/net"
version   = "v0.20.0"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	// GO-2024-2687 的 alias 是 CVE-2023-45288，NVD 給 7.5 / HIGH
	f := findFinding(rep.Findings, "GO-2024-2687")
	if f == nil {
		t.Fatalf("補上分數後應該進需處理清單；Findings=%d Unknown=%d",
			len(rep.Findings), len(rep.Unknown))
	}
	if f.Severity.Source != model.SevSourceNVD {
		t.Errorf("Severity.Source = %q，預期 %q", f.Severity.Source, model.SevSourceNVD)
	}
	if !f.Severity.HasScore || f.Severity.Score != 7.5 {
		t.Errorf("Severity.Score = %.1f (has=%v)，預期 7.5", f.Severity.Score, f.Severity.HasScore)
	}
	if f.Severity.Level != model.LevelHigh {
		t.Errorf("Severity.Level = %v，預期 HIGH", f.Severity.Level)
	}

	// 已經不在 UNKNOWN 區塊（這是回退鏈的設計本意，見 docs/decisions.md §8）
	if findFinding(rep.Unknown, "GO-2024-2687") != nil {
		t.Error("補上分數後不該還留在 UNKNOWN 區塊")
	}

	// 報表必須提醒 NVD 欄位路徑未經驗證
	found := false
	for _, l := range rep.Limitations {
		if strings.Contains(l, "NVD") {
			found = true
		}
	}
	if !found {
		t.Errorf("已知限制應提醒 NVD 欄位路徑未驗證：%v", rep.Limitations)
	}
}

// TestNVDCachedOnSecondRun 驗證 NVD 查詢用長效快取（規劃 §2.2），
// 第二次執行不會再打 NVD。
func TestNVDCachedOnSecondRun(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = true

[[packages]]
ecosystem = "Go"
name      = "golang.org/x/net"
version   = "v0.20.0"
`
	h := newHarness(t, src, nil)
	h.run(t)
	if n := countNVDRequests(h.api.Paths()); n != 1 {
		t.Fatalf("第一次執行的 NVD 請求數 = %d，預期 1", n)
	}

	// 第二次：換新的 client 但共用快取目錄
	h.api.ResetHits()
	h.api.ResetPaths()
	h.http = mustHTTP(t, h.cacheDir, nil)
	rep := h.run(t)

	if n := countNVDRequests(h.api.Paths()); n != 0 {
		t.Errorf("第二次執行的 NVD 請求數 = %d，預期 0（長效快取應命中）", n)
	}
	// 分數仍然要補上
	if f := findFinding(rep.Findings, "GO-2024-2687"); f == nil || f.Severity.Score != 7.5 {
		t.Errorf("用快取也必須補上相同的分數：%+v", f)
	}
}

// TestNVDBudgetLimit 驗證 NVD 查詢的次數上限（規劃 §3.2「額度允許時做」）。
func TestNVDBudgetLimit(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = true

[[languages]]
name    = "go"
version = "1.21.0"

[[packages]]
purl = "pkg:golang/golang.org/x/net@v0.20.0"
`
	h := newHarness(t, src, nil)
	rep, err := runWithBudget(h, 1)
	if err != nil {
		t.Fatal(err)
	}

	// 三筆 GO-* 共三個 CVE alias，但只允許查 1 筆
	nvdQueries := 0
	for _, s := range rep.Sources {
		if s.Name == NVDSourceName {
			nvdQueries = s.Queries
			if !strings.Contains(s.Message, "上限") {
				t.Errorf("NVD 來源說明 = %q，應說明已達上限", s.Message)
			}
		}
	}
	if nvdQueries != 1 {
		t.Errorf("NVD 查詢數 = %d，預期 1（受上限限制）", nvdQueries)
	}

	// 超過上限的項目必須維持 UNKNOWN，並在警告區留痕
	if len(rep.Unknown) == 0 {
		t.Error("超過上限的項目應維持 UNKNOWN")
	}
	found := false
	for _, p := range rep.Problems {
		if strings.Contains(p.Message, "上限") {
			found = true
		}
	}
	if !found {
		t.Errorf("達到上限必須在警告區留痕：%+v", rep.Problems)
	}
}

// TestNVDMissingMetricsKeepsUnknown 驗證 NVD 回應沒有 CVSS 欄位時的容錯：
// 項目維持 UNKNOWN 並留警告，不可靜默失敗（docs/decisions.md §6）。
func TestNVDMissingMetricsKeepsUnknown(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = true

[[languages]]
name    = "go"
version = "1.21.0"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	// GO-2024-2611 的 alias 是 CVE-2024-24783，testdata/nvd 沒有這個檔案，
	// 假伺服器會回 totalResults = 0 的空回應。
	f := findFinding(rep.Unknown, "GO-2024-2611")
	if f == nil {
		t.Fatalf("NVD 查不到分數時，項目必須維持在 UNKNOWN 區塊；Unknown=%d", len(rep.Unknown))
	}
	found := false
	for _, p := range rep.Problems {
		if strings.Contains(p.Where, "CVE-2024-24783") && strings.Contains(p.Message, "沒有這筆 CVE 的 CVSS") {
			found = true
		}
	}
	if !found {
		t.Errorf("找不到 CVSS 欄位必須留警告：%+v", rep.Problems)
	}

	// 但「NVD 沒有這筆 CVE 的 CVSS 資料」是資料缺口，不是來源失敗 ——
	// 否則 AllSourcesOK 幾乎永遠是 false，§5.1 的基準就永遠選不到。
	for _, s := range rep.Sources {
		if s.Name == NVDSourceName && !s.OK {
			t.Errorf("NVD 的資料缺口不該讓來源狀態變成失敗：%+v", s)
		}
	}
}

// TestNVDTransportErrorIsSourceFailure 驗證真正的 HTTP 失敗仍會標記來源失敗。
func TestNVDTransportErrorIsSourceFailure(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = true

[[packages]]
ecosystem = "Go"
name      = "golang.org/x/net"
version   = "v0.20.0"
`
	h := newHarness(t, src, func(o *httpx.Options) { o.MaxRetries = 1 })
	h.api.failNVD = true
	rep := h.run(t)

	var st *model.SourceStatus
	for i := range rep.Sources {
		if rep.Sources[i].Name == NVDSourceName {
			st = &rep.Sources[i]
		}
	}
	if st == nil || st.OK {
		t.Fatalf("NVD 的 HTTP 失敗應標記來源失敗：%+v", st)
	}
	if rep.Summary.AllSourcesOK {
		t.Error("有來源失敗時 AllSourcesOK 應為 false")
	}
	// 項目維持 UNKNOWN，不可消失
	if findFinding(rep.Unknown, "GO-2024-2687") == nil {
		t.Error("NVD 失敗時項目必須維持在 UNKNOWN 區塊")
	}
}

// TestNewFlagFirstRunIsUndetermined 驗證首次執行沒有基準時的行為（§5.1）。
func TestNewFlagFirstRunIsUndetermined(t *testing.T) {
	dir := t.TempDir()
	h := newHarnessWithReportDir(t, dir, `
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
version   = "1.26.5"
`)
	rep := h.run(t)

	for _, f := range rep.AllFindings() {
		if f.New != model.NewStateUndetermined {
			t.Errorf("%s 的 NEW = %q，首次執行應為 undetermined", f.ID, f.New)
		}
	}
	if rep.Baseline == nil || !strings.Contains(rep.Baseline.Note, "首次執行") {
		t.Errorf("Baseline = %+v，應說明首次執行", rep.Baseline)
	}
	if rep.Summary.NewUndetermined != len(rep.AllFindings()) {
		t.Errorf("Summary.NewUndetermined = %d，預期 %d", rep.Summary.NewUndetermined, len(rep.AllFindings()))
	}
}

// TestNewFlagSecondRunNoNew 是驗收標準：
// 第二次執行時，相同結果不會標 NEW（規劃 §9）。
func TestNewFlagSecondRunNoNew(t *testing.T) {
	dir := t.TempDir()
	body := `
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
version   = "1.26.5"
`
	// 第一次：寫出報表當基準
	h1 := newHarnessWithReportDir(t, dir, body)
	rep1 := h1.run(t)
	writeBaseline(t, dir, rep1, "2026-11-02_0830")

	// 第二次
	h2 := newHarnessWithReportDir(t, dir, body)
	rep2 := h2.run(t)

	if rep2.Baseline == nil || !rep2.Baseline.AllSourcesOK {
		t.Fatalf("應該選到「全來源成功」的基準：%+v", rep2.Baseline)
	}
	for _, f := range rep2.AllFindings() {
		if f.New != model.NewStateNo {
			t.Errorf("%s 的 NEW = %q，相同結果不該標 NEW", f.ID, f.New)
		}
	}
	if rep2.Summary.NewCount != 0 {
		t.Errorf("Summary.NewCount = %d，預期 0", rep2.Summary.NewCount)
	}
}

// TestNewFlagDetectsAddedPackage 驗證新增的弱點會標 NEW。
func TestNewFlagDetectsAddedPackage(t *testing.T) {
	dir := t.TempDir()

	h1 := newHarnessWithReportDir(t, dir, `
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
version   = "1.26.5"
`)
	writeBaseline(t, dir, h1.run(t), "2026-11-02_0830")

	// 第二次多了一個套件
	h2 := newHarnessWithReportDir(t, dir, `
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
version   = "1.26.5"

[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"
`)
	rep := h2.run(t)

	if f := findFinding(rep.AllFindings(), "GHSA-9hjg-9r4m-mvj7"); f == nil || f.New != model.NewStateYes {
		t.Errorf("新增的 requests 弱點應標 NEW：%+v", f)
	}
	if f := findFinding(rep.AllFindings(), "GHSA-34jh-p97f-mpxf"); f == nil || f.New != model.NewStateNo {
		t.Errorf("既有的 urllib3 弱點不該標 NEW：%+v", f)
	}
}

// TestNewFlagSurvivesVersionUpgrade 是驗收標準：
// 升版後舊弱點不會重新變 NEW（規劃 §5.1：key 不含版本）。
func TestNewFlagSurvivesVersionUpgrade(t *testing.T) {
	dir := t.TempDir()

	h1 := newHarnessWithReportDir(t, dir, `
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
version   = "1.26.5"
`)
	writeBaseline(t, dir, h1.run(t), "2026-11-02_0830")

	// 使用者升版到 1.26.18（弱點還在，但版本變了）
	h2 := newHarnessWithReportDir(t, dir, `
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
version   = "1.26.18"
`)
	rep := h2.run(t)

	f := findFinding(rep.AllFindings(), "GHSA-34jh-p97f-mpxf")
	if f == nil {
		t.Fatal("前置條件：1.26.18 仍受 GHSA-34jh-p97f-mpxf 影響")
	}
	if f.Target.Version != "1.26.18" {
		t.Fatalf("前置條件：版本應為 1.26.18，實際 %q", f.Target.Version)
	}
	if f.New != model.NewStateNo {
		t.Errorf("升版後舊弱點不該重新變 NEW（規劃 §5.1），實際 %q", f.New)
	}
}

// TestNewFlagUndeterminedWhenBaselineSourceFailed 是驗收標準：
// 上次失敗的來源所涵蓋的項目不被標成 NEW（規劃 §5.1 / §9）。
func TestNewFlagUndeterminedWhenBaselineSourceFailed(t *testing.T) {
	dir := t.TempDir()
	body := `
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
version   = "1.26.5"
`
	// 製造一份「OSV 失敗」的基準報表
	failing := newHarnessWithReportDir(t, dir, body)
	failing.api.failOSV = true
	failing.http = mustHTTP(t, failing.cacheDir, func(o *httpx.Options) { o.MaxRetries = 1 })
	repFail := failing.run(t)
	if repFail.Summary.AllSourcesOK {
		t.Fatal("前置條件：基準報表應為不完整")
	}
	writeBaseline(t, dir, repFail, "2026-11-02_0830")

	// 這次成功，但基準那次 OSV 失敗 → 不可標成 NEW
	h := newHarnessWithReportDir(t, dir, body)
	rep := h.run(t)

	if len(rep.AllFindings()) == 0 {
		t.Fatal("前置條件：這次應該有結果")
	}
	for _, f := range rep.AllFindings() {
		if f.New != model.NewStateUndetermined {
			t.Errorf("%s 的 NEW = %q，上次該來源失敗時應為 undetermined", f.ID, f.New)
		}
	}
	if rep.Baseline == nil || rep.Baseline.AllSourcesOK {
		t.Errorf("Baseline 應標示該次結果不完整：%+v", rep.Baseline)
	}
}

// TestBaselinePrefersAllSourcesOK 驗證比對基準優先選最近一次「全來源成功」的（§5.1）。
func TestBaselinePrefersAllSourcesOK(t *testing.T) {
	dir := t.TempDir()
	body := `
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
version   = "1.26.5"
`
	good := newHarnessWithReportDir(t, dir, body)
	writeBaseline(t, dir, good.run(t), "2026-11-01_0830")

	bad := newHarnessWithReportDir(t, dir, body)
	bad.api.failOSV = true
	bad.http = mustHTTP(t, bad.cacheDir, func(o *httpx.Options) { o.MaxRetries = 1 })
	writeBaseline(t, dir, bad.run(t), "2026-11-02_0830")

	h := newHarnessWithReportDir(t, dir, body)
	rep := h.run(t)

	if rep.Baseline == nil {
		t.Fatal("應該有基準")
	}
	if !strings.Contains(rep.Baseline.Path, "2026-11-01_0830") {
		t.Errorf("基準 = %q，應選較舊但全來源成功的那一份", rep.Baseline.Path)
	}
	if !rep.Baseline.AllSourcesOK {
		t.Error("選到的基準應為全來源成功")
	}
}

func TestMajorMinorAndPatchNumber(t *testing.T) {
	cases := map[string]string{
		"1.27.3": "1.27", "v1.27.3": "1.27", "3.12.7": "3.12",
		"1.82.0": "1.82", "1.82": "1.82", "2": "2",
	}
	for in, want := range cases {
		if got := majorMinor(in); got != want {
			t.Errorf("majorMinor(%q) = %q，預期 %q", in, got, want)
		}
	}

	if n, ok := patchNumber("1.27.3"); !ok || n != 3 {
		t.Errorf("patchNumber(1.27.3) = %d, %v", n, ok)
	}
	if n, ok := patchNumber("1.82"); !ok || n != 0 {
		t.Errorf("patchNumber(1.82) = %d, %v，預期 0, true", n, ok)
	}
	if n, ok := patchNumber("1.27.3-rc1"); !ok || n != 3 {
		t.Errorf("patchNumber(1.27.3-rc1) = %d, %v", n, ok)
	}
	if _, ok := patchNumber("abc"); ok {
		t.Error("patchNumber(abc) 應該回傳 false")
	}
}

func TestSeverityFromNVDPrefersPrimaryV31(t *testing.T) {
	resp := &nvdResponse{}
	resp.Vulnerabilities = append(resp.Vulnerabilities, struct {
		CVE struct {
			ID      string `json:"id"`
			Metrics struct {
				CVSSMetricV31 []nvdMetric `json:"cvssMetricV31"`
				CVSSMetricV30 []nvdMetric `json:"cvssMetricV30"`
				CVSSMetricV40 []nvdMetric `json:"cvssMetricV40"`
			} `json:"metrics"`
		} `json:"cve"`
	}{})
	v := &resp.Vulnerabilities[0].CVE
	v.ID = "CVE-2024-0001"
	v.Metrics.CVSSMetricV31 = []nvdMetric{
		{Type: "Secondary", CVSSData: nvdCVSSData{BaseScore: 3.1, BaseSeverity: "LOW"}},
		{Type: "Primary", CVSSData: nvdCVSSData{BaseScore: 9.1, BaseSeverity: "CRITICAL", VectorString: "CVSS:3.1/..."}},
	}

	sev, ok := severityFromNVD(resp, "CVE-2024-0001")
	if !ok {
		t.Fatal("應該取得嚴重度")
	}
	if sev.Score != 9.1 || sev.Level != model.LevelCritical {
		t.Errorf("sev = %+v，預期 Primary 的 9.1 / CRITICAL", sev)
	}
	if sev.Source != model.SevSourceNVD {
		t.Errorf("Source = %q", sev.Source)
	}

	// 沒有 baseScore 時退而用 baseSeverity
	v.Metrics.CVSSMetricV31 = []nvdMetric{{Type: "Primary", CVSSData: nvdCVSSData{BaseSeverity: "HIGH"}}}
	sev, ok = severityFromNVD(resp, "CVE-2024-0001")
	if !ok || sev.Level != model.LevelHigh || sev.HasScore {
		t.Errorf("sev = %+v，預期 HIGH 且無分數", sev)
	}

	// 完全沒有 metrics → 取不到
	v.Metrics.CVSSMetricV31 = nil
	if _, ok := severityFromNVD(resp, "CVE-2024-0001"); ok {
		t.Error("沒有任何 metrics 時應該回傳 false")
	}

	// CVE 不符
	if _, ok := severityFromNVD(resp, "CVE-9999-9999"); ok {
		t.Error("CVE 不符時應該回傳 false")
	}
}

func TestFlexStringTolerance(t *testing.T) {
	var f flexString
	for raw, want := range map[string]string{
		`"2026-08-19"`: "2026-08-19",
		`null`:         "",
		`false`:        "false",
		`123`:          "123",
	} {
		if err := f.UnmarshalJSON([]byte(raw)); err != nil {
			t.Errorf("UnmarshalJSON(%s) 錯誤: %v", raw, err)
		}
		if f.String() != want {
			t.Errorf("UnmarshalJSON(%s) = %q，預期 %q", raw, f.String(), want)
		}
	}
}

// --- 測試輔助 ---

func newHarnessWithReportDir(t *testing.T, reportDir, body string) *harness {
	t.Helper()
	src := "[general]\n" +
		"report_dir = '" + reportDir + "'\n" +
		"cache_dir  = '" + filepath.Join(t.TempDir(), "cache") + "'\n" +
		body
	return newHarness(t, src, nil)
}

func mustHTTP(t *testing.T, cacheDir string, mod func(*httpx.Options)) *httpx.Client {
	t.Helper()
	o := httpx.Options{
		UserAgent: "vulnwatch/test",
		CacheDir:  cacheDir,
		CacheTTL:  time.Hour,
		Sleep:     func(time.Duration) {},
	}
	if mod != nil {
		mod(&o)
	}
	c, err := httpx.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// runWithBudget 用指定的 NVD 查詢上限執行一次掃描。
func runWithBudget(h *harness, budget int) (*model.Report, error) {
	return Run(context.Background(), Options{
		Config:          h.cfg,
		HTTP:            h.http,
		ToolVersion:     "test",
		Now:             time.Date(2026, 11, 3, 8, 30, 0, 0, time.UTC),
		OSVEndpoint:     h.api.srv.URL,
		EOLEndpoint:     h.api.srv.URL,
		NVDEndpoint:     h.api.srv.URL,
		NVDLookupBudget: budget,
	})
}

func countNVDRequests(paths []string) int {
	n := 0
	for _, p := range paths {
		if strings.Contains(p, "/rest/json/cves/") {
			n++
		}
	}
	return n
}

// writeBaseline 把一份報表寫成舊報表目錄，供下一次執行當 NEW 判定的基準。
func writeBaseline(t *testing.T, reportDir string, rep *model.Report, stamp string) {
	t.Helper()
	dir := filepath.Join(reportDir, stamp)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := report.MarshalJSON(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestConfigWarningWhereAndMessageNotSwapped 是回歸測試：
// 設定檔警告的 Where 必須是位置（檔名:行號 欄位）、Message 必須是訊息內容。
// 曾經顛倒過，報表會印成「<整句警告>：設定檔警告」。
func TestConfigWarningWhereAndMessageNotSwapped(t *testing.T) {
	src := baseGeneral + `report_formats = ["md", "html"]

[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	var p *model.Problem
	for i := range rep.Problems {
		if strings.Contains(rep.Problems[i].Message, "html") {
			p = &rep.Problems[i]
		}
	}
	if p == nil {
		t.Fatalf("找不到 html 格式的警告：%+v", rep.Problems)
	}
	if p.Message == "設定檔警告" {
		t.Error("Message 不可是「設定檔警告」這種標籤，必須是訊息內容")
	}
	if !strings.Contains(p.Where, "vulnwatch.toml:") {
		t.Errorf("Where = %q，必須是「檔名:行號 欄位」形式", p.Where)
	}
	if !strings.Contains(p.Where, "general.report_formats") {
		t.Errorf("Where = %q，應該含欄位名", p.Where)
	}
}

// TestResultLineAlwaysReportsUnknownCount 是回歸測試：
// UNKNOWN 不參與 fail_on，所以有無評級弱點時 exit code 仍是 0。
// log 第一行（規劃 §8 要求寫清楚的那一行）必須寫出 UNKNOWN 數量，
// 否則接監控的人會把 exit 0 誤判成全無風險。
func TestResultLineAlwaysReportsUnknownCount(t *testing.T) {
	src := baseGeneral + `fail_on = "HIGH"

[sources]
nvd = false

[[packages]]
ecosystem = "Go"
name      = "golang.org/x/net"
version   = "v0.20.0"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	if len(rep.Unknown) == 0 {
		t.Fatal("前置條件：應該有 UNKNOWN 項目")
	}
	triggered, _ := FailOnTriggered(rep, h.cfg)
	if triggered {
		t.Fatal("前置條件：UNKNOWN 不該觸發 fail_on")
	}

	line := ResultLine(rep, h.cfg, 0)
	if !strings.Contains(line, "exit 0") {
		t.Errorf("ResultLine = %q，應該是 exit 0", line)
	}
	if !strings.Contains(line, "1 unknown-severity") {
		t.Errorf("ResultLine = %q，必須寫出 1 筆 UNKNOWN，否則 exit 0 會被誤判成全無風險", line)
	}
}
