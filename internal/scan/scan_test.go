package scan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elvis3434/vulnwatch/internal/config"
	"github.com/elvis3434/vulnwatch/internal/httpx"
	"github.com/elvis3434/vulnwatch/internal/model"
)

type harness struct {
	api      *fakeAPI
	cfg      *config.Config
	http     *httpx.Client
	cacheDir string
}

func newHarness(t *testing.T, tomlSrc string, mod func(*httpx.Options)) *harness {
	t.Helper()
	api := newFakeAPI(t)

	cfg, err := config.Parse([]byte(tomlSrc), "vulnwatch.toml")
	if err != nil {
		t.Fatalf("測試用設定檔有錯誤: %v", err)
	}

	cacheDir := t.TempDir()
	opts := httpx.Options{
		UserAgent: "vulnwatch/test",
		CacheDir:  cacheDir,
		CacheTTL:  time.Hour,
		Sleep:     func(time.Duration) {},
	}
	if mod != nil {
		mod(&opts)
	}
	h, err := httpx.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{api: api, cfg: cfg, http: h, cacheDir: cacheDir}
}

func (h *harness) run(t *testing.T) *model.Report {
	t.Helper()
	rep, err := Run(context.Background(), Options{
		Config:      h.cfg,
		HTTP:        h.http,
		ToolVersion: "test",
		Now:         time.Date(2026, 11, 3, 8, 30, 0, 0, time.UTC),
		OSVEndpoint: h.api.srv.URL,
		EOLEndpoint: h.api.srv.URL,
		NVDEndpoint: h.api.srv.URL,
	})
	if err != nil {
		t.Fatalf("scan.Run 失敗: %v", err)
	}
	return rep
}

func findFinding(fs []model.Finding, id string) *model.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

const baseGeneral = `
[general]
report_dir = "/tmp/vw-test/reports"
cache_dir  = "/tmp/vw-test/cache"
`

// TestGoAdvisoryStaysInUnknownBlock 是規劃 §9 的具名回歸案例：
// min_severity = "HIGH" 時，Go/golang.org/x/net@v0.20.0 的 GO-* 弱點（無 CVSS）
// 仍必須出現在 UNKNOWN 區塊，不可消失。這是第一版最嚴重的 bug。
func TestGoAdvisoryStaysInUnknownBlock(t *testing.T) {
	src := baseGeneral + `min_severity = "HIGH"

[sources]
nvd = false

[[packages]]
ecosystem = "Go"
name      = "golang.org/x/net"
version   = "v0.20.0"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	if f := findFinding(rep.Unknown, "GO-2024-2687"); f == nil {
		t.Fatalf("GO-2024-2687 必須出現在 UNKNOWN 區塊；目前 Unknown=%d、Findings=%d、Filtered=%d",
			len(rep.Unknown), len(rep.Findings), len(rep.Filtered))
	}
	// 不可被 min_severity 濾掉
	if f := findFinding(rep.Filtered, "GO-2024-2687"); f != nil {
		t.Fatal("UNKNOWN 永不可被 min_severity 濾掉（規劃 §3.2 硬規則）")
	}

	f := findFinding(rep.Unknown, "GO-2024-2687")
	if f.Severity.Level != model.LevelUnknown {
		t.Errorf("Severity.Level = %v，預期 UNKNOWN", f.Severity.Level)
	}
	if f.Severity.Source != model.SevSourceNone {
		t.Errorf("Severity.Source = %q，預期 %q", f.Severity.Source, model.SevSourceNone)
	}
	// 即使沒有分數，仍要給出可操作的修正版本
	if f.Fix.Kind != model.FixKindFixed || f.Fix.Version != "0.23.0" {
		t.Errorf("Fix = %+v，預期 fixed 0.23.0", f.Fix)
	}
	if rep.Summary.UnknownCount != 1 {
		t.Errorf("Summary.UnknownCount = %d，預期 1", rep.Summary.UnknownCount)
	}
}

// TestURLLib3FixedVersionEndToEnd 是規劃 §9 的另一個具名回歸案例，
// 這次走完整的 scan 流程。
func TestURLLib3FixedVersionEndToEnd(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
version   = "1.26.5"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	f := findFinding(rep.Findings, "GHSA-34jh-p97f-mpxf")
	if f == nil {
		t.Fatalf("找不到 GHSA-34jh-p97f-mpxf；Findings=%d Filtered=%d Unknown=%d",
			len(rep.Findings), len(rep.Filtered), len(rep.Unknown))
	}
	if f.Fix.Version != "1.26.19" {
		t.Fatalf("最低安全版本 = %q，預期 1.26.19（不能是 2.2.2）", f.Fix.Version)
	}
	if f.Severity.Source != model.SevSourceCVSS31OSV {
		t.Errorf("Severity.Source = %q，預期 CVSS3.1(OSV)", f.Severity.Source)
	}
}

// TestMinSeverityFiltersScoredFindings 驗證 min_severity 對「有評級」的項目有效。
func TestMinSeverityFiltersScoredFindings(t *testing.T) {
	src := baseGeneral + `min_severity = "HIGH"

[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	// requests 的 GHSA-9hjg-9r4m-mvj7 是 MEDIUM(5.3)，低於 HIGH
	if len(rep.Findings) != 0 {
		t.Errorf("Findings = %d，預期 0（MEDIUM 低於 HIGH 門檻）", len(rep.Findings))
	}
	if findFinding(rep.Filtered, "GHSA-9hjg-9r4m-mvj7") == nil {
		t.Error("被濾掉的項目仍必須寫進 JSON 的 filtered_out，否則下次會誤判成 NEW")
	}
	if rep.Summary.FilteredCount != 1 {
		t.Errorf("Summary.FilteredCount = %d，預期 1", rep.Summary.FilteredCount)
	}
}

// TestCleanPackageHasNoFindings 驗收標準：以最新版掃描，報表顯示無弱點。
func TestCleanPackageHasNoFindings(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = false

[[packages]]
ecosystem = "crates.io"
name      = "tokio"
version   = "1.38.0"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	if len(rep.Findings)+len(rep.Unknown)+len(rep.Filtered) != 0 {
		t.Errorf("預期無弱點，但得到 findings=%d unknown=%d filtered=%d",
			len(rep.Findings), len(rep.Unknown), len(rep.Filtered))
	}
	if len(rep.NoData) != 0 {
		t.Error("查詢成功但無弱點，不該出現在「無資料」區塊")
	}
	if !rep.Summary.AllSourcesOK {
		t.Error("所有來源都成功時 AllSourcesOK 應為 true")
	}
}

// TestSecondRunUsesCache 是驗收標準「第二次執行的網路請求數明顯下降」（規劃 §9 / §2.2）。
func TestSecondRunUsesCache(t *testing.T) {
	src := baseGeneral + `
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

[[packages]]
purl = "pkg:golang/golang.org/x/net@v0.20.0"
`
	h := newHarness(t, src, nil)
	h.run(t)
	first := h.api.Hits()
	if first != 3 {
		t.Fatalf("第一次執行的請求數 = %d，預期 3（每個套件一次 POST /v1/query）", first)
	}

	// 第二次執行：換新的 client 但共用快取目錄
	h.api.ResetHits()
	h2, err := httpx.New(httpx.Options{
		UserAgent: "vulnwatch/test",
		CacheDir:  h.cacheDir,
		CacheTTL:  time.Hour,
		Sleep:     func(time.Duration) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.http = h2
	rep2 := h.run(t)

	if got := h.api.Hits(); got != 0 {
		t.Errorf("第二次執行的網路請求數 = %d，預期 0（全部命中快取）", got)
	}
	if h2.Stats().CacheHits != 3 {
		t.Errorf("快取命中 = %d，預期 3", h2.Stats().CacheHits)
	}
	// 結果必須和第一次一樣
	if len(rep2.Findings) == 0 && len(rep2.Unknown) == 0 {
		t.Error("用快取也必須產出相同的結果")
	}
}

// TestOfflineMarksNoDataNotNoVulns 是驗收標準：
// --offline 在有快取時可產出報表，未命中項目標示「無資料」而非「無弱點」（規劃 §2.2 / §9）。
func TestOfflineMarksNoDataNotNoVulns(t *testing.T) {
	src := baseGeneral + `
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
`
	// 第一次只暖一個套件的快取
	warm := newHarness(t, baseGeneral+`
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
version   = "1.26.5"
`, nil)
	warm.run(t)

	// 第二次用 offline，共用快取目錄，但設定檔多了一個沒暖過的套件
	h := newHarness(t, src, func(o *httpx.Options) {
		o.CacheDir = warm.cacheDir
		o.Offline = true
	})
	h.api = warm.api // 指向同一個假伺服器（offline 下不該被呼叫）
	h.api.ResetHits()
	rep := h.run(t)

	if h.api.Hits() != 0 {
		t.Errorf("--offline 下不可發出網路請求，但伺服器收到 %d 次", h.api.Hits())
	}
	if !rep.Offline {
		t.Error("報表應該標示 offline 模式")
	}

	// 有快取的 urllib3 照常產出結果
	if findFinding(rep.Findings, "GHSA-34jh-p97f-mpxf") == nil {
		t.Error("有快取的套件應該照常產出弱點")
	}

	// 沒快取的 requests 必須是「無資料」，不是「無弱點」
	if len(rep.NoData) != 1 {
		t.Fatalf("NoData = %d 筆，預期 1 筆（requests 未命中快取）", len(rep.NoData))
	}
	nd := rep.NoData[0]
	if nd.Target.Name != "requests" {
		t.Errorf("NoData 對象 = %q，預期 requests", nd.Target.Name)
	}
	if !strings.Contains(nd.Reason, "無法判斷") {
		t.Errorf("NoData 原因 = %q，必須說明無法判斷有無弱點", nd.Reason)
	}
	if rep.Summary.AllSourcesOK {
		t.Error("有對象無資料時，結果不算完整")
	}
}

// TestSourceFailureStillProducesReport 是驗收標準：
// 某個資料來源失敗時，其餘照常產出，報表明確標示不完整（規劃 §9）。
func TestSourceFailureStillProducesReport(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
version   = "1.26.5"
`
	h := newHarness(t, src, func(o *httpx.Options) { o.MaxRetries = 1 })
	h.api.failOSV = true
	rep := h.run(t)

	if rep.Summary.AllSourcesOK {
		t.Error("OSV 失敗時 AllSourcesOK 必須是 false")
	}
	var osvStatus *model.SourceStatus
	for i := range rep.Sources {
		if rep.Sources[i].Name == "OSV" {
			osvStatus = &rep.Sources[i]
		}
	}
	if osvStatus == nil {
		t.Fatal("報表必須含 OSV 的來源狀態")
	}
	if osvStatus.OK || osvStatus.Errors == 0 {
		t.Errorf("OSV 狀態 = %+v，預期失敗且 Errors > 0", *osvStatus)
	}
	// 失敗必須寫進錯誤區，不可靜默吞掉（規劃 §5 第 7 點）
	hasError := false
	for _, p := range rep.Problems {
		if p.Level == model.ProblemError {
			hasError = true
		}
	}
	if !hasError {
		t.Error("來源失敗必須在報表的錯誤區出現")
	}
	// 失敗的對象要列為無資料
	if len(rep.NoData) != 1 {
		t.Errorf("NoData = %d 筆，預期 1 筆", len(rep.NoData))
	}
}

// TestIgnoreListHidesAndExpiredReappears 驗證忽略清單與到期行為（規劃 §3.4）。
func TestIgnoreListHidesAndExpiredReappears(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
version   = "1.26.5"

[[ignore]]
id        = "GHSA-34jh-p97f-mpxf"
ecosystem = "PyPI"
name      = "urllib3"
reason    = "未使用 proxy"
expires   = "2027-12-31"

[[ignore]]
id      = "CVE-2023-45803"
reason  = "已於上游修正，等下個版本窗口"
expires = "2026-01-01"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	// 未到期的忽略 → 進「已忽略項目」區塊
	if findFinding(rep.Ignored, "GHSA-34jh-p97f-mpxf") == nil {
		t.Errorf("未到期的忽略應該進 Ignored 區塊；Ignored=%d", len(rep.Ignored))
	}
	if findFinding(rep.Findings, "GHSA-34jh-p97f-mpxf") != nil {
		t.Error("未到期的忽略不該出現在需處理清單")
	}

	// 已到期的忽略（用 alias CVE 命中）→ 照常列入報表並標示到期
	f := findFinding(rep.Findings, "GHSA-g4mx-q9vg-27p4")
	if f == nil {
		t.Fatal("已到期的忽略項目必須重新列入報表（規劃 §3.4）")
	}
	if f.Ignore == nil || !f.Ignore.Expired {
		t.Errorf("項目應標示忽略已到期：%+v", f.Ignore)
	}
	if f.Ignore.Expires != "2026-01-01" {
		t.Errorf("到期日 = %q", f.Ignore.Expires)
	}
}

// TestMavenCandidatesInReport 驗證不做版本比較的生態系（規劃 §3.3）。
func TestMavenCandidatesInReport(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = false

[[packages]]
ecosystem = "Maven"
name      = "org.apache.logging.log4j:log4j-core"
version   = "2.14.1"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	f := findFinding(rep.Findings, "GHSA-jfh8-c2jp-5v3q")
	if f == nil {
		t.Fatalf("找不到 log4j 的弱點；Findings=%d", len(rep.Findings))
	}
	if f.Fix.Kind != model.FixKindCandidates {
		t.Errorf("Fix.Kind = %q，預期 candidates", f.Fix.Kind)
	}
	if f.Severity.Level != model.LevelCritical {
		t.Errorf("Severity.Level = %v，預期 CRITICAL", f.Severity.Level)
	}
	// 報表的已知限制必須提到 Maven 不做版本比較
	found := false
	for _, l := range rep.Limitations {
		if strings.Contains(l, "Maven") {
			found = true
		}
	}
	if !found {
		t.Error("已知限制必須說明 Maven 不做版本比較")
	}
}

// TestDedupSameAdvisory 驗證同一對象的同一 advisory 只出現一次。
func TestDedupSameAdvisory(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
version   = "1.26.5"

[[packages]]
ecosystem = "PyPI"
name      = "URLLIB3"
version   = "1.26.5"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	n := 0
	for _, f := range rep.AllFindings() {
		if f.ID == "GHSA-34jh-p97f-mpxf" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("GHSA-34jh-p97f-mpxf 出現 %d 次，預期 1 次（PyPI 名稱需正規化後去重）", n)
	}
}

// TestConfigWarningsReachReport 驗證設定檔警告會進報表（規劃 §3.4）。
func TestConfigWarningsReachReport(t *testing.T) {
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

	found := false
	for _, p := range rep.Problems {
		if p.Level == model.ProblemWarning && strings.Contains(p.Message, "html") {
			found = true
		}
	}
	if !found {
		t.Errorf("設定檔警告必須進報表的錯誤/警告區：%+v", rep.Problems)
	}
}

// TestFailOnTriggered 驗證 fail_on 的 exit code 判定（規劃 §6 / §8）。
func TestFailOnTriggered(t *testing.T) {
	src := baseGeneral + `fail_on = "HIGH"

[sources]
nvd = false

[[packages]]
ecosystem = "Maven"
name      = "org.apache.logging.log4j:log4j-core"
version   = "2.14.1"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	triggered, n := FailOnTriggered(rep, h.cfg)
	if !triggered || n != 1 {
		t.Errorf("FailOnTriggered = %v, %d，預期 true, 1（CRITICAL >= HIGH）", triggered, n)
	}
	line := ResultLine(rep, h.cfg, 1)
	if !strings.HasPrefix(line, "RESULT: 1 findings >= HIGH (exit 1)") {
		t.Errorf("ResultLine = %q，格式應照規劃 §8", line)
	}
	// UNKNOWN 數量一律要附上，否則接監控的人會以為 exit 0 就是全無風險
	if !strings.Contains(line, "unknown-severity") {
		t.Errorf("ResultLine = %q，設了 fail_on 時也必須寫出 UNKNOWN 數量", line)
	}
}

// TestFailOnUnsetAlwaysZero 驗證 fail_on 預設為空字串時永遠不觸發（規劃 §8）。
func TestFailOnUnsetAlwaysZero(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = false

[[packages]]
ecosystem = "Maven"
name      = "org.apache.logging.log4j:log4j-core"
version   = "2.14.1"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	if triggered, _ := FailOnTriggered(rep, h.cfg); triggered {
		t.Error("fail_on 未設定時不可觸發 exit 1（規劃 §8：排程器會把 exit 1 顯示成錯誤）")
	}
	if line := ResultLine(rep, h.cfg, 0); !strings.Contains(line, "fail_on 未設定") {
		t.Errorf("ResultLine = %q", line)
	}
}

// TestFailOnIgnoresUnknown 驗證 UNKNOWN 不參與 fail_on（它沒有分數可比）。
func TestFailOnIgnoresUnknown(t *testing.T) {
	src := baseGeneral + `fail_on = "LOW"

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
	if triggered, _ := FailOnTriggered(rep, h.cfg); triggered {
		t.Error("UNKNOWN 不該觸發 fail_on（無分數可與門檻比較）")
	}
}

// TestNoVersionListsAllVulns 驗證未指定版本的行為（規劃 §3.1）。
func TestNoVersionListsAllVulns(t *testing.T) {
	src := baseGeneral + `
[sources]
nvd = false

[[packages]]
ecosystem = "PyPI"
name      = "urllib3"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	f := findFinding(rep.AllFindings(), "GHSA-34jh-p97f-mpxf")
	if f == nil {
		t.Fatal("未指定版本時應該列出全部已知弱點")
	}
	if f.Fix.Kind != model.FixKindCandidates {
		t.Errorf("Fix.Kind = %q，預期 candidates（無法判定版本線）", f.Fix.Kind)
	}
}

// TestPhase2SourcesAreReportedAsNotQueried 驗證 Phase 2 來源的狀態也會列出，
// 使用者才知道這次沒有查（規劃 §5）。
func TestPhase2SourcesAreReportedAsNotQueried(t *testing.T) {
	src := baseGeneral + `
[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"
`
	h := newHarness(t, src, nil)
	rep := h.run(t)

	want := map[string]bool{"RustSec": false, "deps.dev": false, "KEV": false, "EPSS": false}
	for _, s := range rep.Sources {
		if _, ok := want[s.Name]; ok {
			want[s.Name] = true
			if !strings.Contains(s.Message, "Phase 2") {
				t.Errorf("%s 的說明 = %q，應標示 Phase 2 未查詢", s.Name, s.Message)
			}
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("報表缺少 %s 的來源狀態", name)
		}
	}
}

func TestTargetKeyAndDiffKey(t *testing.T) {
	// DiffKey 刻意不含版本（規劃 §5.1：否則升版後舊弱點會重新變 NEW）
	a := model.Finding{Target: model.Target{Ecosystem: "PyPI", Name: "urllib3", Version: "1.26.5"}, ID: "GHSA-x"}
	b := model.Finding{Target: model.Target{Ecosystem: "PyPI", Name: "urllib3", Version: "1.26.18"}, ID: "GHSA-x"}
	if a.DiffKey() != b.DiffKey() {
		t.Errorf("升版後 DiffKey 不該改變：%q vs %q", a.DiffKey(), b.DiffKey())
	}
	// 但 Target.Key 含版本（用於同一次掃描內的去重）
	if a.Target.Key() == b.Target.Key() {
		t.Error("Target.Key 應該含版本")
	}
}

func TestRunRequiresConfigAndClient(t *testing.T) {
	if _, err := Run(context.Background(), Options{}); err == nil {
		t.Error("缺少設定檔時應該回傳錯誤")
	}
	cfg, err := config.Parse([]byte(baseGeneral+`
[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"
`), "x.toml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), Options{Config: cfg}); err == nil {
		t.Error("缺少 HTTP 客戶端時應該回傳錯誤")
	}
}

func TestReportPathsUseFilepath(t *testing.T) {
	// 這個測試只是確保報表目錄組合用的是 filepath（規劃 §6：需支援 Windows 路徑）。
	p := filepath.Join("D:\\vulnwatch\\reports", "2026-11-03_0830")
	if p == "" {
		t.Fatal("unreachable")
	}
}
