package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elvis3434/vulnwatch/internal/httpx"
	"github.com/elvis3434/vulnwatch/internal/model"
)

// testdataDir 是 repo 根目錄下的 testdata。
func testdataDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata")
}

func loadFixture(t *testing.T, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(testdataDir(t), rel))
	if err != nil {
		t.Fatalf("讀取 fixture %s 失敗: %v", rel, err)
	}
	return raw
}

func loadAdvisories(t *testing.T, rel string) []Advisory {
	t.Helper()
	var qr queryResponse
	if err := json.Unmarshal(loadFixture(t, rel), &qr); err != nil {
		t.Fatalf("解析 fixture %s 失敗: %v", rel, err)
	}
	return qr.Vulns
}

func findAdvisory(t *testing.T, advs []Advisory, id string) Advisory {
	t.Helper()
	for _, a := range advs {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("fixture 裡找不到 advisory %s", id)
	return Advisory{}
}

// TestSelectFixURLLib3Regression 是規劃 §9 的具名回歸案例：
// PyPI/urllib3@1.26.5 的 GHSA-34jh-p97f-mpxf，最低安全版本必須是 1.26.19，
// 不能是 2.2.2（挑錯就會建議使用者做跨大版本的破壞性升級）。
func TestSelectFixURLLib3Regression(t *testing.T) {
	advs := loadAdvisories(t, filepath.Join("osv", "pypi_urllib3_1.26.5.json"))
	adv := findAdvisory(t, advs, "GHSA-34jh-p97f-mpxf")

	fix := SelectFix(adv, model.EcosystemPyPI, "urllib3", "1.26.5", model.ComparerFor(model.EcosystemPyPI))

	if fix.Kind != model.FixKindFixed {
		t.Fatalf("Fix.Kind = %q，預期 %q（應該能確定版本）", fix.Kind, model.FixKindFixed)
	}
	if fix.Version != "1.26.19" {
		t.Fatalf("最低安全版本 = %q，預期 1.26.19（規劃 §9 回歸案例；2.2.2 是錯的）", fix.Version)
	}
}

// TestSelectFixPicksCorrectLineForEachVersion 驗證同一個 advisory 的不同版本線。
func TestSelectFixPicksCorrectLineForEachVersion(t *testing.T) {
	advs := loadAdvisories(t, filepath.Join("osv", "pypi_urllib3_1.26.5.json"))
	adv := findAdvisory(t, advs, "GHSA-34jh-p97f-mpxf")
	cmp := model.ComparerFor(model.EcosystemPyPI)

	cases := map[string]string{
		"1.26.0":  "1.26.19", // 第一段
		"1.26.5":  "1.26.19",
		"1.26.18": "1.26.19",
		"2.0.0":   "2.2.2", // 第二段
		"2.2.1":   "2.2.2",
	}
	for version, want := range cases {
		fix := SelectFix(adv, model.EcosystemPyPI, "urllib3", version, cmp)
		if fix.Version != want {
			t.Errorf("urllib3@%s 的最低安全版本 = %q（kind=%s），預期 %q",
				version, fix.Version, fix.Kind, want)
		}
	}
}

// TestSelectFixNoComparer 驗證 Maven 不做版本比較時列出全部候選（規劃 §3.3）。
func TestSelectFixNoComparer(t *testing.T) {
	advs := loadAdvisories(t, filepath.Join("osv", "maven_log4j_2.14.1.json"))
	adv := advs[0]

	fix := SelectFix(adv, model.EcosystemMaven,
		"org.apache.logging.log4j:log4j-core", "2.14.1", model.ComparerFor(model.EcosystemMaven))

	if fix.Kind != model.FixKindCandidates {
		t.Fatalf("Fix.Kind = %q，預期 %q（Maven 不做版本比較）", fix.Kind, model.FixKindCandidates)
	}
	if len(fix.Candidates) != 3 {
		t.Fatalf("候選版本 = %v，預期 3 個（2.3.1 / 2.12.2 / 2.15.0）", fix.Candidates)
	}
	if fix.Note == "" {
		t.Error("未做版本比較時必須標註限制")
	}
	// 報表上必須看得出來這是「多個候選、未比較」的狀態。
	if disp := fix.Display(); disp == "2.15.0" || disp == "" {
		t.Errorf("Fix.Display() = %q，應該明確表達未比較狀態", disp)
	}
}

// TestSelectFixGoSemver 驗證 Go 的版本線挑選。
func TestSelectFixGoSemver(t *testing.T) {
	advs := loadAdvisories(t, filepath.Join("osv", "go_x_net_v0.20.0.json"))
	adv := findAdvisory(t, advs, "GO-2024-2687")

	fix := SelectFix(adv, model.EcosystemGo, "golang.org/x/net", "v0.20.0", model.ComparerFor(model.EcosystemGo))
	if fix.Kind != model.FixKindFixed || fix.Version != "0.23.0" {
		t.Fatalf("Fix = %+v，預期 fixed 0.23.0", fix)
	}
}

// TestSelectFixMultiRangeStdlib 驗證 stdlib 的多版本線（1.21.x 與 1.22.x）。
func TestSelectFixMultiRangeStdlib(t *testing.T) {
	advs := loadAdvisories(t, filepath.Join("osv", "go_stdlib_v1.21.0.json"))
	adv := advs[0]
	cmp := model.ComparerFor(model.EcosystemGo)

	if fix := SelectFix(adv, model.EcosystemGo, "stdlib", "v1.21.0", cmp); fix.Version != "1.21.8" {
		t.Errorf("stdlib@v1.21.0 → %q，預期 1.21.8", fix.Version)
	}
	if fix := SelectFix(adv, model.EcosystemGo, "stdlib", "v1.22.0", cmp); fix.Version != "1.22.1" {
		t.Errorf("stdlib@v1.22.0 → %q，預期 1.22.1", fix.Version)
	}
}

// TestSelectFixNoVersion 驗證未指定版本時的行為（規劃 §3.1）。
func TestSelectFixNoVersion(t *testing.T) {
	advs := loadAdvisories(t, filepath.Join("osv", "pypi_urllib3_1.26.5.json"))
	adv := findAdvisory(t, advs, "GHSA-34jh-p97f-mpxf")

	fix := SelectFix(adv, model.EcosystemPyPI, "urllib3", "", model.ComparerFor(model.EcosystemPyPI))
	if fix.Kind != model.FixKindCandidates {
		t.Fatalf("Fix.Kind = %q，預期 %q", fix.Kind, model.FixKindCandidates)
	}
	if len(fix.Candidates) != 2 {
		t.Errorf("候選版本 = %v，預期 1.26.19 與 2.2.2", fix.Candidates)
	}
}

// TestSelectFixNoFixAvailable 驗證「尚無修正版本」。
func TestSelectFixNoFixAvailable(t *testing.T) {
	adv := Advisory{
		ID: "GHSA-test-nofix",
		Affected: []Affected{{
			Package: Package{Ecosystem: model.EcosystemPyPI, Name: "example"},
			Ranges: []Range{{
				Type:   "ECOSYSTEM",
				Events: []Event{{Introduced: "0"}},
			}},
		}},
	}
	fix := SelectFix(adv, model.EcosystemPyPI, "example", "1.0.0", model.ComparerFor(model.EcosystemPyPI))
	if fix.Kind != model.FixKindNone {
		t.Fatalf("Fix.Kind = %q，預期 %q", fix.Kind, model.FixKindNone)
	}
	if fix.Display() != "尚無修正版本" {
		t.Errorf("Fix.Display() = %q", fix.Display())
	}
}

// TestSelectFixIgnoresGitRange 驗證 GIT range 不會被誤用（規劃 §4.2 的 CPython 案例）。
func TestSelectFixIgnoresGitRange(t *testing.T) {
	adv := Advisory{
		ID: "CVE-2024-9287",
		Affected: []Affected{{
			Package: Package{Ecosystem: model.EcosystemPyPI, Name: "cpython"},
			Ranges: []Range{{
				Type:   "GIT",
				Repo:   "https://github.com/python/cpython",
				Events: []Event{{Introduced: "0"}, {Fixed: "f3994ad7a2b5a7c9c1b0b6b4f9d6c8a0e5f1b2c3"}},
			}},
		}},
	}
	fix := SelectFix(adv, model.EcosystemPyPI, "cpython", "3.12.7", model.ComparerFor(model.EcosystemPyPI))
	if fix.Kind == model.FixKindFixed {
		t.Fatalf("GIT range 的 commit hash 不可被當成版本號：%+v", fix)
	}
}

// TestResolveSeverityCVSSV3 驗證第 1 層回退：CVSS_V3 vector 自算分數。
func TestResolveSeverityCVSSV3(t *testing.T) {
	advs := loadAdvisories(t, filepath.Join("osv", "pypi_requests_2.31.0.json"))
	adv := findAdvisory(t, advs, "GHSA-9hjg-9r4m-mvj7")

	sev := ResolveSeverity(adv)
	if sev.Source != model.SevSourceCVSS31OSV {
		t.Fatalf("Severity.Source = %q，預期 %q（第 1 層）", sev.Source, model.SevSourceCVSS31OSV)
	}
	if !sev.HasScore || sev.Score != 5.3 {
		t.Fatalf("Severity.Score = %.1f (has=%v)，預期 5.3", sev.Score, sev.HasScore)
	}
	if sev.Level != model.LevelMedium {
		t.Fatalf("Severity.Level = %v，預期 MEDIUM", sev.Level)
	}
}

// TestResolveSeverityGHSAQualitative 驗證第 2 層回退：
// 沒有 CVSS_V3、只有 CVSS_V4 時，用 database_specific.severity 的質性等級，
// 並且**不**硬算 v4 分數（規劃 §3.2）。
func TestResolveSeverityGHSAQualitative(t *testing.T) {
	adv := Advisory{
		ID: "GHSA-only-v4",
		Severity: []Severity{
			{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		},
		DatabaseSpecific: json.RawMessage(`{"severity":"HIGH"}`),
	}
	sev := ResolveSeverity(adv)
	if sev.Source != model.SevSourceGHSA {
		t.Fatalf("Severity.Source = %q，預期 %q（第 2 層）", sev.Source, model.SevSourceGHSA)
	}
	if sev.Level != model.LevelHigh {
		t.Fatalf("Severity.Level = %v，預期 HIGH", sev.Level)
	}
	if sev.HasScore {
		t.Error("只有 CVSS_V4 時不可硬算分數（規劃 §3.2）")
	}
	if sev.Vector == "" || sev.VectorType != "CVSS_V4" {
		t.Error("CVSS_V4 的 vector 原文仍必須保留供顯示")
	}
}

// TestResolveSeverityGoAdvisoryIsUnknown 驗證第 4 層回退：
// Go 官方 advisory 的 severity 一律是 null，必須走 UNKNOWN（規劃 §3.2 / §11）。
func TestResolveSeverityGoAdvisoryIsUnknown(t *testing.T) {
	for _, rel := range []string{
		filepath.Join("osv", "go_x_net_v0.20.0.json"),
		filepath.Join("osv", "go_stdlib_v1.21.0.json"),
		filepath.Join("osv", "go_toolchain_v1.21.0.json"),
	} {
		for _, adv := range loadAdvisories(t, rel) {
			sev := ResolveSeverity(adv)
			if sev.Level != model.LevelUnknown {
				t.Errorf("%s 的 %s：Severity.Level = %v，預期 UNKNOWN", rel, adv.ID, sev.Level)
			}
			if sev.Source != model.SevSourceNone {
				t.Errorf("%s 的 %s：Severity.Source = %q，預期 %q", rel, adv.ID, sev.Source, model.SevSourceNone)
			}
			if sev.HasScore {
				t.Errorf("%s 的 %s 不該有分數", rel, adv.ID)
			}
		}
	}
}

// TestResolveSeverityAffectedLevelDatabaseSpecific 驗證質性等級也會從 affected[] 層級取。
func TestResolveSeverityAffectedLevelDatabaseSpecific(t *testing.T) {
	adv := Advisory{
		ID: "GHSA-affected-level",
		Affected: []Affected{{
			Package:          Package{Ecosystem: model.EcosystemNPM, Name: "lodash"},
			DatabaseSpecific: json.RawMessage(`{"severity":"CRITICAL"}`),
		}},
	}
	if sev := ResolveSeverity(adv); sev.Level != model.LevelCritical {
		t.Fatalf("Severity.Level = %v，預期 CRITICAL", sev.Level)
	}
}

func TestCVEAliases(t *testing.T) {
	advs := loadAdvisories(t, filepath.Join("osv", "go_x_net_v0.20.0.json"))
	cves := CVEAliases(advs[0])
	if len(cves) != 1 || cves[0] != "CVE-2023-45288" {
		t.Fatalf("CVEAliases = %v，預期 [CVE-2023-45288]（GHSA 別名不算）", cves)
	}
}

// TestClientQueryUsesPostV1Query 驗證 Phase 1 用 POST /v1/query，
// 而不是只回 {id, modified} 的 querybatch（規劃 §2.1）。
func TestClientQueryUsesPostV1Query(t *testing.T) {
	var gotPath, gotMethod, gotUA, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotUA = r.URL.Path, r.Method, r.Header.Get("User-Agent")
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(loadFixture(t, filepath.Join("osv", "pypi_urllib3_1.26.5.json")))
	}))
	defer srv.Close()

	h, err := httpx.New(httpx.Options{
		UserAgent: "vulnwatch/test",
		CacheDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}

	advs, err := New(h, srv.URL).Query(context.Background(), model.EcosystemPyPI, "urllib3", "1.26.5")
	if err != nil {
		t.Fatalf("Query 失敗: %v", err)
	}
	if len(advs) != 2 {
		t.Fatalf("取得 %d 筆 advisory，預期 2", len(advs))
	}
	if gotMethod != http.MethodPost {
		t.Errorf("HTTP method = %q，預期 POST", gotMethod)
	}
	if gotPath != "/v1/query" {
		t.Errorf("路徑 = %q，預期 /v1/query（不可用 querybatch）", gotPath)
	}
	if gotUA != "vulnwatch/test" {
		t.Errorf("User-Agent = %q，預期 vulnwatch/test", gotUA)
	}
	var req queryRequest
	if err := json.Unmarshal([]byte(gotBody), &req); err != nil {
		t.Fatalf("request body 不是合法 JSON: %v (%q)", err, gotBody)
	}
	if req.Version != "1.26.5" || req.Package == nil ||
		req.Package.Ecosystem != model.EcosystemPyPI || req.Package.Name != "urllib3" {
		t.Errorf("request body = %+v，預期帶 package + version", req)
	}
}

// TestClientQuerySkipsWithdrawn 驗證已撤回的 advisory 不會提醒使用者。
func TestClientQuerySkipsWithdrawn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulns":[
			{"id":"GHSA-live"},
			{"id":"GHSA-withdrawn","withdrawn":"2024-01-01T00:00:00Z"}
		]}`))
	}))
	defer srv.Close()

	h, _ := httpx.New(httpx.Options{CacheDir: t.TempDir()})
	advs, err := New(h, srv.URL).Query(context.Background(), model.EcosystemPyPI, "x", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || advs[0].ID != "GHSA-live" {
		t.Fatalf("advisories = %+v，預期只留 GHSA-live", advs)
	}
}

// TestClientQueryEmptyResponse 驗證 {} 的空結果（規劃 §11：OSV 查無資料時回 {}）。
func TestClientQueryEmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(loadFixture(t, filepath.Join("osv", "empty.json")))
	}))
	defer srv.Close()

	h, _ := httpx.New(httpx.Options{CacheDir: t.TempDir()})
	advs, err := New(h, srv.URL).Query(context.Background(), model.EcosystemCrates, "std", "1.82.0")
	if err != nil {
		t.Fatalf("空結果不該是錯誤: %v", err)
	}
	if len(advs) != 0 {
		t.Fatalf("advisories = %+v，預期空", advs)
	}
}

func TestPrimaryReferencesPrefersAdvisory(t *testing.T) {
	adv := Advisory{References: []Reference{
		{Type: "WEB", URL: "https://example.com/web"},
		{Type: "ADVISORY", URL: "https://example.com/advisory"},
		{Type: "", URL: ""},
	}}
	refs := PrimaryReferences(adv, 3)
	if len(refs) != 2 || refs[0] != "https://example.com/advisory" {
		t.Fatalf("PrimaryReferences = %v，預期 ADVISORY 優先且略過空 URL", refs)
	}
}

// TestResolveSeverityQualitativeWithExtraFields 是回歸測試：
// database_specific 裡除了 severity 以外還有別的欄位（GHSA 幾乎一定有
// github_reviewed: true、cwe_ids 等）時，第 2 層質性等級回退仍必須生效。
//
// 曾經的 bug：databaseSpecific 把 github_reviewed 宣告成 string，
// 但它實際是 bool，json.Unmarshal 會回傳 UnmarshalTypeError，
// 導致整個 database_specific 被當成無法解析 —— 凡是沒有 CVSS_V3 的
// GHSA 都會silently 掉到 UNKNOWN。
func TestResolveSeverityQualitativeWithExtraFields(t *testing.T) {
	adv := Advisory{
		ID: "GHSA-with-extra-fields",
		DatabaseSpecific: json.RawMessage(`{
			"cwe_ids": ["CWE-200"],
			"severity": "MODERATE",
			"github_reviewed": true,
			"github_reviewed_at": "2024-06-17T18:30:21Z",
			"nvd_published_at": null
		}`),
	}
	sev := ResolveSeverity(adv)
	if sev.Level != model.LevelMedium {
		t.Fatalf("Severity.Level = %v，預期 MEDIUM（database_specific 有其他欄位時，"+
			"第 2 層回退仍必須生效）", sev.Level)
	}
	if sev.Source != model.SevSourceGHSA {
		t.Errorf("Severity.Source = %q，預期 %q", sev.Source, model.SevSourceGHSA)
	}
}

// TestResolveSeverityQualitativeFromRealFixtureShape 用與 testdata 相同的
// database_specific 形狀驗證（fixture 裡就帶著 github_reviewed）。
func TestResolveSeverityQualitativeFromRealFixtureShape(t *testing.T) {
	advs := loadAdvisories(t, filepath.Join("osv", "pypi_urllib3_1.26.5.json"))
	adv := findAdvisory(t, advs, "GHSA-34jh-p97f-mpxf")

	// 把 CVSS_V3 拿掉，強迫走第 2 層
	var kept []Severity
	for _, s := range adv.Severity {
		if !strings.EqualFold(s.Type, "CVSS_V3") {
			kept = append(kept, s)
		}
	}
	adv.Severity = kept

	sev := ResolveSeverity(adv)
	if sev.Level != model.LevelMedium {
		t.Fatalf("Severity.Level = %v，預期 MEDIUM（fixture 的 database_specific 是 "+
			"{\"severity\":\"MODERATE\",\"github_reviewed\":true}）", sev.Level)
	}
	if sev.Source != model.SevSourceGHSA {
		t.Errorf("Severity.Source = %q，預期 %q", sev.Source, model.SevSourceGHSA)
	}
	// 只剩 CVSS_V4 時，vector 原文仍要保留但不算分數
	if sev.HasScore {
		t.Error("只有 CVSS_V4 時不可算分數")
	}
	if sev.VectorType != "CVSS_V4" || sev.Vector == "" {
		t.Errorf("CVSS_V4 的 vector 原文應保留：%+v", sev)
	}
}

// TestSelectFixCandidatesNoteIsAccurate 是回歸測試：
// Go / PyPI 有版本比較器，若回到「多個候選」是因為 ranges 沒有包含目前版本的
// 區間（或版本字串無法解析），報表**不可**說成「未做版本比較」—— 那是在說謊，
// 會讓使用者以為本工具對 Go 不支援版本比較。
func TestSelectFixCandidatesNoteIsAccurate(t *testing.T) {
	// stdlib 的 advisory 只涵蓋 1.21.x 與 1.22.x，拿 1.25.4 去比會找不到區間。
	advs := loadAdvisories(t, filepath.Join("osv", "go_stdlib_v1.21.0.json"))
	adv := advs[0]

	fix := SelectFix(adv, model.EcosystemGo, "stdlib", "v1.25.4", model.ComparerFor(model.EcosystemGo))
	if fix.Kind != model.FixKindCandidates {
		t.Fatalf("Fix.Kind = %q，預期 candidates", fix.Kind)
	}
	disp := fix.Display()
	if strings.Contains(disp, "未做版本比較") {
		t.Errorf("Fix.Display() = %q —— Go 有版本比較器，不可說成「未做版本比較」", disp)
	}
	if !strings.Contains(disp, "沒有包含目前版本的區間") {
		t.Errorf("Fix.Display() = %q，應說明真正的原因", disp)
	}

	// Maven 的情況才該說「不做版本比較」
	mavenAdvs := loadAdvisories(t, filepath.Join("osv", "maven_log4j_2.14.1.json"))
	mavenFix := SelectFix(mavenAdvs[0], model.EcosystemMaven,
		"org.apache.logging.log4j:log4j-core", "2.14.1", nil)
	if !strings.Contains(mavenFix.Display(), "不做版本比較") {
		t.Errorf("Maven 的 Fix.Display() = %q，應說明不做版本比較", mavenFix.Display())
	}
}

func TestCVEAliasesOf(t *testing.T) {
	// 主 ID 本身是 CVE 時也要算進去
	got := CVEAliasesOf("CVE-2024-9287", []string{"GHSA-abcd-1234-efgh", "cve-2024-9287", "CVE-2024-0001"})
	if len(got) != 2 || got[0] != "CVE-2024-9287" || got[1] != "CVE-2024-0001" {
		t.Fatalf("CVEAliasesOf = %v，預期去重且略過 GHSA", got)
	}
	if n := len(CVEAliasesOf("GO-2024-2687", nil)); n != 0 {
		t.Errorf("沒有 CVE 別名時應回傳空，得到 %d 筆", n)
	}
}
