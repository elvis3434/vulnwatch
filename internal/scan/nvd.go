package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/elvis3434/vulnwatch/internal/httpx"
	"github.com/elvis3434/vulnwatch/internal/model"
	"github.com/elvis3434/vulnwatch/internal/source/osv"
)

// NVD API 2.0 客戶端，只用來實作規劃 §3.2 嚴重度回退的**第 3 層**：
// 拿 aliases 中的 CVE 去 NVD 查 CVSS 分數，補上 OSV 沒給分數的項目
// （主要是 Go 官方 advisory，它們的 severity 一律是 null）。
//
// 本階段刻意**不**做 §4.2 的 python CPE 比對（誤報嚴重，需要 configurations
// 後處理），那是 Phase 2。
//
// 刻意放在 internal/scan 而不是另開 internal/source/nvd：
// 規劃 §6 要求 Phase 1 維持 6 個 package，詳見 docs/decisions.md §1。

const (
	// DefaultNVDEndpoint 是 NVD API 2.0 的根路徑。
	DefaultNVDEndpoint = "https://services.nvd.nist.gov"
	// NVDSourceName 是這個來源在報表中的名稱。
	NVDSourceName = "NVD"
	// 規劃 §3.2 第 3 層：「只在額度允許時做」。規劃沒有定義額度，
	// 這裡取的值見 docs/decisions.md §7。
	nvdBudgetNoKey   = 25
	nvdBudgetWithKey = 100
)

// nvdCVSSData 是 metrics 裡的 cvssData 物件。
//
// 注意：規劃 §11 把「NVD 回應中的 CVSS 區塊路徑」列為**實作時仍需確認**的項目，
// 而本次開發環境的網路政策封鎖了 services.nvd.nist.gov，無法實測確認。
// 這裡的路徑依 NVD API 2.0 的公開文件撰寫，並刻意寫得寬容：
// 讀不到就讓項目保持 UNKNOWN 並在報表留警告，不會靜默失敗。
// 詳見 docs/decisions.md §0 與 §6。
type nvdCVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdMetric struct {
	Source   string      `json:"source"`
	Type     string      `json:"type"`
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID      string `json:"id"`
			Metrics struct {
				CVSSMetricV31 []nvdMetric `json:"cvssMetricV31"`
				CVSSMetricV30 []nvdMetric `json:"cvssMetricV30"`
				CVSSMetricV40 []nvdMetric `json:"cvssMetricV40"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// pickMetric 取一筆 metric：type == "Primary" 優先，否則取第一筆。
func pickMetric(list []nvdMetric) (nvdMetric, bool) {
	if len(list) == 0 {
		return nvdMetric{}, false
	}
	for _, m := range list {
		if strings.EqualFold(m.Type, "Primary") {
			return m, true
		}
	}
	return list[0], true
}

// severityFromNVD 由 NVD 回應取出嚴重度。
// 回傳 ok=false 表示回應裡找不到可用的 CVSS 資料。
func severityFromNVD(resp *nvdResponse, cveID string) (model.Severity, bool) {
	for _, v := range resp.Vulnerabilities {
		if !strings.EqualFold(v.CVE.ID, cveID) {
			continue
		}
		m := v.CVE.Metrics

		// v3.1 優先，其次 v3.0：兩者都有 base score 可用。
		for _, list := range [][]nvdMetric{m.CVSSMetricV31, m.CVSSMetricV30} {
			metric, ok := pickMetric(list)
			if !ok {
				continue
			}
			d := metric.CVSSData
			if d.BaseScore > 0 {
				return model.Severity{
					Level:      model.LevelFromScore(d.BaseScore),
					Score:      d.BaseScore,
					HasScore:   true,
					Source:     model.SevSourceNVD,
					Vector:     d.VectorString,
					VectorType: "CVSS_V3",
				}, true
			}
			// baseScore 缺漏時退而用質性等級（只有等級，沒有分數）。
			if lvl, ok := model.ParseLevel(d.BaseSeverity); ok && lvl != model.LevelUnknown {
				return model.Severity{
					Level:  lvl,
					Source: model.SevSourceNVD,
					Vector: d.VectorString,
				}, true
			}
		}

		// 只有 v4 時不算分數（規劃 §3.2），只取質性等級。
		if metric, ok := pickMetric(m.CVSSMetricV40); ok {
			d := metric.CVSSData
			if lvl, ok := model.ParseLevel(d.BaseSeverity); ok && lvl != model.LevelUnknown {
				return model.Severity{
					Level:      lvl,
					Source:     model.SevSourceNVD,
					Vector:     d.VectorString,
					VectorType: "CVSS_V4",
				}, true
			}
		}
		return model.Severity{}, false
	}
	return model.Severity{}, false
}

// ErrNoCVSSInNVD 表示 NVD 的回應讀得到，但裡面沒有這筆 CVE 的 CVSS 資料。
//
// 這不是「來源失敗」，而是資料缺口：很多 CVE 本來就還沒有 NVD 評分。
// 如果把它當成來源失敗，AllSourcesOK 幾乎永遠是 false，那麼 §5.1 的
// 「優先選最近一次全來源成功的報表當基準」就永遠選不到基準，
// 所有項目會一直停在「無法判定是否新增」。
var ErrNoCVSSInNVD = errors.New("NVD 回應中沒有這筆 CVE 的 CVSS 資料")

// lookupCVE 查一個 CVE 的嚴重度。
func (r *runner) lookupCVE(ctx context.Context, cveID string) (model.Severity, error) {
	endpoint := r.opt.NVDEndpoint
	if endpoint == "" {
		endpoint = DefaultNVDEndpoint
	}
	url := strings.TrimRight(endpoint, "/") + "/rest/json/cves/2.0?cveId=" + cveID

	req := httpx.Request{
		Method: http.MethodGet,
		URL:    url,
		// advisory 內容幾乎不變，用長效快取（規劃 §2.2 第二層）。
		CacheKey: httpx.NamedCacheKey("nvd-cve:" + cveID),
		CacheTTL: httpx.LongCacheTTL,
	}
	if r.opt.NVDAPIKey != "" {
		req.Header = map[string]string{"apiKey": r.opt.NVDAPIKey}
	}

	resp, err := r.opt.HTTP.Do(ctx, req)
	if err != nil {
		return model.Severity{}, err
	}

	var out nvdResponse
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return model.Severity{}, fmt.Errorf("NVD 回應不是合法的 JSON（%s）: %w", cveID, err)
	}
	sev, ok := severityFromNVD(&out, cveID)
	if !ok {
		return model.Severity{}, fmt.Errorf("%w：%s（totalResults=%d）",
			ErrNoCVSSInNVD, cveID, out.TotalResults)
	}
	return sev, nil
}

// fillSeverityFromNVD 實作規劃 §3.2 的第 3 層回退。
// 必須在 classify 之前執行，否則補上的分數不會影響分類。
func (r *runner) fillSeverityFromNVD(ctx context.Context) {
	r.nvdStatus = model.SourceStatus{Name: NVDSourceName, Enabled: r.cfg.Sources.NVD, OK: true}
	if !r.cfg.Sources.NVD {
		r.nvdStatus.Message = "[sources].nvd = false，未用 alias CVE 補分數"
		return
	}

	budget := r.opt.NVDLookupBudget
	if budget <= 0 {
		budget = nvdBudgetNoKey
		if r.opt.NVDAPIKey != "" {
			budget = nvdBudgetWithKey
		}
	}

	// 收集需要補分數的 CVE：只處理 UNKNOWN 的項目。
	need := map[string][]int{}
	for i := range r.findings {
		f := &r.findings[i]
		if f.Severity.Level != model.LevelUnknown {
			continue
		}
		for _, cve := range osv.CVEAliases(osv.Advisory{ID: f.ID, Aliases: f.Aliases}) {
			need[cve] = append(need[cve], i)
		}
	}
	if len(need) == 0 {
		r.nvdStatus.Message = "沒有需要補分數的項目"
		return
	}

	cves := make([]string, 0, len(need))
	for cve := range need {
		cves = append(cves, cve)
	}
	// 排序讓每次執行的查詢順序一致（也讓額度用在同一批項目上）。
	sort.Strings(cves)

	truncated := 0
	if len(cves) > budget {
		truncated = len(cves) - budget
		cves = cves[:budget]
	}

	// NVD 的 per-host 限流是序列化 + 間隔，所以這裡不需要自己做併發控制。
	for _, cve := range cves {
		if ctx.Err() != nil {
			break
		}
		r.nvdStatus.Queries++
		sev, err := r.lookupCVE(ctx, cve)
		if err != nil {
			r.nvdStatus.Errors++
			switch {
			case errors.Is(err, httpx.ErrOfflineMiss):
				r.rep.AddProblem(model.ProblemWarning, NVDSourceName+" "+cve,
					"offline 快取未命中，這筆弱點維持無嚴重度評級")
			case errors.Is(err, ErrNoCVSSInNVD):
				// 資料缺口，不是來源失敗（見 ErrNoCVSSInNVD 的說明）。
				r.rep.AddProblem(model.ProblemWarning, NVDSourceName+" "+cve,
					"NVD 沒有這筆 CVE 的 CVSS 資料，維持無嚴重度評級：%v", err)
			default:
				r.nvdStatus.OK = false
				r.rep.AddProblem(model.ProblemWarning, NVDSourceName+" "+cve,
					"無法補上嚴重度分數：%v", err)
			}
			continue
		}
		for _, idx := range need[cve] {
			// 只覆寫仍然是 UNKNOWN 的項目（同一筆可能有多個 CVE alias）。
			if r.findings[idx].Severity.Level == model.LevelUnknown {
				vector := r.findings[idx].Severity.Vector
				r.findings[idx].Severity = sev
				// OSV 原本給的 CVSS_V4 vector 若存在就保留下來顯示。
				if sev.Vector == "" && vector != "" {
					r.findings[idx].Severity.Vector = vector
				}
			}
		}
		r.logf("NVD 補上 %s 的嚴重度：%s", cve, sev.Display())
	}

	if r.nvdStatus.Errors > 0 && r.nvdStatus.OK && r.nvdStatus.Message == "" {
		r.nvdStatus.Message = fmt.Sprintf("%d 筆 CVE 在 NVD 沒有 CVSS 資料（維持無嚴重度評級）", r.nvdStatus.Errors)
	}
	if truncated > 0 {
		r.nvdStatus.Message = fmt.Sprintf("已達本次查詢上限 %d 筆，另有 %d 筆 CVE 未查（維持無嚴重度評級）",
			budget, truncated)
		r.rep.AddProblem(model.ProblemWarning, NVDSourceName, "%s", r.nvdStatus.Message)
	}
}
