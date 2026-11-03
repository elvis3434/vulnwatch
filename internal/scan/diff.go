package scan

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/elvis3434/vulnwatch/internal/model"
	"github.com/elvis3434/vulnwatch/internal/report"
)

// NEW 標記規則（規劃 §5.1，刻意避免假陽性）：
//
//   - JSON 中記錄每個來源的成功/失敗狀態。
//   - diff 時，上次失敗的來源所涵蓋的項目不參與 NEW 判定，標為「無法判定是否新增」。
//   - 比對基準優先選最近一次「全來源成功」的 JSON；若沒有，用最近一次並套用上一條。
//   - NEW 的 key = (ecosystem, name, 弱點主 ID)，不含版本 —— 否則使用者升版後，
//     舊弱點會重新被標成 NEW。

// loadBaseline 找出這次 NEW 判定要用的比對基準。
// 回傳 nil 表示沒有可用的基準（例如首次執行）。
func loadBaseline(reportDir string) (*model.Report, *model.BaselineInfo) {
	names, err := report.ReportDirs(reportDir)
	if err != nil || len(names) == 0 {
		return nil, &model.BaselineInfo{Note: "首次執行，沒有可比對的舊報表"}
	}

	var (
		newest     *model.Report
		newestName string
	)
	for _, name := range names {
		p := filepath.Join(reportDir, name, "report.json")
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		rep, err := report.UnmarshalJSON(raw)
		if err != nil {
			continue
		}
		if newest == nil {
			newest, newestName = rep, name
		}
		// 優先選最近一次「全來源成功」的
		if rep.Summary.AllSourcesOK {
			return rep, &model.BaselineInfo{
				Path:         filepath.Join(name, "report.json"),
				GeneratedAt:  rep.GeneratedAt.Format("2006-01-02 15:04:05 -07:00"),
				AllSourcesOK: true,
			}
		}
	}

	if newest == nil {
		return nil, &model.BaselineInfo{Note: "找不到可讀取的舊報表 JSON，無法判定是否新增"}
	}
	return newest, &model.BaselineInfo{
		Path:         filepath.Join(newestName, "report.json"),
		GeneratedAt:  newest.GeneratedAt.Format("2006-01-02 15:04:05 -07:00"),
		AllSourcesOK: false,
		Note:         "沒有「全來源成功」的舊報表，改用最近一次；該次失敗的來源所涵蓋的項目標為「無法判定」",
	}
}

// applyNewState 設定每個項目的 NEW 狀態。必須在 classify 之後、fillSummary 之前執行。
func (r *runner) applyNewState() {
	baseline, info := loadBaseline(r.cfg.General.ReportDir)
	r.rep.Baseline = info

	if baseline == nil {
		// 沒有基準 → 全部標為「無法判定是否新增」。
		// 刻意不標成「否」也不標成「是」：前者會讓第一次執行完全看不出有東西，
		// 後者會讓第一次執行滿版都是 NEW。
		r.forEachFinding(func(f *model.Finding) { f.New = model.NewStateUndetermined })
		return
	}

	seen := map[string]bool{}
	for _, f := range baseline.AllFindings() {
		seen[f.DiffKey()] = true
	}

	r.forEachFinding(func(f *model.Finding) {
		switch {
		case seen[f.DiffKey()]:
			f.New = model.NewStateNo
		case !baselineCovers(baseline, f.Source):
			// 上次這個來源失敗（或根本沒有紀錄）→ 不參與 NEW 判定。
			f.New = model.NewStateUndetermined
		default:
			f.New = model.NewStateYes
		}
	})
}

// baselineCovers 回傳基準報表是否可信地涵蓋了這個來源。
func baselineCovers(baseline *model.Report, source string) bool {
	if strings.TrimSpace(source) == "" {
		return false
	}
	if !baseline.HasSource(source) {
		// 舊報表沒有這個來源的紀錄（例如當時還沒實作）→ 當成未涵蓋。
		return false
	}
	return baseline.SourceOK(source)
}

// forEachFinding 走訪報表所有分類中的項目（就地修改）。
func (r *runner) forEachFinding(fn func(*model.Finding)) {
	for _, list := range [][]model.Finding{
		r.rep.Findings, r.rep.Unknown, r.rep.Filtered, r.rep.Ignored,
	} {
		for i := range list {
			fn(&list[i])
		}
	}
}
