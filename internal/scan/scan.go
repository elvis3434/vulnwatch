// Package scan 負責調度：併發查詢各來源、合併去重、分類、與上次結果比對。
package scan

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/elvis3434/vulnwatch/internal/config"
	"github.com/elvis3434/vulnwatch/internal/httpx"
	"github.com/elvis3434/vulnwatch/internal/model"
	"github.com/elvis3434/vulnwatch/internal/source/osv"
)

// DefaultConcurrency 是 OSV 查詢的併發數。
// 規劃 §11 最後一項：無金鑰下的併發容忍度未實測，先保守用 5。
const DefaultConcurrency = 5

// Options 是一次掃描的參數。
type Options struct {
	Config      *config.Config
	HTTP        *httpx.Client
	ToolVersion string
	// Now 是這次掃描的時間；留零值則用 time.Now()。
	Now time.Time
	// Concurrency 為 0 時用 DefaultConcurrency。
	Concurrency int
	// Logf 為 nil 時不輸出。
	Logf func(format string, args ...any)

	// 以下 endpoint 只給測試覆寫，正式執行留空用各來源的預設值。
	OSVEndpoint string
	EOLEndpoint string
	NVDEndpoint string
	// NVDAPIKey 來自環境變數 VULNWATCH_NVD_API_KEY。
	NVDAPIKey string
	// NVDLookupBudget 是這次執行最多向 NVD 補幾筆分數（規劃 §3.2 第 3 層
	// 「只在額度允許時做」）。0 表示用預設值。
	NVDLookupBudget int
}

type runner struct {
	opt Options
	rep *model.Report
	cfg *config.Config

	mu       sync.Mutex
	findings []model.Finding

	osvStatus model.SourceStatus
	eolStatus model.SourceStatus
	nvdStatus model.SourceStatus
}

func (r *runner) logf(format string, args ...any) {
	if r.opt.Logf != nil {
		r.opt.Logf(format, args...)
	}
}

// Run 執行一次完整掃描並回傳報表。
//
// 回傳 error 只代表「連報表都做不出來」的致命錯誤；單一來源失敗會記在
// 報表的 Sources 與 Problems 裡，其餘照常產出（規劃 §9）。
func Run(ctx context.Context, opt Options) (*model.Report, error) {
	if opt.Config == nil {
		return nil, errors.New("scan.Run: 缺少設定檔")
	}
	if opt.HTTP == nil {
		return nil, errors.New("scan.Run: 缺少 HTTP 客戶端")
	}
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = DefaultConcurrency
	}

	cfg := opt.Config
	loc := cfg.Location
	if loc == nil {
		loc = time.Local
	}

	r := &runner{
		opt: opt,
		cfg: cfg,
		rep: &model.Report{
			Tool:          "vulnwatch",
			ToolVersion:   opt.ToolVersion,
			SchemaVersion: model.SchemaVersion,
			GeneratedAt:   now.In(loc),
			Timezone:      cfg.General.Timezone,
			ConfigPath:    cfg.Path,
			Offline:       opt.HTTP.Offline(),
			MinSeverity:   cfg.MinLevel.String(),
			FailOn:        thresholdString(cfg),
		},
	}

	// 設定檔的警告必須進報表的「錯誤 / 警告」區，不可靜默忽略（規劃 §3.4）。
	for _, w := range cfg.SortedWarnings() {
		r.rep.AddProblem(model.ProblemWarning, w.String(), "設定檔警告")
	}

	r.scanPackages(ctx)
	r.scanLanguages(ctx, now)
	r.fillSeverityFromNVD(ctx)

	r.rep.Sources = r.sourceStatuses()
	r.classify(now)
	// NEW 判定必須在 classify 之後（項目已分類）、fillSummary 之前（要統計 NEW 數）。
	r.applyNewState()
	r.rep.Limitations = r.limitations()
	r.fillSummary()

	return r.rep, nil
}

func thresholdString(cfg *config.Config) string {
	if !cfg.FailOnSet {
		return ""
	}
	return cfg.FailOnLevel.String()
}

// scanPackages 用 OSV 查詢所有 [[packages]]。
func (r *runner) scanPackages(ctx context.Context) {
	targets := r.cfg.Targets()
	r.osvStatus = model.SourceStatus{Name: osv.SourceName, Enabled: r.cfg.Sources.OSV, OK: true}

	if !r.cfg.Sources.OSV {
		r.osvStatus.Message = "[sources].osv = false，未查詢"
		return
	}
	if len(targets) == 0 {
		return
	}

	client := osv.New(r.opt.HTTP, r.opt.OSVEndpoint)
	sem := make(chan struct{}, r.opt.Concurrency)
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		go func(t model.Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}
			r.queryOne(ctx, client, t)
		}(t)
	}
	wg.Wait()
}

// queryOne 查一個對象，並把結果轉成 Finding。
func (r *runner) queryOne(ctx context.Context, client *osv.Client, t model.Target) {
	r.logf("查詢 OSV：%s", t.Label())

	advs, err := client.Query(ctx, t.Ecosystem, t.Name, t.Version)

	r.mu.Lock()
	r.osvStatus.Queries++
	r.mu.Unlock()

	if err != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		if errors.Is(err, httpx.ErrOfflineMiss) {
			// 規劃 §2.2：快取未命中的項目必須標示「無資料」，不可當成「無弱點」。
			r.rep.NoData = append(r.rep.NoData, model.NoDataItem{
				Target: t,
				Source: osv.SourceName,
				Reason: "--offline 且快取未命中，本次無法判斷是否有弱點",
			})
			r.rep.AddProblem(model.ProblemWarning, t.Label(), "offline 快取未命中，這個對象的結果缺漏")
			return
		}
		r.osvStatus.Errors++
		r.osvStatus.OK = false
		r.rep.NoData = append(r.rep.NoData, model.NoDataItem{
			Target: t,
			Source: osv.SourceName,
			Reason: "查詢失敗，本次無法判斷是否有弱點",
		})
		r.rep.AddProblem(model.ProblemError, t.Label(), "OSV 查詢失敗：%v", err)
		return
	}

	cmp := model.ComparerFor(t.Ecosystem)
	out := make([]model.Finding, 0, len(advs))
	for _, a := range advs {
		out = append(out, model.Finding{
			Target:     t,
			ID:         a.ID,
			Aliases:    a.Aliases,
			Summary:    a.Summary,
			Severity:   osv.ResolveSeverity(a),
			Fix:        osv.SelectFix(a, t.Ecosystem, t.Name, t.Version, cmp),
			References: osv.PrimaryReferences(a, 3),
			Source:     osv.SourceName,
			Modified:   a.Modified,
			New:        model.NewStateUndetermined,
		})
	}

	r.mu.Lock()
	r.findings = append(r.findings, out...)
	r.mu.Unlock()
}

// classify 把結果分成需處理清單、UNKNOWN 區塊、被濾掉的、以及被忽略的。
func (r *runner) classify(now time.Time) {
	// 去重：同一個對象的同一個 advisory 只留一筆。
	seen := map[string]bool{}
	uniq := make([]model.Finding, 0, len(r.findings))
	for _, f := range r.findings {
		key := f.Target.Key() + "|" + f.ID
		if seen[key] {
			continue
		}
		seen[key] = true
		uniq = append(uniq, f)
	}

	for _, f := range uniq {
		if ig, ok := r.matchIgnore(f, now); ok {
			f.Ignore = ig
			if !ig.Expired {
				r.rep.Ignored = append(r.rep.Ignored, f)
				continue
			}
			// 已過期的忽略：照常列入報表，並在項目上標示（規劃 §3.4）。
		}

		switch {
		case f.Severity.Level == model.LevelUnknown:
			// 硬規則：UNKNOWN 永不被 min_severity 濾掉（規劃 §3.2）。
			r.rep.Unknown = append(r.rep.Unknown, f)
		case f.Severity.Level >= r.cfg.MinLevel:
			r.rep.Findings = append(r.rep.Findings, f)
		default:
			r.rep.Filtered = append(r.rep.Filtered, f)
		}
	}

	model.SortFindings(r.rep.Findings)
	model.SortFindings(r.rep.Unknown)
	model.SortFindings(r.rep.Filtered)
	model.SortFindings(r.rep.Ignored)

	if r.rep.Findings == nil {
		r.rep.Findings = []model.Finding{}
	}
	if r.rep.Unknown == nil {
		r.rep.Unknown = []model.Finding{}
	}
	if r.rep.Filtered == nil {
		r.rep.Filtered = []model.Finding{}
	}
	if r.rep.Ignored == nil {
		r.rep.Ignored = []model.Finding{}
	}
}

func (r *runner) matchIgnore(f model.Finding, now time.Time) (*model.IgnoreState, bool) {
	for _, ig := range r.cfg.Ignore {
		if !ig.Matches(f.Target.Ecosystem, f.Target.Name, f.ID, f.Aliases) {
			continue
		}
		return &model.IgnoreState{
			ID:      ig.ID,
			Reason:  ig.Reason,
			Expires: ig.Expires,
			Expired: ig.Expired(now),
		}, true
	}
	return nil, false
}

func (r *runner) sourceStatuses() []model.SourceStatus {
	out := []model.SourceStatus{r.osvStatus}
	if r.eolStatus.Name != "" {
		out = append(out, r.eolStatus)
	}
	if r.nvdStatus.Name != "" {
		out = append(out, r.nvdStatus)
	}
	// Phase 2 才實作的來源也列出來，讓使用者知道這次沒有查
	// （規劃 §5：摘要要有每個資料來源的成功/失敗狀態）。
	for _, p := range []struct {
		name    string
		enabled bool
	}{
		{"RustSec", r.cfg.Sources.RustSec},
		{"deps.dev", r.cfg.Sources.DepsDev},
		{"KEV", r.cfg.Sources.KEV},
		{"EPSS", r.cfg.Sources.EPSS},
	} {
		out = append(out, model.SourceStatus{
			Name:    p.name,
			Enabled: p.enabled,
			OK:      true,
			Message: "Phase 2 才實作，本次未查詢",
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (r *runner) limitations() []string {
	lim := []string{
		"各弱點資料庫的覆蓋範圍不同，本報表不保證弱點清單完整。",
		"UNKNOWN（無嚴重度評級）區塊不受 min_severity 影響，請務必一併檢視。",
		"Maven / NuGet 不做版本比較，「最低安全版本」會列出全部候選，請自行確認對應的版本線。",
		"crates.io / npm 的版本比較是 Phase 2 功能，目前同樣只列候選。",
		"只有 CVSS_V4 評分的項目不計算分數，只顯示 vector 原文。",
		"KEV（是否已遭實際利用）、EPSS（被利用機率）與 deps.dev（最新版本）是 Phase 2 功能，本次未查詢。",
	}

	// 語言執行環境的階段性限制
	for _, lang := range r.cfg.Languages {
		if spec, ok := model.Languages[lang.Name]; ok && !spec.VulnSupported {
			lim = append(lim, spec.Name+"：只輸出 EOL 與版本落後狀態，弱點清單是 Phase 2 功能。")
		}
	}
	if r.nvdStatus.Enabled && r.nvdStatus.Queries > 0 {
		lim = append(lim,
			"NVD 補分數使用的 CVSS 欄位路徑尚未以真實請求驗證過（見 docs/decisions.md §0 / §6），"+
				"第一次在真實網路上執行時請人工核對一次。")
	}
	if r.rep.Offline {
		lim = append(lim, "本次以 --offline 執行，只使用快取；「無資料」區塊的對象這次完全沒有被檢查。")
	}
	return lim
}

func (r *runner) fillSummary() {
	s := model.Summary{ByLevel: map[string]int{}}
	for _, lang := range r.rep.Languages {
		_ = lang
		s.Languages++
	}
	s.Packages = len(r.cfg.Packages)
	s.Targets = s.Packages + s.Languages

	all := r.rep.AllFindings()
	s.TotalFindings = len(all)
	for _, f := range all {
		s.ByLevel[f.Severity.Level.String()]++
		if f.KEV {
			s.KEVCount++
		}
		switch f.New {
		case model.NewStateYes:
			s.NewCount++
		case model.NewStateUndetermined:
			s.NewUndetermined++
		}
	}
	s.UnknownCount = len(r.rep.Unknown)
	s.FilteredCount = len(r.rep.Filtered)
	s.IgnoredCount = len(r.rep.Ignored)

	s.AllSourcesOK = true
	for _, src := range r.rep.Sources {
		if src.Enabled && !src.OK {
			s.AllSourcesOK = false
		}
	}
	// --offline 快取未命中也算結果不完整，否則下次會把這些項目誤判成 NEW。
	if len(r.rep.NoData) > 0 {
		s.AllSourcesOK = false
	}
	r.rep.Summary = s
}

// FailOnTriggered 判斷是否有達到 fail_on 門檻的弱點（exit code 1）。
// UNKNOWN 不參與 fail_on 判定：它沒有分數，無法與門檻比較。
func FailOnTriggered(rep *model.Report, cfg *config.Config) (bool, int) {
	if !cfg.FailOnSet {
		return false, 0
	}
	n := 0
	for _, f := range rep.Findings {
		if f.Severity.Level >= cfg.FailOnLevel {
			n++
		}
	}
	return n > 0, n
}

// ResultLine 是 log 檔第一行要寫的結論（規劃 §8：設了 fail_on 之後，
// log 第一行必須寫清楚，例如 "RESULT: 3 findings >= HIGH (exit 1)"）。
func ResultLine(rep *model.Report, cfg *config.Config, exitCode int) string {
	if cfg.FailOnSet {
		_, n := FailOnTriggered(rep, cfg)
		return fmt.Sprintf("RESULT: %d findings >= %s (exit %d)", n, cfg.FailOnLevel.String(), exitCode)
	}
	return fmt.Sprintf("RESULT: %d findings, %d unknown-severity, fail_on 未設定 (exit %d)",
		len(rep.Findings), len(rep.Unknown), exitCode)
}
