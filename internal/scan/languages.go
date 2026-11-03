package scan

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/elvis3434/vulnwatch/internal/httpx"
	"github.com/elvis3434/vulnwatch/internal/model"
	"github.com/elvis3434/vulnwatch/internal/source/osv"
)

// scanLanguages 掃描 [[languages]] 的程式語言執行環境。
//
// 規劃 §4 的主軸：報表以「目前版本 / 該版本線最新修補版 / 是否 EOL /
// 落後幾個 patch」為主要結論，CVE 清單為輔。
//
// 本階段的範圍：
//   - go：OSV 的 stdlib 與 toolchain（版本加 v 前綴，§4.1）+ endoflife.date
//   - python / rust：只查 endoflife.date。弱點清單是 Phase 2
//     （python 需要 §4.2 的 CPE 誤報後處理，rust 需要解析 RustSec advisory-db）
func (r *runner) scanLanguages(ctx context.Context, now time.Time) {
	if len(r.cfg.Languages) == 0 {
		return
	}

	r.eolStatus = model.SourceStatus{Name: EOLSourceName, Enabled: r.cfg.Sources.EOL, OK: true}
	if !r.cfg.Sources.EOL {
		r.eolStatus.Message = "[sources].eol = false，未查詢"
	}

	osvClient := osv.New(r.opt.HTTP, r.opt.OSVEndpoint)

	for _, lang := range r.cfg.Languages {
		spec, ok := model.Languages[lang.Name]
		if !ok {
			// 設定檔驗證已經攔掉不支援的語言，這裡只是防禦。
			continue
		}
		r.scanOneLanguage(ctx, osvClient, spec, lang.Version)
	}
}

func (r *runner) scanOneLanguage(ctx context.Context, osvClient *osv.Client, spec model.LanguageSpec, version string) {
	// ---- EOL / 版本落後狀態 ----
	status := model.LanguageStatus{
		Name:        spec.Name,
		Version:     version,
		ReleaseLine: majorMinor(version),
		EOL:         "unknown",
		VulnScanned: spec.VulnSupported,
	}

	if r.cfg.Sources.EOL && spec.EOLProduct != "" {
		resp, err := r.fetchEOL(ctx, spec.EOLProduct)
		r.eolStatus.Queries++
		switch {
		case err == nil:
			var warns []string
			status, warns = buildLanguageStatus(spec.Name, version, resp)
			status.VulnScanned = spec.VulnSupported
			for _, w := range warns {
				r.rep.AddProblem(model.ProblemWarning, EOLSourceName+" "+spec.Name, "%s", w)
			}
		case errors.Is(err, httpx.ErrOfflineMiss):
			r.rep.NoData = append(r.rep.NoData, model.NoDataItem{
				Target: model.Target{Kind: model.TargetKindLanguage, Ecosystem: model.EcosystemLanguage, Name: spec.Name, Version: version},
				Source: EOLSourceName,
				Reason: "--offline 且快取未命中，無法判斷是否 EOL 或落後幾個 patch",
			})
			status.Note = "offline 快取未命中，無 EOL 資料"
		default:
			r.eolStatus.Errors++
			r.eolStatus.OK = false
			r.rep.AddProblem(model.ProblemError, EOLSourceName+" "+spec.Name, "查詢 EOL 失敗：%v", err)
			status.Note = "EOL 查詢失敗，無法判斷版本落後狀態"
		}
	} else if !r.cfg.Sources.EOL {
		status.Note = "[sources].eol = false，未查詢 EOL"
	}

	// ---- 執行環境的弱點清單 ----
	if !spec.VulnSupported {
		if spec.PendingNote != "" {
			r.rep.AddProblem(model.ProblemWarning, spec.Name+" "+version, "%s", spec.PendingNote)
			if status.Note == "" {
				status.Note = spec.PendingNote
			}
		}
	} else if r.cfg.Sources.OSV && spec.OSVEcosystem != "" {
		r.scanLanguageVulns(ctx, osvClient, spec, version)
	}

	r.mu.Lock()
	r.rep.Languages = append(r.rep.Languages, status)
	r.mu.Unlock()
}

// scanLanguageVulns 用 OSV 查語言執行環境的弱點。
// 規劃 §4.1：Go 要查 stdlib 與 toolchain 兩個 package，版本需轉成 v1.27.3 形式。
// 這些 advisory 的 severity 一律是 null，依 §3.2 會以 UNKNOWN 進入報表的
// 獨立區塊，不可被 min_severity 濾掉。
func (r *runner) scanLanguageVulns(ctx context.Context, client *osv.Client, spec model.LanguageSpec, version string) {
	osvVersion := version
	if spec.OSVEcosystem == model.EcosystemGo {
		osvVersion = model.EnsureGoVersionPrefix(version)
	}

	sem := make(chan struct{}, r.opt.Concurrency)
	var wg sync.WaitGroup

	for _, pkg := range spec.OSVPackages {
		wg.Add(1)
		go func(pkg string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}
			r.queryOne(ctx, client, model.Target{
				Kind:      model.TargetKindLanguage,
				Ecosystem: spec.OSVEcosystem,
				Name:      pkg,
				Version:   osvVersion,
				Note:      spec.Name + " 執行環境",
			})
		}(pkg)
	}
	wg.Wait()
}
