package report

import (
	"fmt"
	"strings"

	"github.com/elvis3434/vulnwatch/internal/model"
)

// Markdown 產生 Markdown 報表。區塊順序照規劃 §5：
//  1. 摘要（含各資料來源成功/失敗狀態）
//  2. 需處理清單
//  3. 無嚴重度評級（UNKNOWN）獨立區塊 —— 不是次要區塊，放在醒目位置
//  4. 語言執行環境狀態
//  5. 參考（可能誤報）—— Phase 2
//  6. 已忽略項目
//  7. 錯誤 / 警告
func Markdown(rep *model.Report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# vulnwatch 弱點報表\n\n")
	writeSummary(&b, rep)
	writeFindings(&b, rep)
	writeUnknown(&b, rep)
	writeLanguages(&b, rep)
	writeNoData(&b, rep)
	writeFiltered(&b, rep)
	writeIgnored(&b, rep)
	writeProblems(&b, rep)
	writeLimitations(&b, rep)

	return b.String()
}

func writeSummary(b *strings.Builder, rep *model.Report) {
	fmt.Fprintf(b, "## 1. 摘要\n\n")
	fmt.Fprintf(b, "| 項目 | 內容 |\n|---|---|\n")
	fmt.Fprintf(b, "| 掃描時間 | %s |\n", rep.GeneratedAt.Format("2006-01-02 15:04:05 -07:00"))
	if rep.Timezone != "" {
		fmt.Fprintf(b, "| 時區 | %s |\n", rep.Timezone)
	}
	fmt.Fprintf(b, "| 工具版本 | %s |\n", orDash(rep.ToolVersion))
	if rep.ConfigPath != "" {
		fmt.Fprintf(b, "| 設定檔 | `%s` |\n", rep.ConfigPath)
	}
	fmt.Fprintf(b, "| 執行模式 | %s |\n", mode(rep))
	fmt.Fprintf(b, "| 掃描對象 | %d（套件 %d、語言 %d） |\n",
		rep.Summary.Targets, rep.Summary.Packages, rep.Summary.Languages)
	fmt.Fprintf(b, "| min_severity | %s |\n", orDash(rep.MinSeverity))
	fmt.Fprintf(b, "| fail_on | %s |\n", failOnText(rep))
	fmt.Fprintf(b, "| 需處理項目 | %d |\n", len(rep.Findings))
	fmt.Fprintf(b, "| 無嚴重度評級（UNKNOWN） | %d |\n", rep.Summary.UnknownCount)
	fmt.Fprintf(b, "| 低於 min_severity 被濾掉 | %d |\n", rep.Summary.FilteredCount)
	fmt.Fprintf(b, "| 本次新增（NEW） | %d |\n", rep.Summary.NewCount)
	fmt.Fprintf(b, "| 無法判定是否新增 | %d |\n", rep.Summary.NewUndetermined)
	fmt.Fprintf(b, "| 已忽略 | %d |\n", rep.Summary.IgnoredCount)
	fmt.Fprintf(b, "| KEV（已遭實際利用） | %d |\n", rep.Summary.KEVCount)
	fmt.Fprintf(b, "| 無資料對象 | %d |\n", len(rep.NoData))
	fmt.Fprintf(b, "\n")

	// 各嚴重度數量
	if len(rep.Summary.ByLevel) > 0 {
		levels := []string{
			model.LevelNameCritical, model.LevelNameHigh, model.LevelNameMedium,
			model.LevelNameLow, model.LevelNameUnknown,
		}
		var parts []string
		for _, l := range levels {
			if n := rep.Summary.ByLevel[l]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", l, n))
			}
		}
		if len(parts) > 0 {
			fmt.Fprintf(b, "各嚴重度數量（含被濾掉與已忽略）：%s\n\n", strings.Join(parts, "、"))
		}
	}

	// 規劃 §5：摘要必須包含每個資料來源的成功/失敗狀態。
	fmt.Fprintf(b, "### 資料來源狀態\n\n")
	fmt.Fprintf(b, "| 來源 | 啟用 | 結果 | 查詢次數 | 失敗次數 | 說明 |\n|---|---|---|---|---|---|\n")
	for _, s := range rep.Sources {
		fmt.Fprintf(b, "| %s | %s | %s | %d | %d | %s |\n",
			s.Name, yesNo(s.Enabled), sourceResult(s), s.Queries, s.Errors, orDash(s.Message))
	}
	fmt.Fprintf(b, "\n")

	if !rep.Summary.AllSourcesOK {
		fmt.Fprintf(b, "> **本次結果可能不完整**：有資料來源失敗或有對象無資料，"+
			"請看下方「錯誤 / 警告」與「無資料」區塊。\n\n")
	}

	if rep.Baseline != nil {
		fmt.Fprintf(b, "NEW 判定基準：%s\n\n", baselineText(rep.Baseline))
	}
}

func baselineText(bi *model.BaselineInfo) string {
	var parts []string
	if bi.Path != "" {
		parts = append(parts, "`"+bi.Path+"`")
	}
	if bi.GeneratedAt != "" {
		parts = append(parts, bi.GeneratedAt)
	}
	if bi.Path != "" {
		if bi.AllSourcesOK {
			parts = append(parts, "該次全來源成功")
		} else {
			parts = append(parts, "該次結果不完整，受影響的項目標為「無法判定」")
		}
	}
	if bi.Note != "" {
		parts = append(parts, bi.Note)
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "，")
}

func writeFindings(b *strings.Builder, rep *model.Report) {
	fmt.Fprintf(b, "## 2. 需處理清單\n\n")
	if len(rep.Findings) == 0 {
		fmt.Fprintf(b, "沒有達到 min_severity（%s）門檻的弱點。\n\n", orDash(rep.MinSeverity))
		fmt.Fprintf(b, "> 這不代表完全沒有風險：請一併看第 3 節的 UNKNOWN 區塊。\n\n")
		return
	}
	fmt.Fprintf(b, "依 KEV → 嚴重度 → EPSS 排序。\n\n")
	writeFindingTable(b, rep.Findings)
}

func writeUnknown(b *strings.Builder, rep *model.Report) {
	fmt.Fprintf(b, "## 3. 無嚴重度評級（UNKNOWN）\n\n")
	fmt.Fprintf(b, "**這個區塊不受 min_severity 影響，也不參與 fail_on 判定**"+
		"（沒有分數可與門檻比較）—— 不是次要區塊，請務必檢視。\n\n")
	fmt.Fprintf(b, "Go 官方 advisory（`GO-*`）與 RustSec 的項目本身沒有 CVSS 分數。"+
		"若 `[sources].nvd = true` 且能用 advisory 的 alias CVE 向 NVD 取到分數，"+
		"該項目會改以 NVD 的等級列在上面的需處理清單（來源欄位會顯示 `NVD`）；"+
		"取不到分數的才留在這裡。\n\n")
	if len(rep.Unknown) == 0 {
		fmt.Fprintf(b, "沒有無評級的弱點。\n\n")
		return
	}
	writeFindingTable(b, rep.Unknown)
}

func writeFindingTable(b *strings.Builder, fs []model.Finding) {
	fmt.Fprintf(b, "| | 對象 | 目前版本 | 弱點 ID | 嚴重度（來源） | 最低安全版本 | 摘要 |\n")
	fmt.Fprintf(b, "|---|---|---|---|---|---|---|\n")
	for _, f := range fs {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			flags(f),
			mdEscape(targetName(f.Target)),
			orDash(f.Target.Version),
			mdEscape(idWithAliases(f)),
			f.Severity.Display(),
			mdEscape(f.Fix.Display()),
			mdEscape(truncate(f.Summary, 110)),
		)
	}
	fmt.Fprintf(b, "\n")

	// 細節（參考連結、vector、note）放在表格後面，避免表格過寬。
	fmt.Fprintf(b, "<details>\n<summary>各項目細節</summary>\n\n")
	for _, f := range fs {
		fmt.Fprintf(b, "- **%s** — %s@%s\n", f.ID, targetName(f.Target), orDash(f.Target.Version))
		if f.Target.Note != "" {
			fmt.Fprintf(b, "  - 備註（設定檔）：%s\n", f.Target.Note)
		}
		if f.Summary != "" {
			fmt.Fprintf(b, "  - 摘要：%s\n", f.Summary)
		}
		if len(f.Aliases) > 0 {
			fmt.Fprintf(b, "  - 別名：%s\n", strings.Join(f.Aliases, "、"))
		}
		fmt.Fprintf(b, "  - 嚴重度：%s\n", f.Severity.Display())
		if f.Severity.Vector != "" {
			note := ""
			if f.Severity.VectorType == "CVSS_V4" {
				note = "（CVSS 4.0 不計算分數，只顯示 vector）"
			}
			fmt.Fprintf(b, "  - CVSS vector：`%s`%s\n", f.Severity.Vector, note)
		}
		fmt.Fprintf(b, "  - 最低安全版本：%s\n", f.Fix.Display())
		// Display() 在候選狀態下已經把 Note 寫進去了，不要重複印。
		if f.Fix.Note != "" && f.Fix.Kind != model.FixKindCandidates {
			fmt.Fprintf(b, "  - 版本判定說明：%s\n", f.Fix.Note)
		}
		if f.Ignore != nil && f.Ignore.Expired {
			fmt.Fprintf(b, "  - ⚠ 忽略已於 %s 到期，已重新列入報表\n", f.Ignore.Expires)
		}
		fmt.Fprintf(b, "  - NEW：%s\n", newText(f.New))
		if f.Source != "" {
			fmt.Fprintf(b, "  - 資料來源：%s\n", f.Source)
		}
		for _, ref := range f.References {
			fmt.Fprintf(b, "  - 參考：%s\n", ref)
		}
	}
	fmt.Fprintf(b, "\n</details>\n\n")
}

func writeLanguages(b *strings.Builder, rep *model.Report) {
	fmt.Fprintf(b, "## 4. 程式語言執行環境\n\n")
	if len(rep.Languages) == 0 {
		fmt.Fprintf(b, "設定檔沒有 `[[languages]]`，或這次沒有查到任何語言狀態。\n\n")
		return
	}
	fmt.Fprintf(b, "主要結論看「落後幾個 patch」與「是否 EOL」；"+
		"CVE 清單（若有）可能含誤報，請以版本落後狀態為主要判斷依據。\n\n")
	fmt.Fprintf(b, "| 語言 | 目前版本 | 版本線 | 該版本線最新 | 落後 patch | 是否 EOL | 建議版本 | 說明 |\n")
	fmt.Fprintf(b, "|---|---|---|---|---|---|---|---|\n")
	for _, l := range rep.Languages {
		behind := "—"
		if l.PatchesBehindKnown {
			behind = fmt.Sprintf("%d", l.PatchesBehind)
		}
		eol := l.EOL
		switch l.EOL {
		case "yes":
			eol = "**是**"
			if l.EOLFrom != "" {
				eol = fmt.Sprintf("**是**（自 %s）", l.EOLFrom)
			}
		case "no":
			eol = "否"
		default:
			eol = "不明"
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			l.Name, orDash(l.Version), orDash(l.ReleaseLine), orDash(l.LatestInLine),
			behind, eol, orDash(l.Recommended), orDash(l.Note))
	}
	fmt.Fprintf(b, "\n")
}

func writeNoData(b *strings.Builder, rep *model.Report) {
	if len(rep.NoData) == 0 {
		return
	}
	fmt.Fprintf(b, "## 4b. 無資料（**不等於沒有弱點**）\n\n")
	fmt.Fprintf(b, "以下對象這次沒有取得資料，所以**無法判斷**有沒有弱點：\n\n")
	fmt.Fprintf(b, "| 對象 | 來源 | 原因 |\n|---|---|---|\n")
	for _, n := range rep.NoData {
		fmt.Fprintf(b, "| %s | %s | %s |\n", mdEscape(n.Target.Label()), n.Source, mdEscape(n.Reason))
	}
	fmt.Fprintf(b, "\n")
}

func writeFiltered(b *strings.Builder, rep *model.Report) {
	if len(rep.Filtered) == 0 {
		return
	}
	fmt.Fprintf(b, "## 5. 低於 min_severity 的項目\n\n")
	fmt.Fprintf(b, "這些項目的嚴重度低於 `min_severity = %s`，列在這裡供參考。\n\n", orDash(rep.MinSeverity))
	fmt.Fprintf(b, "| 對象 | 弱點 ID | 嚴重度（來源） | 最低安全版本 |\n|---|---|---|---|\n")
	for _, f := range rep.Filtered {
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n",
			mdEscape(f.Target.Label()), mdEscape(f.ID), f.Severity.Display(), mdEscape(f.Fix.Display()))
	}
	fmt.Fprintf(b, "\n")
}

func writeIgnored(b *strings.Builder, rep *model.Report) {
	fmt.Fprintf(b, "## 6. 已忽略項目\n\n")
	if len(rep.Ignored) == 0 {
		fmt.Fprintf(b, "沒有被忽略的項目。\n\n")
		return
	}
	fmt.Fprintf(b, "| 對象 | 弱點 ID | 嚴重度 | 原因 | 到期日 |\n|---|---|---|---|---|\n")
	for _, f := range rep.Ignored {
		reason, expires := "—", "—"
		if f.Ignore != nil {
			reason = orDash(f.Ignore.Reason)
			expires = orDash(f.Ignore.Expires)
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n",
			mdEscape(f.Target.Label()), mdEscape(f.ID), f.Severity.Display(),
			mdEscape(reason), expires)
	}
	fmt.Fprintf(b, "\n")
}

func writeProblems(b *strings.Builder, rep *model.Report) {
	fmt.Fprintf(b, "## 7. 錯誤 / 警告\n\n")
	if len(rep.Problems) == 0 {
		fmt.Fprintf(b, "沒有錯誤或警告。\n\n")
		return
	}
	errs := make([]model.Problem, 0, len(rep.Problems))
	warns := make([]model.Problem, 0, len(rep.Problems))
	for _, p := range rep.Problems {
		if p.Level == model.ProblemError {
			errs = append(errs, p)
		} else {
			warns = append(warns, p)
		}
	}
	if len(errs) > 0 {
		fmt.Fprintf(b, "### 錯誤（%d）\n\n", len(errs))
		for _, p := range errs {
			fmt.Fprintf(b, "- **%s**：%s\n", mdEscape(orDash(p.Where)), mdEscape(p.Message))
		}
		fmt.Fprintf(b, "\n")
	}
	if len(warns) > 0 {
		fmt.Fprintf(b, "### 警告（%d）\n\n", len(warns))
		for _, p := range warns {
			fmt.Fprintf(b, "- %s：%s\n", mdEscape(orDash(p.Where)), mdEscape(p.Message))
		}
		fmt.Fprintf(b, "\n")
	}
}

func writeLimitations(b *strings.Builder, rep *model.Report) {
	if len(rep.Limitations) == 0 {
		return
	}
	fmt.Fprintf(b, "## 8. 已知限制\n\n")
	for _, l := range rep.Limitations {
		fmt.Fprintf(b, "- %s\n", l)
	}
	fmt.Fprintf(b, "\n")
}

func targetName(t model.Target) string {
	if t.Kind == model.TargetKindLanguage {
		return t.Name + "（執行環境）"
	}
	if t.Ecosystem == "" {
		return t.Name
	}
	return t.Ecosystem + "/" + t.Name
}

func idWithAliases(f model.Finding) string {
	if len(f.Aliases) == 0 {
		return f.ID
	}
	show := f.Aliases
	if len(show) > 2 {
		show = show[:2]
	}
	return f.ID + "（" + strings.Join(show, "、") + "）"
}

func flags(f model.Finding) string {
	var out []string
	if f.New == model.NewStateYes {
		out = append(out, "**NEW**")
	}
	if f.KEV {
		out = append(out, "**KEV**")
	}
	if f.Ignore != nil && f.Ignore.Expired {
		out = append(out, "忽略已到期")
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, " ")
}

func newText(s model.NewState) string {
	switch s {
	case model.NewStateYes:
		return "是（本次新增）"
	case model.NewStateNo:
		return "否"
	default:
		return "無法判定是否新增"
	}
}

func sourceResult(s model.SourceStatus) string {
	if !s.Enabled {
		return "未啟用"
	}
	if s.OK {
		return "成功"
	}
	return "**失敗**"
}

func mode(rep *model.Report) string {
	if rep.Offline {
		return "offline（只使用快取）"
	}
	return "正常（連線查詢）"
}

func failOnText(rep *model.Report) string {
	if rep.FailOn == "" {
		return "未設定（永遠 exit 0，由報表負責告知）"
	}
	return rep.FailOn
}

func yesNo(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}

// mdEscape 處理會破壞 Markdown 表格的字元。
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
