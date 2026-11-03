package osv

import (
	"encoding/json"
	"strings"

	"github.com/elvis3434/vulnwatch/internal/model"
)

// SourceName 是這個來源在報表中的名稱。
const SourceName = "OSV"

// ResolveSeverity 實作規劃 §3.2 嚴重度四層回退的第 1、2、4 層。
//
//	第 1 層：severity 裡 CVSS_V3 的 vector → 自己算 CVSS 3.1 base score
//	第 2 層：database_specific.severity 的質性等級（GHSA 的 LOW/MODERATE/HIGH/CRITICAL）
//	第 3 層：alias CVE → NVD 補分數（不在這裡做，由 internal/scan 在拿到全部
//	        結果後統一處理，因為它需要 NVD 客戶端與額度控制）
//	第 4 層：UNKNOWN，分數留白
//
// 兩條硬規則：
//   - UNKNOWN 永不被 min_severity 濾掉（由 internal/scan 的分類負責）。
//   - 只有 CVSS_V4 的項目不硬算分數，只保留 vector 原文顯示。
func ResolveSeverity(a Advisory) model.Severity {
	// 第 1 層：CVSS_V3 vector 自算分數。
	if v := findSeverityVector(a.Severity, "CVSS_V3"); v != "" {
		if score, err := model.CVSS31BaseScore(v); err == nil {
			return model.Severity{
				Level:      model.LevelFromScore(score),
				Score:      score,
				HasScore:   true,
				Source:     model.SevSourceCVSS31OSV,
				Vector:     v,
				VectorType: "CVSS_V3",
			}
		}
		// vector 解析失敗就往下一層走，不要讓整筆資料消失。
	}

	// 只有 CVSS_V4 時保留 vector 原文，但刻意不算分數
	// （CVSS 4.0 base score 需查 270 筆 MacroVector 表，Phase 1 不做）。
	v4 := findSeverityVector(a.Severity, "CVSS_V4")

	// 第 2 層：GHSA 的質性等級。
	if lvl, ok := qualitativeLevel(a); ok {
		return model.Severity{
			Level:      lvl,
			HasScore:   false,
			Source:     model.SevSourceGHSA,
			Vector:     v4,
			VectorType: vectorType(v4),
		}
	}

	// 第 4 層：UNKNOWN。Go 官方 advisory（GO-*）一律走到這裡。
	return model.Severity{
		Level:      model.LevelUnknown,
		Source:     model.SevSourceNone,
		Vector:     v4,
		VectorType: vectorType(v4),
	}
}

func vectorType(v string) string {
	if v == "" {
		return ""
	}
	return "CVSS_V4"
}

func findSeverityVector(list []Severity, typ string) string {
	for _, s := range list {
		if strings.EqualFold(s.Type, typ) && strings.TrimSpace(s.Score) != "" {
			return strings.TrimSpace(s.Score)
		}
	}
	return ""
}

// qualitativeLevel 取 database_specific.severity 的質性等級。
// 先看 advisory 層級，再看 affected[] 層級（不同資料庫放的位置不一樣）。
func qualitativeLevel(a Advisory) (model.Level, bool) {
	if lvl, ok := levelFromDatabaseSpecific(a.DatabaseSpecific); ok {
		return lvl, true
	}
	for _, af := range a.Affected {
		if lvl, ok := levelFromDatabaseSpecific(af.DatabaseSpecific); ok {
			return lvl, true
		}
	}
	return model.LevelUnknown, false
}

func levelFromDatabaseSpecific(raw json.RawMessage) (model.Level, bool) {
	if len(raw) == 0 {
		return model.LevelUnknown, false
	}
	var ds databaseSpecific
	if err := json.Unmarshal(raw, &ds); err != nil {
		return model.LevelUnknown, false
	}
	if strings.TrimSpace(ds.Severity) == "" {
		return model.LevelUnknown, false
	}
	lvl, ok := model.ParseLevel(ds.Severity)
	if !ok || lvl == model.LevelUnknown {
		return model.LevelUnknown, false
	}
	return lvl, true
}

// CVEAliases 回傳 aliases 中的 CVE 編號，供規劃 §3.2 第 3 層（NVD 補分數）使用。
func CVEAliases(a Advisory) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		up := strings.ToUpper(strings.TrimSpace(s))
		if strings.HasPrefix(up, "CVE-") && !seen[up] {
			seen[up] = true
			out = append(out, up)
		}
	}
	add(a.ID)
	for _, s := range a.Aliases {
		add(s)
	}
	return out
}

// PrimaryReferences 回傳最多 n 個參考連結，ADVISORY 類型優先。
func PrimaryReferences(a Advisory, n int) []string {
	var advisory, others []string
	for _, r := range a.References {
		if strings.TrimSpace(r.URL) == "" {
			continue
		}
		if strings.EqualFold(r.Type, "ADVISORY") {
			advisory = append(advisory, r.URL)
		} else {
			others = append(others, r.URL)
		}
	}
	out := append(advisory, others...)
	if len(out) > n {
		out = out[:n]
	}
	return out
}
