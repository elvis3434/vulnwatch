// Package model 定義弱點掃描結果的核心資料結構、CVSS 3.1 計分，
// 以及各生態系的版本比較規則。本 package 不依賴任何第三方套件以外的東西，
// 也不發出任何網路請求。
package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Level 是弱點的嚴重度等級。
//
// 規劃 §3.2 的硬規則：LevelUnknown（無評級）永遠不會被 min_severity 濾掉，
// 它會被放進報表的「無嚴重度評級」獨立區塊。Go 官方 advisory（GO-*）的
// severity 一律是 null，全靠這條規則才不會從報表中消失。
type Level int

const (
	// LevelUnknown 表示所有嚴重度來源都查不到評級。
	LevelUnknown Level = iota
	LevelLow
	LevelMedium
	LevelHigh
	LevelCritical
)

const (
	LevelNameUnknown  = "UNKNOWN"
	LevelNameLow      = "LOW"
	LevelNameMedium   = "MEDIUM"
	LevelNameHigh     = "HIGH"
	LevelNameCritical = "CRITICAL"
)

func (l Level) String() string {
	switch l {
	case LevelLow:
		return LevelNameLow
	case LevelMedium:
		return LevelNameMedium
	case LevelHigh:
		return LevelNameHigh
	case LevelCritical:
		return LevelNameCritical
	default:
		return LevelNameUnknown
	}
}

// ParseLevel 解析嚴重度等級名稱。GHSA 用的 MODERATE 對應到 MEDIUM。
func ParseLevel(s string) (Level, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case LevelNameUnknown:
		return LevelUnknown, true
	case LevelNameLow:
		return LevelLow, true
	case LevelNameMedium, "MODERATE":
		return LevelMedium, true
	case LevelNameHigh:
		return LevelHigh, true
	case LevelNameCritical:
		return LevelCritical, true
	default:
		return LevelUnknown, false
	}
}

// LevelFromScore 依 CVSS 3.1 的質性評級對照表把 base score 轉成等級。
// 分數 0.0（CVSS 定義為 None）在本工具中視為 LOW，因為 OSV 不會為「無影響」
// 的項目建立 advisory，硬歸成 UNKNOWN 反而會讓它跳過 min_severity。
func LevelFromScore(score float64) Level {
	switch {
	case score >= 9.0:
		return LevelCritical
	case score >= 7.0:
		return LevelHigh
	case score >= 4.0:
		return LevelMedium
	default:
		return LevelLow
	}
}

func (l Level) MarshalJSON() ([]byte, error) { return json.Marshal(l.String()) }

func (l *Level) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	lv, ok := ParseLevel(s)
	if !ok {
		return fmt.Errorf("未知的嚴重度等級 %q", s)
	}
	*l = lv
	return nil
}

// 嚴重度分數的來源標記（規劃 §3.2：報表必須標明分數來源，使用者才知道可不可信）。
const (
	SevSourceCVSS31OSV = "CVSS3.1(OSV)" // 第 1 層：OSV severity 的 CVSS_V3 vector 自算
	SevSourceGHSA      = "GHSA"         // 第 2 層：GHSA database_specific.severity 質性等級
	SevSourceNVD       = "NVD"          // 第 3 層：以 alias CVE 向 NVD 取分數
	SevSourceNone      = "—"            // 第 4 層：查不到
)

// Severity 是單一弱點的嚴重度判定結果。
type Severity struct {
	Level Level `json:"level"`
	// Score 只有在 HasScore 為 true 時有意義。
	Score    float64 `json:"score,omitempty"`
	HasScore bool    `json:"has_score"`
	// Source 是分數/等級的來源，見 SevSource* 常數。
	Source string `json:"source"`
	// Vector 是 OSV 給的 CVSS vector 原文。只有 CVSS_V4 的項目不自算分數
	// （規劃 §3.2：CVSS 4.0 需查 270 筆 MacroVector 表，Phase 1 不做），
	// 但 vector 原文仍要顯示給使用者。
	Vector     string `json:"vector,omitempty"`
	VectorType string `json:"vector_type,omitempty"`
}

// UnknownSeverity 回傳第 4 層回退的結果。
func UnknownSeverity() Severity {
	return Severity{Level: LevelUnknown, Source: SevSourceNone}
}

// Display 回傳報表用的嚴重度字串，例如 "HIGH 7.5 (CVSS3.1(OSV))"。
func (s Severity) Display() string {
	var b strings.Builder
	b.WriteString(s.Level.String())
	if s.HasScore {
		fmt.Fprintf(&b, " %.1f", s.Score)
	}
	src := s.Source
	if src == "" {
		src = SevSourceNone
	}
	fmt.Fprintf(&b, " (%s)", src)
	return b.String()
}
