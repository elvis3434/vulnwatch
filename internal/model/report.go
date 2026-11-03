package model

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Target 是一個掃描對象：第三方套件，或程式語言執行環境。
type Target struct {
	// Kind 為 "package" 或 "language"。
	Kind      string `json:"kind"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Note      string `json:"note,omitempty"`
}

const (
	TargetKindPackage  = "package"
	TargetKindLanguage = "language"
)

// Label 回傳報表上顯示的對象名稱。
func (t Target) Label() string {
	var b strings.Builder
	if t.Ecosystem != "" && t.Ecosystem != EcosystemLanguage {
		b.WriteString(t.Ecosystem)
		b.WriteString("/")
	}
	b.WriteString(t.Name)
	if t.Version != "" {
		b.WriteString("@")
		b.WriteString(t.Version)
	}
	return b.String()
}

// Key 是 target 的識別鍵（含版本）。
func (t Target) Key() string {
	return t.Kind + "|" + t.Ecosystem + "|" + NormalizePackageName(t.Ecosystem, t.Name) + "|" + t.Version
}

// FixKind 表達「最低安全版本」的三種狀態（規劃 §3.3）。
type FixKind string

const (
	// FixKindFixed：確定值，已經比較過版本並挑出包含目前版本的那一段。
	FixKindFixed FixKind = "fixed"
	// FixKindCandidates：多個候選，本工具未對該生態系做版本比較。
	FixKindCandidates FixKind = "candidates"
	// FixKindNone：上游尚無修正版本。
	FixKindNone FixKind = "none"
	// FixKindUnknown：資料不足（例如未指定版本、或 advisory 只有 GIT range）。
	FixKindUnknown FixKind = "unknown"
)

// Fix 是弱點的修正資訊。
type Fix struct {
	Kind       FixKind  `json:"kind"`
	Version    string   `json:"version,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
	Note       string   `json:"note,omitempty"`
}

// Display 回傳報表用的「最低安全版本」字串，能表達規劃 §3.3 要求的三種狀態：
// 確定值、多個候選（未比較）、尚無修正版本。
//
// 「多個候選」的原因一律取自 Note，不可寫死成「未做版本比較」：
// Go 與 PyPI 是**有**版本比較器的，它們回到候選狀態時的原因是
// 「advisory 的 ranges 沒有包含目前版本的區間」或「版本字串無法解析」。
// 寫死成「未做版本比較」會讓使用者誤以為本工具對 Go 不支援版本比較。
func (f Fix) Display() string {
	switch f.Kind {
	case FixKindFixed:
		return f.Version
	case FixKindCandidates:
		reason := strings.TrimSpace(f.Note)
		if reason == "" {
			reason = "未做版本比較，請自行確認對應的版本線"
		}
		if len(f.Candidates) == 0 {
			return "候選版本不明（" + reason + "）"
		}
		return strings.Join(f.Candidates, " / ") + "（" + reason + "）"
	case FixKindNone:
		return "尚無修正版本"
	default:
		return "無資料"
	}
}

// NewState 是 NEW 標記的三種狀態（規劃 §5.1）。
// 上次執行時失敗的來源所涵蓋的項目不參與 NEW 判定，標為 NewStateUndetermined。
type NewState string

const (
	NewStateNo           NewState = "no"
	NewStateYes          NewState = "yes"
	NewStateUndetermined NewState = "undetermined"
)

// IgnoreState 記錄這個項目被忽略清單命中的情形。
type IgnoreState struct {
	ID      string `json:"id"`
	Reason  string `json:"reason,omitempty"`
	Expires string `json:"expires,omitempty"`
	// Expired 為 true 時，項目照常列入報表，並標示忽略已到期（規劃 §3.4）。
	Expired bool `json:"expired"`
}

// Finding 是一筆「某個對象中了某個弱點」的結果。
type Finding struct {
	Target      Target   `json:"target"`
	ID          string   `json:"id"`
	Aliases     []string `json:"aliases,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	Severity    Severity `json:"severity"`
	Fix         Fix      `json:"fix"`
	LatestKnown string   `json:"latest_known,omitempty"`
	References  []string `json:"references,omitempty"`
	// Source 是提供這筆資料的來源名稱，例如 "OSV"。NEW 判定會用到
	// （規劃 §5.1：上次失敗的來源涵蓋的項目不參與 NEW 判定）。
	Source   string `json:"source"`
	Modified string `json:"modified,omitempty"`
	// KEV / EPSS 是 Phase 2 才填的欄位，這裡先保留以固定 JSON 結構。
	KEV  bool     `json:"kev"`
	EPSS *float64 `json:"epss,omitempty"`

	New    NewState     `json:"new"`
	Ignore *IgnoreState `json:"ignore,omitempty"`
}

// DiffKey 是 NEW 判定用的鍵：(ecosystem, name, 弱點主 ID)，刻意**不含版本**
// —— 否則使用者升版後，舊弱點會重新被標成 NEW（規劃 §5.1）。
func (f Finding) DiffKey() string {
	return strings.ToLower(f.Target.Ecosystem) + "|" +
		NormalizePackageName(f.Target.Ecosystem, f.Target.Name) + "|" +
		strings.ToUpper(f.ID)
}

// SourceStatus 記錄每個資料來源這次執行的成敗（規劃 §5 摘要、§5.1 NEW 判定）。
type SourceStatus struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	OK      bool   `json:"ok"`
	Queries int    `json:"queries"`
	Errors  int    `json:"errors"`
	Message string `json:"message,omitempty"`
}

// Problem 是報表「錯誤 / 警告」區的一筆項目。不可靜默吞掉（規劃 §5 第 7 點）。
type Problem struct {
	// Level 為 "error" 或 "warning"。
	Level   string `json:"level"`
	Where   string `json:"where,omitempty"`
	Message string `json:"message"`
}

const (
	ProblemError   = "error"
	ProblemWarning = "warning"
)

// NoDataItem 是查不到資料的對象（例如 --offline 快取未命中）。
// 規劃 §2.2：這類項目必須標示「無資料」，不可當成「無弱點」。
type NoDataItem struct {
	Target Target `json:"target"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

// LanguageStatus 是程式語言執行環境的狀態（規劃 §5 第 4 點）。
// 主軸是「目前版本 / 該版本線最新修補版 / 是否 EOL / 落後幾個 patch」。
type LanguageStatus struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	ReleaseLine   string `json:"release_line,omitempty"`
	LatestInLine  string `json:"latest_in_line,omitempty"`
	LatestOverall string `json:"latest_overall,omitempty"`
	// PatchesBehind 只有在 PatchesBehindKnown 為 true 時有意義。
	PatchesBehind      int  `json:"patches_behind,omitempty"`
	PatchesBehindKnown bool `json:"patches_behind_known"`
	// EOL 為 "yes" / "no" / "unknown"。
	EOL         string `json:"eol"`
	EOLFrom     string `json:"eol_from,omitempty"`
	Recommended string `json:"recommended,omitempty"`
	// VulnScanned 為 false 表示本階段沒有掃這個語言的弱點清單。
	VulnScanned bool   `json:"vuln_scanned"`
	Note        string `json:"note,omitempty"`
}

// Summary 是報表摘要區。
type Summary struct {
	Targets         int            `json:"targets"`
	Packages        int            `json:"packages"`
	Languages       int            `json:"languages"`
	TotalFindings   int            `json:"total_findings"`
	ByLevel         map[string]int `json:"by_level"`
	UnknownCount    int            `json:"unknown_count"`
	FilteredCount   int            `json:"filtered_count"`
	NewCount        int            `json:"new_count"`
	NewUndetermined int            `json:"new_undetermined"`
	IgnoredCount    int            `json:"ignored_count"`
	KEVCount        int            `json:"kev_count"`
	AllSourcesOK    bool           `json:"all_sources_ok"`
}

// BaselineInfo 記錄這次 NEW 判定用的比對基準。
type BaselineInfo struct {
	Path         string `json:"path,omitempty"`
	GeneratedAt  string `json:"generated_at,omitempty"`
	AllSourcesOK bool   `json:"all_sources_ok"`
	Note         string `json:"note,omitempty"`
}

// Report 是一次掃描的完整結果，也是寫出 JSON 報表的結構。
// 下一次執行會讀回這份 JSON 做 NEW 判定（規劃 §5.1）。
type Report struct {
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"tool_version"`
	SchemaVersion int       `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Timezone      string    `json:"timezone,omitempty"`
	ConfigPath    string    `json:"config_path,omitempty"`
	Offline       bool      `json:"offline"`
	MinSeverity   string    `json:"min_severity"`
	FailOn        string    `json:"fail_on,omitempty"`

	Summary Summary `json:"summary"`
	// Findings 是「需處理清單」：有嚴重度評級且達到 min_severity 的項目。
	Findings []Finding `json:"findings"`
	// Unknown 是「無嚴重度評級」獨立區塊，不受 min_severity 影響（規劃 §3.2）。
	Unknown []Finding `json:"unknown_severity"`
	// Filtered 是低於 min_severity 被濾掉的項目。仍寫進 JSON，
	// 否則下次調整 min_severity 時這些項目會被誤判成 NEW。
	Filtered []Finding `json:"filtered_out"`
	// Ignored 是被忽略清單命中且尚未到期的項目。
	Ignored []Finding `json:"ignored"`

	Languages   []LanguageStatus `json:"languages,omitempty"`
	NoData      []NoDataItem     `json:"no_data,omitempty"`
	Sources     []SourceStatus   `json:"sources"`
	Problems    []Problem        `json:"problems,omitempty"`
	Baseline    *BaselineInfo    `json:"baseline,omitempty"`
	Limitations []string         `json:"limitations,omitempty"`
}

// SchemaVersion 是 JSON 報表的結構版本，供未來讀回舊報表時判斷。
const SchemaVersion = 1

// AllFindings 回傳所有分類中的項目，供 NEW 判定與統計使用。
func (r *Report) AllFindings() []Finding {
	out := make([]Finding, 0, len(r.Findings)+len(r.Unknown)+len(r.Filtered)+len(r.Ignored))
	out = append(out, r.Findings...)
	out = append(out, r.Unknown...)
	out = append(out, r.Filtered...)
	out = append(out, r.Ignored...)
	return out
}

// SourceOK 回傳指定來源這次執行是否成功；來源不存在時回傳 false。
func (r *Report) SourceOK(name string) bool {
	for _, s := range r.Sources {
		if strings.EqualFold(s.Name, name) {
			return s.OK
		}
	}
	return false
}

// HasSource 回傳報表中是否有這個來源的狀態紀錄。
func (r *Report) HasSource(name string) bool {
	for _, s := range r.Sources {
		if strings.EqualFold(s.Name, name) {
			return true
		}
	}
	return false
}

// AddProblem 附加一筆錯誤或警告。
func (r *Report) AddProblem(level, where, format string, args ...any) {
	r.Problems = append(r.Problems, Problem{
		Level:   level,
		Where:   where,
		Message: fmt.Sprintf(format, args...),
	})
}

// SortFindings 依「KEV → 嚴重度 → EPSS」排序（規劃 §5 第 2 點）。
// Phase 1 還沒有 KEV / EPSS 資料，排序會自然退化成「嚴重度 → 分數 → ID」。
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if a.Severity.Level != b.Severity.Level {
			return a.Severity.Level > b.Severity.Level
		}
		if a.Severity.Score != b.Severity.Score {
			return a.Severity.Score > b.Severity.Score
		}
		ae, be := 0.0, 0.0
		if a.EPSS != nil {
			ae = *a.EPSS
		}
		if b.EPSS != nil {
			be = *b.EPSS
		}
		if ae != be {
			return ae > be
		}
		if a.Target.Label() != b.Target.Label() {
			return a.Target.Label() < b.Target.Label()
		}
		return a.ID < b.ID
	})
}
