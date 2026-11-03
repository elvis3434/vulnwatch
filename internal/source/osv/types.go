// Package osv 是 OSV.dev 的查詢客戶端，外加兩段規劃中最容易做錯的邏輯：
// §3.2 的嚴重度四層回退，與 §3.3 的「挑出包含目前版本的那一段 range」。
package osv

import "encoding/json"

// Advisory 是 OSV 的 vulnerability 物件（只取本工具用得到的欄位）。
type Advisory struct {
	SchemaVersion string   `json:"schema_version,omitempty"`
	ID            string   `json:"id"`
	Modified      string   `json:"modified,omitempty"`
	Published     string   `json:"published,omitempty"`
	Withdrawn     string   `json:"withdrawn,omitempty"`
	Aliases       []string `json:"aliases,omitempty"`
	Related       []string `json:"related,omitempty"`
	Summary       string   `json:"summary,omitempty"`
	Details       string   `json:"details,omitempty"`
	// Severity 的 score 欄位是 CVSS **vector 字串**，不是分數（規劃 §11 實測）。
	// Go 官方 advisory（GO-*）這個欄位一律是 null。
	Severity         []Severity      `json:"severity,omitempty"`
	Affected         []Affected      `json:"affected,omitempty"`
	References       []Reference     `json:"references,omitempty"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
}

// Severity 是 OSV 的 severity 項目。
type Severity struct {
	// Type 實測值有 "CVSS_V2"、"CVSS_V3"、"CVSS_V4"。
	Type string `json:"type"`
	// Score 是 vector 字串，例如 "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"。
	Score string `json:"score"`
}

// Affected 是 OSV 的 affected 項目。
type Affected struct {
	Package Package `json:"package"`
	Ranges  []Range `json:"ranges,omitempty"`
	// Versions 可能列舉數百個版本號（規劃 §2.2：所以快取要 gzip）。
	Versions          []string        `json:"versions,omitempty"`
	EcosystemSpecific json.RawMessage `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  json.RawMessage `json:"database_specific,omitempty"`
}

// Package 是 OSV 的 package 物件。
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl,omitempty"`
}

// Range 是 OSV 的 range 物件。
type Range struct {
	// Type 實測值有 "SEMVER"、"ECOSYSTEM"、"GIT"。
	// GIT range 是 commit hash，無法用版本號比對（規劃 §4.2 的 CPython 案例）。
	Type   string  `json:"type"`
	Repo   string  `json:"repo,omitempty"`
	Events []Event `json:"events,omitempty"`
}

// Event 是 range 裡的邊界事件。同一筆最多只有一個欄位有值。
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Reference 是 OSV 的參考連結。
type Reference struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url"`
}

// queryRequest 是 POST /v1/query 的 request body。
type queryRequest struct {
	Version string   `json:"version,omitempty"`
	Package *Package `json:"package,omitempty"`
}

// queryResponse 是 POST /v1/query 的回應。
type queryResponse struct {
	Vulns []Advisory `json:"vulns"`
}

// databaseSpecific 只取本工具用得到的欄位。
// GHSA 的 database_specific.severity 是 LOW/MODERATE/HIGH/CRITICAL 質性等級，
// 是規劃 §3.2 第 2 層回退的來源。
type databaseSpecific struct {
	Severity     string `json:"severity,omitempty"`
	GitHubSevery string `json:"github_reviewed,omitempty"`
	ReviewStatus string `json:"review_status,omitempty"`
}
