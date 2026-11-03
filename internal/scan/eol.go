package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/elvis3434/vulnwatch/internal/httpx"
	"github.com/elvis3434/vulnwatch/internal/model"
)

// endoflife.date API v1 客戶端。
//
// 規劃 §2 / §11：用 /api/v1/products/{product}，結構是 result.releases[]，
// 每筆有 name、latest{name,date,link}、isEol、eolFrom、isMaintained。
// 舊的 /api/{product}.json 端點雖然還回 200，但已非主推。
//
// 刻意放在 internal/scan 而不是另開 internal/source/eol：
// 規劃 §6 要求 Phase 1 維持 6 個 package，詳見 docs/decisions.md §1。

const (
	// DefaultEOLEndpoint 是 endoflife.date 的根路徑。
	DefaultEOLEndpoint = "https://endoflife.date"
	// EOLSourceName 是這個來源在報表中的名稱。
	EOLSourceName = "endoflife.date"
	// eolCacheTTL 依規劃 §2.2：一天更新一次就夠。
	eolCacheTTL = 24 * time.Hour
)

// flexString 容忍 endoflife.date 把欄位寫成 string / null / bool / number。
// 規劃 §11 把「python、rust 是否與 go 同結構」列為待確認項目，
// 所以解析器寫成容錯的，欄位型別不如預期時不會讓整個查詢失敗。
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == "" {
		*f = ""
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		*f = flexString(str)
		return nil
	}
	*f = flexString(strings.Trim(s, `"`))
	return nil
}

func (f flexString) String() string { return string(f) }

type eolLatest struct {
	Name flexString `json:"name"`
	Date flexString `json:"date"`
	Link flexString `json:"link"`
}

type eolRelease struct {
	Name         flexString `json:"name"`
	IsEOL        bool       `json:"isEol"`
	IsMaintained bool       `json:"isMaintained"`
	EOLFrom      flexString `json:"eolFrom"`
	Latest       eolLatest  `json:"latest"`
}

type eolResponse struct {
	Result struct {
		Name     flexString   `json:"name"`
		Releases []eolRelease `json:"releases"`
	} `json:"result"`
}

// fetchEOL 查一個產品的 EOL 資料。
func (r *runner) fetchEOL(ctx context.Context, product string) (*eolResponse, error) {
	endpoint := r.opt.EOLEndpoint
	if endpoint == "" {
		endpoint = DefaultEOLEndpoint
	}
	url := strings.TrimRight(endpoint, "/") + "/api/v1/products/" + product

	resp, err := r.opt.HTTP.Do(ctx, httpx.Request{
		Method:   http.MethodGet,
		URL:      url,
		CacheTTL: eolCacheTTL,
	})
	if err != nil {
		return nil, err
	}

	var out eolResponse
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("endoflife.date 回應不是合法的 JSON（%s）: %w", product, err)
	}
	if len(out.Result.Releases) == 0 {
		return nil, fmt.Errorf("endoflife.date 回應中 %s 沒有任何 releases（結構可能已變更）", product)
	}
	return &out, nil
}

// majorMinor 取版本線，例如 1.27.3 → 1.27、3.12.7 → 3.12。
func majorMinor(version string) string {
	s := strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return s
	}
	return parts[0] + "." + parts[1]
}

// patchNumber 取版本的第三段數字；回傳 ok=false 表示取不到。
func patchNumber(version string) (int, bool) {
	s := strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.Split(s, ".")
	if len(parts) < 3 {
		// 1.82 這種只有兩段的版本視為 patch 0
		if len(parts) == 2 {
			return 0, true
		}
		return 0, false
	}
	// 去掉 1.27.3-rc1 這類後綴
	numeric := parts[2]
	for i, c := range numeric {
		if c < '0' || c > '9' {
			numeric = numeric[:i]
			break
		}
	}
	n, err := strconv.Atoi(numeric)
	if err != nil {
		return 0, false
	}
	return n, true
}

// buildLanguageStatus 由 EOL 回應算出語言執行環境狀態（規劃 §5 第 4 點）。
// 主軸是「目前版本 / 該版本線最新修補版 / 落後幾個 patch / 是否 EOL」。
// 第二個回傳值是要寫進報表警告區的訊息。
func buildLanguageStatus(name, version string, resp *eolResponse) (model.LanguageStatus, []string) {
	st := model.LanguageStatus{
		Name:        name,
		Version:     version,
		ReleaseLine: majorMinor(version),
		EOL:         "unknown",
	}
	var warns []string

	var cur *eolRelease
	for i := range resp.Result.Releases {
		if resp.Result.Releases[i].Name.String() == st.ReleaseLine {
			cur = &resp.Result.Releases[i]
			break
		}
	}

	// 整體最新版：releases[] 由新到舊，取第一筆有 latest.name 的。
	for i := range resp.Result.Releases {
		if n := resp.Result.Releases[i].Latest.Name.String(); n != "" {
			st.LatestOverall = n
			break
		}
	}

	if cur == nil {
		st.Note = fmt.Sprintf("endoflife.date 沒有 %s 這個版本線（可能太舊或太新）", st.ReleaseLine)
		warns = append(warns, fmt.Sprintf("%s %s：endoflife.date 沒有 %s 版本線的資料，無法判斷 EOL 與落後狀態",
			name, version, st.ReleaseLine))
		return st, warns
	}

	st.LatestInLine = cur.Latest.Name.String()
	if cur.IsEOL {
		st.EOL = "yes"
	} else {
		st.EOL = "no"
	}
	st.EOLFrom = cur.EOLFrom.String()

	// 落後幾個 patch
	if st.LatestInLine != "" {
		curPatch, ok1 := patchNumber(version)
		latestPatch, ok2 := patchNumber(st.LatestInLine)
		if ok1 && ok2 && majorMinor(st.LatestInLine) == st.ReleaseLine {
			st.PatchesBehindKnown = true
			if n := latestPatch - curPatch; n > 0 {
				st.PatchesBehind = n
			}
		} else {
			warns = append(warns, fmt.Sprintf("%s %s：無法由 %q 算出落後幾個 patch（版本格式與預期不符）",
				name, version, st.LatestInLine))
		}
	} else {
		warns = append(warns, fmt.Sprintf("%s %s：endoflife.date 回應缺少 latest.name（結構可能已變更）", name, version))
	}

	// 建議版本
	switch {
	case cur.IsEOL:
		// 已 EOL → 建議升到最新一個還在維護的版本線
		st.Recommended = recommendMaintained(resp)
		if st.Recommended == "" {
			st.Recommended = st.LatestOverall
		}
		st.Note = strings.TrimSpace(fmt.Sprintf("%s 版本線已 EOL%s，建議升級版本線",
			st.ReleaseLine, eolFromSuffix(st.EOLFrom)))
	case !cur.IsMaintained:
		st.Recommended = recommendMaintained(resp)
		if st.Recommended == "" {
			st.Recommended = st.LatestOverall
		}
		st.Note = fmt.Sprintf("%s 版本線尚未標記 EOL，但已不再維護", st.ReleaseLine)
	case st.PatchesBehindKnown && st.PatchesBehind > 0:
		st.Recommended = st.LatestInLine
		st.Note = fmt.Sprintf("同版本線內可直接升到 %s", st.LatestInLine)
	case st.PatchesBehindKnown:
		st.Note = "已是該版本線的最新修補版"
	}

	return st, warns
}

func eolFromSuffix(from string) string {
	if from == "" {
		return ""
	}
	return "（自 " + from + "）"
}

// recommendMaintained 回傳最新一個仍在維護、且未 EOL 的版本線的最新版本。
func recommendMaintained(resp *eolResponse) string {
	for i := range resp.Result.Releases {
		rel := &resp.Result.Releases[i]
		if rel.IsMaintained && !rel.IsEOL {
			if n := rel.Latest.Name.String(); n != "" {
				return n
			}
		}
	}
	return ""
}
