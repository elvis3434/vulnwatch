// Package report 負責寫出 Markdown 與 JSON 報表（Phase 2 再加 HTML）。
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/elvis3434/vulnwatch/internal/model"
)

// DirPattern 是報表目錄的命名格式：YYYY-MM-DD_HHmm。
// keep_reports 清理時只會刪除符合這個格式的目錄（規劃 §5.2）。
const DirPattern = "2006-01-02_1504"

// dirRe 必須與 DirPattern 對應。規劃 §5.2：絕不對整個 report_dir 做 glob 刪除。
var dirRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}_\d{4}$`)

// MarshalJSON 把報表序列化成 JSON（下次執行會讀回來做 NEW 判定）。
func MarshalJSON(rep *model.Report) ([]byte, error) {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// UnmarshalJSON 讀回舊的 JSON 報表。
func UnmarshalJSON(raw []byte) (*model.Report, error) {
	var rep model.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

// Write 把報表寫到 reportDir/YYYY-MM-DD_HHmm/，並在 reportDir 下另存
// latest.md / latest.json 方便固定開啟（規劃 §5）。
// 回傳實際寫出的檔案路徑。
func Write(rep *model.Report, reportDir string, formats []string, at time.Time) ([]string, error) {
	stamp := at.Format(DirPattern)
	dir := filepath.Join(reportDir, stamp)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("建立報表目錄 %s 失敗: %w", dir, err)
	}

	// 這次不產生的格式，要把舊的 latest.<fmt> 移掉。
	// 否則使用者把 report_formats 從 ["md","json"] 改成 ["json"] 之後，
	// 舊的 latest.md 會留在原地 —— 它看起來是最新報表，其實是上一次的結果。
	// 對一個弱點掃描工具來說，這種過期檔案比沒有檔案危險得多。
	if _, err := pruneStaleLatest(reportDir, formats); err != nil {
		return nil, err
	}

	var written []string
	for _, f := range formats {
		switch f {
		case "json":
			raw, err := MarshalJSON(rep)
			if err != nil {
				return written, err
			}
			p := filepath.Join(dir, "report.json")
			if err := os.WriteFile(p, raw, 0o644); err != nil {
				return written, fmt.Errorf("寫入 %s 失敗: %w", p, err)
			}
			written = append(written, p)

			latest := filepath.Join(reportDir, "latest.json")
			if err := os.WriteFile(latest, raw, 0o644); err != nil {
				return written, fmt.Errorf("寫入 %s 失敗: %w", latest, err)
			}
			written = append(written, latest)

		case "md":
			raw := []byte(Markdown(rep))
			p := filepath.Join(dir, "report.md")
			if err := os.WriteFile(p, raw, 0o644); err != nil {
				return written, fmt.Errorf("寫入 %s 失敗: %w", p, err)
			}
			written = append(written, p)

			latest := filepath.Join(reportDir, "latest.md")
			if err := os.WriteFile(latest, raw, 0o644); err != nil {
				return written, fmt.Errorf("寫入 %s 失敗: %w", latest, err)
			}
			written = append(written, latest)
		}
	}
	return written, nil
}

// ReportDirs 回傳 reportDir 下所有符合 YYYY-MM-DD_HHmm 命名的目錄，由新到舊。
func ReportDirs(reportDir string) ([]string, error) {
	entries, err := os.ReadDir(reportDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && dirRe.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	// 命名格式本身就是可排序的字串。
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names, nil
}

// Cleanup 只保留最近 keep 份報表目錄（規劃 §5.2）。
// keep <= 0 表示不清理。回傳被刪除的目錄名稱。
//
// 刻意只刪除檔名符合 DirPattern 的目錄：使用者可能在 report_dir 裡放自己的東西，
// 絕不對整個 report_dir 做 glob 刪除。
func Cleanup(reportDir string, keep int) ([]string, error) {
	if keep <= 0 {
		return nil, nil
	}
	names, err := ReportDirs(reportDir)
	if err != nil {
		return nil, err
	}
	if len(names) <= keep {
		return nil, nil
	}
	var removed []string
	for _, name := range names[keep:] {
		p := filepath.Join(reportDir, name)
		if err := os.RemoveAll(p); err != nil {
			return removed, fmt.Errorf("刪除舊報表目錄 %s 失敗: %w", p, err)
		}
		removed = append(removed, name)
	}
	return removed, nil
}

// latestFiles 是各格式對應的 latest 檔名。
var latestFiles = map[string]string{
	"md":   "latest.md",
	"json": "latest.json",
	// html 是 Phase 2；先列在這裡，這樣從 html 改回 md/json 時
	// 舊的 latest.html 也會被清掉。
	"html": "latest.html",
}

// pruneStaleLatest 移除「這次不產生的格式」留下的舊 latest 檔。
// 回傳被移除的檔名。
func pruneStaleLatest(reportDir string, formats []string) ([]string, error) {
	keep := make(map[string]bool, len(formats))
	for _, f := range formats {
		if name, ok := latestFiles[f]; ok {
			keep[name] = true
		}
	}

	var removed []string
	for _, name := range latestFiles {
		if keep[name] {
			continue
		}
		p := filepath.Join(reportDir, name)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := os.Remove(p); err != nil {
			return removed, fmt.Errorf("移除過期的 %s 失敗: %w", p, err)
		}
		removed = append(removed, name)
	}
	sort.Strings(removed)
	return removed, nil
}
