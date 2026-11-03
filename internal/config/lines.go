package config

import (
	"bufio"
	"bytes"
	"strings"
)

// lineIndex 從 TOML 原文建立「section / key → 行號」的索引。
//
// 為什麼需要這個：go-toml/v2 的 *解碼* 錯誤本身就帶行號，但本工具的
// *語意* 驗證（例如 ecosystem 不在支援清單、expires 格式錯誤）是解碼完成後
// 才做的，那時已經沒有位置資訊。驗收標準（規劃 §9 第一條）要求
// `vulnwatch check` 指出具體欄位與行號，所以這裡用一個輕量的行掃描補上。
//
// 這是刻意做成啟發式的：只認得「行首（可含空白）是 [table]、[[array]]、
// 或 key =」這幾種形狀，不處理多行陣列裡的鍵。對本工具的設定檔格式足夠，
// 找不到時會退回該區塊的起始行，不會給出錯誤的行號。
type lineIndex struct {
	tableLines map[string]int
	tableKeys  map[string]map[string]int
	arrays     map[string][]arrayEntry
}

type arrayEntry struct {
	line int
	keys map[string]int
}

func newLineIndex(src []byte) *lineIndex {
	idx := &lineIndex{
		tableLines: map[string]int{},
		tableKeys:  map[string]map[string]int{},
		arrays:     map[string][]arrayEntry{},
	}

	var curTable string
	var curArray string
	curArrayIdx := -1

	sc := bufio.NewScanner(bytes.NewReader(src))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		if strings.HasPrefix(raw, "[[") {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(cutComment(raw), "[["), "]]"))
			name = strings.Trim(name, "]")
			curArray = name
			curTable = ""
			idx.arrays[name] = append(idx.arrays[name], arrayEntry{line: line, keys: map[string]int{}})
			curArrayIdx = len(idx.arrays[name]) - 1
			continue
		}

		if strings.HasPrefix(raw, "[") {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(cutComment(raw), "["), "]"))
			curTable = name
			curArray = ""
			curArrayIdx = -1
			if _, ok := idx.tableLines[name]; !ok {
				idx.tableLines[name] = line
				idx.tableKeys[name] = map[string]int{}
			}
			continue
		}

		key, _, ok := strings.Cut(raw, "=")
		if !ok {
			continue
		}
		key = strings.Trim(strings.TrimSpace(key), `"'`)
		if key == "" {
			continue
		}

		switch {
		case curArray != "" && curArrayIdx >= 0:
			entries := idx.arrays[curArray]
			if _, exists := entries[curArrayIdx].keys[key]; !exists {
				entries[curArrayIdx].keys[key] = line
			}
		case curTable != "":
			if _, exists := idx.tableKeys[curTable][key]; !exists {
				idx.tableKeys[curTable][key] = line
			}
		}
	}
	return idx
}

// cutComment 去掉行尾註解。只在解析 table 標頭時用，不處理引號內的 #。
func cutComment(s string) string {
	if i := strings.Index(s, "#"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// tableKey 回傳 [section] 裡某個 key 的行號；找不到就回傳該 section 的行號。
func (l *lineIndex) tableKey(section, key string) int {
	if l == nil {
		return 0
	}
	if keys, ok := l.tableKeys[section]; ok {
		if n, ok := keys[key]; ok {
			return n
		}
	}
	return l.tableLines[section]
}

// arrayKey 回傳第 i 個 [[name]] 裡某個 key 的行號；找不到就回傳該筆的起始行。
func (l *lineIndex) arrayKey(name string, i int, key string) int {
	if l == nil {
		return 0
	}
	entries := l.arrays[name]
	if i < 0 || i >= len(entries) {
		return 0
	}
	if n, ok := entries[i].keys[key]; ok {
		return n
	}
	return entries[i].line
}

// arrayLine 回傳第 i 個 [[name]] 的起始行。
func (l *lineIndex) arrayLine(name string, i int) int {
	if l == nil {
		return 0
	}
	entries := l.arrays[name]
	if i < 0 || i >= len(entries) {
		return 0
	}
	return entries[i].line
}
