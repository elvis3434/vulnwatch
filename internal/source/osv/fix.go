package osv

import (
	"sort"
	"strings"

	"github.com/elvis3434/vulnwatch/internal/model"
)

// introducedZero 是 OSV 用來表示「從最初版本就受影響」的哨兵值。
const introducedZero = "0"

// segment 是一段受影響的版本區間 [introduced, fixed) 或 [introduced, lastAffected]。
type segment struct {
	introduced   string
	fixed        string
	lastAffected string
}

// SelectFix 實作規劃 §3.3：找出包含「目前版本」的那一段 range，取該段的 fixed
// 當作「最低安全版本」。
//
// 為什麼不能只取第一個 fixed：實測 urllib3 1.26.5 的 GHSA-34jh-p97f-mpxf 有兩段
//
//	range 1: introduced 0      → fixed 1.26.19   ← 1.26.5 落在這段，正解
//	range 2: introduced 2.0.0  → fixed 2.2.2
//
// 挑錯就會建議使用者從 1.26.5 跳到 2.2.2（跨大版本、破壞性升級）。
//
// cmp 為 nil（Maven / NuGet 不做比較，crates.io / npm 留到 Phase 2）時，
// 回傳全部 fixed 版本當候選並標註限制 —— 老實標示限制，比猜錯升級方向好。
func SelectFix(a Advisory, ecosystem, name, version string, cmp model.Comparer) model.Fix {
	affected := matchingAffected(a, ecosystem, name)
	if len(affected) == 0 {
		return model.Fix{Kind: model.FixKindUnknown, Note: "advisory 沒有對應這個套件的 affected 資料"}
	}

	allFixed := collectFixed(affected)

	// 未指定版本時無法判定落在哪一段（規劃 §3.1）。
	if strings.TrimSpace(version) == "" {
		if len(allFixed) == 0 {
			return model.Fix{Kind: model.FixKindNone, Note: "未指定版本，且 advisory 未提供修正版本"}
		}
		return model.Fix{
			Kind:       model.FixKindCandidates,
			Candidates: allFixed,
			Note:       "未指定目前版本，無法判定該升到哪一段的 fixed",
		}
	}

	if cmp == nil {
		if len(allFixed) == 0 {
			return model.Fix{Kind: model.FixKindNone, Note: "advisory 未提供修正版本"}
		}
		return model.Fix{
			Kind:       model.FixKindCandidates,
			Candidates: allFixed,
			Note:       ecosystem + " 不做版本比較，請自行確認對應的版本線",
		}
	}

	var (
		hits        []string
		foundNoFix  bool
		compareFail bool
	)
	for _, af := range affected {
		for _, r := range af.Ranges {
			// GIT range 是 commit hash，無法用版本號比對（規劃 §4.2 的 CPython 案例）。
			if strings.EqualFold(r.Type, "GIT") {
				continue
			}
			segs, err := buildSegments(r.Events, cmp)
			if err != nil {
				compareFail = true
				continue
			}
			seg, ok, err := findSegment(segs, version, cmp)
			if err != nil {
				compareFail = true
				continue
			}
			if !ok {
				continue
			}
			if seg.fixed != "" {
				hits = appendUniqueStr(hits, seg.fixed)
			} else {
				// 這一段沒有 fixed 事件 → 上游尚未修復。
				foundNoFix = true
			}
		}
	}

	switch {
	case len(hits) == 1:
		return model.Fix{Kind: model.FixKindFixed, Version: hits[0]}
	case len(hits) > 1:
		// 同一個 advisory 有多個 affected 指向同一套件、且各自的版本線不同時，
		// 取版本序最小的那一個當建議值，其餘列為候選。
		sortVersions(hits, cmp)
		return model.Fix{
			Kind:       model.FixKindFixed,
			Version:    hits[0],
			Candidates: hits,
			Note:       "advisory 有多段同時包含目前版本，取版本序最小的 fixed",
		}
	case foundNoFix:
		return model.Fix{Kind: model.FixKindNone, Note: "目前版本所在的版本線尚無修正版本"}
	case compareFail && len(allFixed) > 0:
		return model.Fix{
			Kind:       model.FixKindCandidates,
			Candidates: allFixed,
			Note:       "版本比較失敗（advisory 的版本格式無法解析），列出全部 fixed 版本",
		}
	case len(allFixed) > 0:
		// OSV 已判定這個版本受影響，但 ranges 沒有任何一段包含它
		// （例如只用 affected[].versions 列舉）。不猜，列出全部候選。
		return model.Fix{
			Kind:       model.FixKindCandidates,
			Candidates: allFixed,
			Note:       "advisory 的 ranges 沒有包含目前版本的區間，列出全部 fixed 版本",
		}
	default:
		return model.Fix{Kind: model.FixKindNone, Note: "advisory 未提供修正版本"}
	}
}

// matchingAffected 取出 advisory 中對應這個套件的 affected 項目。
// 一個 advisory 可能同時影響多個套件（例如同一個 CVE 的多個生態系）。
func matchingAffected(a Advisory, ecosystem, name string) []Affected {
	var out []Affected
	for _, af := range a.Affected {
		if model.SamePackage(af.Package.Ecosystem, af.Package.Name, ecosystem, name) {
			out = append(out, af)
		}
	}
	return out
}

func collectFixed(affected []Affected) []string {
	var out []string
	for _, af := range affected {
		for _, r := range af.Ranges {
			if strings.EqualFold(r.Type, "GIT") {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" {
					out = appendUniqueStr(out, e.Fixed)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// buildSegments 把 ranges[].events 攤平成遞增的受影響區間（規劃 §3.3 的演算法）。
//
// OSV 規格不保證 events 的順序，所以先依版本序排序，再配對 introduced 與
// 其後的 fixed / last_affected。
func buildSegments(events []Event, cmp model.Comparer) ([]segment, error) {
	type ev struct {
		kind    string // "introduced" / "fixed" / "last_affected"
		version string
		zero    bool
		order   int
	}

	var list []ev
	for i, e := range events {
		switch {
		case e.Introduced != "":
			list = append(list, ev{kind: "introduced", version: e.Introduced, zero: e.Introduced == introducedZero, order: i})
		case e.Fixed != "":
			list = append(list, ev{kind: "fixed", version: e.Fixed, order: i})
		case e.LastAffected != "":
			list = append(list, ev{kind: "last_affected", version: e.LastAffected, order: i})
		}
		// limit 事件對「挑 fixed」沒有影響，刻意忽略。
	}
	if len(list) == 0 {
		return nil, nil
	}

	// 先驗證所有非哨兵版本都能解析，不能解析就讓呼叫端走候選路線。
	for _, e := range list {
		if e.zero {
			continue
		}
		if _, err := cmp.Compare(e.version, e.version); err != nil {
			return nil, err
		}
	}

	var sortErr error
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		switch {
		case a.zero && b.zero:
			return a.order < b.order
		case a.zero:
			return true
		case b.zero:
			return false
		}
		c, err := cmp.Compare(a.version, b.version)
		if err != nil {
			sortErr = err
			return a.order < b.order
		}
		if c != 0 {
			return c < 0
		}
		// 同版本時 introduced 排前面，這樣零長度區間才不會吃掉下一段。
		if a.kind != b.kind {
			return a.kind == "introduced"
		}
		return a.order < b.order
	})
	if sortErr != nil {
		return nil, sortErr
	}

	var (
		segs []segment
		cur  segment
		open bool
	)
	for _, e := range list {
		switch e.kind {
		case "introduced":
			if open {
				segs = append(segs, cur)
			}
			cur = segment{introduced: e.version}
			open = true
		case "fixed":
			if !open {
				cur = segment{introduced: introducedZero}
			}
			cur.fixed = e.version
			segs = append(segs, cur)
			cur, open = segment{}, false
		case "last_affected":
			if !open {
				cur = segment{introduced: introducedZero}
			}
			cur.lastAffected = e.version
			segs = append(segs, cur)
			cur, open = segment{}, false
		}
	}
	if open {
		segs = append(segs, cur)
	}
	return segs, nil
}

// findSegment 找出包含 version 的那一段。
func findSegment(segs []segment, version string, cmp model.Comparer) (segment, bool, error) {
	for _, s := range segs {
		// version >= introduced
		if s.introduced != "" && s.introduced != introducedZero {
			c, err := cmp.Compare(version, s.introduced)
			if err != nil {
				return segment{}, false, err
			}
			if c < 0 {
				continue
			}
		}
		// version < fixed
		if s.fixed != "" {
			c, err := cmp.Compare(version, s.fixed)
			if err != nil {
				return segment{}, false, err
			}
			if c >= 0 {
				continue
			}
		}
		// version <= last_affected
		if s.lastAffected != "" {
			c, err := cmp.Compare(version, s.lastAffected)
			if err != nil {
				return segment{}, false, err
			}
			if c > 0 {
				continue
			}
		}
		return s, true, nil
	}
	return segment{}, false, nil
}

func sortVersions(vs []string, cmp model.Comparer) {
	sort.SliceStable(vs, func(i, j int) bool {
		c, err := cmp.Compare(vs[i], vs[j])
		if err != nil {
			return vs[i] < vs[j]
		}
		return c < 0
	})
}

func appendUniqueStr(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
