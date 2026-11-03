package model

import (
	"fmt"
	"math"
	"strings"
)

// CVSS 3.1 base score 計算。規劃 §3.2 第 1 層回退用。
//
// 這是純公式（CVSS v3.1 規格 §7.1），不需要任何對照表，所以自己實作，
// 不引入第三方相依（規劃 §6 的相依白名單）。
//
// 刻意不實作 CVSS 4.0：v4 的 base score 需要查 270 筆 MacroVector 對照表，
// 規劃 §3.2 明確要求 Phase 1 不硬算 v4 分數，只顯示 vector 原文。

var (
	cvssAV  = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvssAC  = map[string]float64{"L": 0.77, "H": 0.44}
	cvssUI  = map[string]float64{"N": 0.85, "R": 0.62}
	cvssCIA = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	// PR 的權重取決於 Scope 是否改變。
	cvssPRUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	cvssPRChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
)

// CVSSVectorKind 判斷一條 vector 字串是哪個版本。
func CVSSVectorKind(vector string) string {
	v := strings.TrimSpace(vector)
	switch {
	case strings.HasPrefix(v, "CVSS:3.1/"):
		return "3.1"
	case strings.HasPrefix(v, "CVSS:3.0/"):
		return "3.0"
	case strings.HasPrefix(v, "CVSS:4.0/"):
		return "4.0"
	case strings.HasPrefix(v, "CVSS:2.0/"), strings.HasPrefix(v, "AV:"):
		return "2.0"
	default:
		return ""
	}
}

// CVSS31BaseScore 由 CVSS 3.0/3.1 vector 字串算出 base score。
// base 公式在 3.0 與 3.1 之間只有 roundup 的定義不同，這裡一律用 3.1 的
// roundup（整數運算版），對 3.0 的 vector 也是可接受的近似。
func CVSS31BaseScore(vector string) (float64, error) {
	kind := CVSSVectorKind(vector)
	if kind != "3.1" && kind != "3.0" {
		return 0, fmt.Errorf("不是 CVSS 3.x vector: %q", vector)
	}

	metrics := map[string]string{}
	for _, part := range strings.Split(strings.TrimSpace(vector), "/") {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		metrics[strings.ToUpper(k)] = strings.ToUpper(v)
	}

	// Scope 要先讀，因為 PR 的權重取決於它。
	scope, ok := metrics["S"]
	if !ok {
		return 0, fmt.Errorf("CVSS vector 缺少 S（Scope）: %q", vector)
	}
	scopeChanged := scope == "C"
	if !scopeChanged && scope != "U" {
		return 0, fmt.Errorf("CVSS vector 的 S 值無效: %q", scope)
	}

	prTable := cvssPRUnchanged
	if scopeChanged {
		prTable = cvssPRChanged
	}

	lookup := func(key string, table map[string]float64) (float64, error) {
		raw, ok := metrics[key]
		if !ok {
			return 0, fmt.Errorf("CVSS vector 缺少必要欄位 %s: %q", key, vector)
		}
		w, ok := table[raw]
		if !ok {
			return 0, fmt.Errorf("CVSS vector 的 %s 值無效: %q", key, raw)
		}
		return w, nil
	}

	av, err := lookup("AV", cvssAV)
	if err != nil {
		return 0, err
	}
	ac, err := lookup("AC", cvssAC)
	if err != nil {
		return 0, err
	}
	pr, err := lookup("PR", prTable)
	if err != nil {
		return 0, err
	}
	ui, err := lookup("UI", cvssUI)
	if err != nil {
		return 0, err
	}
	c, err := lookup("C", cvssCIA)
	if err != nil {
		return 0, err
	}
	i, err := lookup("I", cvssCIA)
	if err != nil {
		return 0, err
	}
	a, err := lookup("A", cvssCIA)
	if err != nil {
		return 0, err
	}

	iss := 1 - (1-c)*(1-i)*(1-a)

	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, nil
	}

	exploitability := 8.22 * av * ac * pr * ui

	score := impact + exploitability
	if scopeChanged {
		score *= 1.08
	}
	return cvssRoundup(math.Min(score, 10)), nil
}

// cvssRoundup 是 CVSS 3.1 規格定義的 Roundup：進位到小數一位，
// 但用整數運算避免浮點誤差（規格附錄 A 的參考實作）。
func cvssRoundup(x float64) float64 {
	intInput := int64(math.Round(x * 100000))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000.0
	}
	return (math.Floor(float64(intInput)/10000.0) + 1) / 10.0
}
