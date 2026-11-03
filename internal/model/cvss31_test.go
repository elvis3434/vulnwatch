package model

import "testing"

func TestCVSS31BaseScore(t *testing.T) {
	// 這些 vector 的 base score 是 CVSS 3.1 規格與公開 advisory 上的已知值，
	// 用來驗證自己寫的公式（規劃 §3.2 第 1 層回退）。
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9},
		// scope changed（1.08 倍與不同的 impact 公式）
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		// 本地、需高權限、無影響
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0},
		// requests 的 GHSA-9hjg-9r4m-mvj7（規劃 §3.2 引用的實測 vector）
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3},
		// CVSS 3.0 的 base 公式與 3.1 相同，只有 roundup 定義不同
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	}
	for _, c := range cases {
		got, err := CVSS31BaseScore(c.vector)
		if err != nil {
			t.Fatalf("CVSS31BaseScore(%q) 回傳錯誤: %v", c.vector, err)
		}
		if got != c.want {
			t.Errorf("CVSS31BaseScore(%q) = %.1f，預期 %.1f", c.vector, got, c.want)
		}
	}
}

func TestCVSS31BaseScoreRejectsV4(t *testing.T) {
	// 規劃 §3.2：只有 CVSS_V4 的項目不要硬算分數。
	v4 := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	if _, err := CVSS31BaseScore(v4); err == nil {
		t.Fatal("CVSS 4.0 vector 應該被拒絕，不可硬算分數")
	}
	if kind := CVSSVectorKind(v4); kind != "4.0" {
		t.Errorf("CVSSVectorKind = %q，預期 4.0", kind)
	}
}

func TestCVSS31BaseScoreBadInput(t *testing.T) {
	for _, v := range []string{
		"",
		"not-a-vector",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H", // 缺 S
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // AV 值無效
	} {
		if _, err := CVSS31BaseScore(v); err == nil {
			t.Errorf("CVSS31BaseScore(%q) 應該回傳錯誤", v)
		}
	}
}

func TestLevelFromScore(t *testing.T) {
	cases := []struct {
		score float64
		want  Level
	}{
		{0.0, LevelLow}, {3.9, LevelLow},
		{4.0, LevelMedium}, {6.9, LevelMedium},
		{7.0, LevelHigh}, {8.9, LevelHigh},
		{9.0, LevelCritical}, {10.0, LevelCritical},
	}
	for _, c := range cases {
		if got := LevelFromScore(c.score); got != c.want {
			t.Errorf("LevelFromScore(%.1f) = %v，預期 %v", c.score, got, c.want)
		}
	}
}

func TestParseLevelModerate(t *testing.T) {
	// GHSA 用 MODERATE，必須對應到 MEDIUM（規劃 §3.2 第 2 層）。
	lv, ok := ParseLevel("MODERATE")
	if !ok || lv != LevelMedium {
		t.Fatalf("ParseLevel(MODERATE) = %v, %v，預期 MEDIUM, true", lv, ok)
	}
	if _, ok := ParseLevel("BOGUS"); ok {
		t.Error("ParseLevel(BOGUS) 應該回傳 false")
	}
}
