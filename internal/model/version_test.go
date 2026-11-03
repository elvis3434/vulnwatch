package model

import "testing"

func TestPEP440Ordering(t *testing.T) {
	// PEP 440 的標準排序：dev < pre < final < post
	ordered := []string{
		"1.0.dev1",
		"1.0a1",
		"1.0a2.dev1",
		"1.0a2",
		"1.0b1",
		"1.0rc1",
		"1.0",
		"1.0.post1",
		"1.0.1",
		"1.1",
		"1.26.5",
		"1.26.18",
		"1.26.19",
		"2.0.0",
		"2.2.1",
		"2.2.2",
		"2!1.0",
	}
	cmp := pypiComparer{}
	for i := 0; i+1 < len(ordered); i++ {
		a, b := ordered[i], ordered[i+1]
		c, err := cmp.Compare(a, b)
		if err != nil {
			t.Fatalf("Compare(%q, %q) 錯誤: %v", a, b, err)
		}
		if c != -1 {
			t.Errorf("Compare(%q, %q) = %d，預期 -1（%q 應該小於 %q）", a, b, c, a, b)
		}
	}
}

func TestPEP440Equality(t *testing.T) {
	cmp := pypiComparer{}
	cases := [][2]string{
		{"1.0", "1.0.0"},
		{"1.0", "1.0.0.0"},
		{"1.0a1", "1.0alpha1"},
		{"1.0b2", "1.0beta2"},
		{"1.0rc1", "1.0c1"},
		{"1.0.post1", "1.0-1"},
		{"1.0", "v1.0"},
		{"1.0", " 1.0 "},
		{"1.0.DEV1", "1.0.dev1"},
	}
	for _, c := range cases {
		got, err := cmp.Compare(c[0], c[1])
		if err != nil {
			t.Fatalf("Compare(%q, %q) 錯誤: %v", c[0], c[1], err)
		}
		if got != 0 {
			t.Errorf("Compare(%q, %q) = %d，預期 0（兩者等價）", c[0], c[1], got)
		}
	}
}

func TestPEP440Local(t *testing.T) {
	cmp := pypiComparer{}
	// 有 local 版本大於沒有 local 的
	if c, err := cmp.Compare("1.0", "1.0+local"); err != nil || c != -1 {
		t.Errorf("Compare(1.0, 1.0+local) = %d, %v，預期 -1", c, err)
	}
	if c, err := cmp.Compare("1.0+abc", "1.0+1"); err != nil || c != -1 {
		t.Errorf("Compare(1.0+abc, 1.0+1) = %d, %v，預期 -1（數字段大於字串段）", c, err)
	}
}

func TestPEP440Invalid(t *testing.T) {
	for _, v := range []string{"", "abc", "1.0.x", "latest", ">=1.0"} {
		if _, err := ParsePEP440(v); err == nil {
			t.Errorf("ParsePEP440(%q) 應該回傳錯誤", v)
		}
	}
}

func TestNormalizePyPIName(t *testing.T) {
	// PEP 503：小寫，且 - _ . 連續段轉成單一 -
	cases := map[string]string{
		"Requests":         "requests",
		"zope.interface":   "zope-interface",
		"my_package":       "my-package",
		"My.Weird__Name":   "my-weird-name",
		"ruamel.yaml.clib": "ruamel-yaml-clib",
	}
	for in, want := range cases {
		if got := NormalizePyPIName(in); got != want {
			t.Errorf("NormalizePyPIName(%q) = %q，預期 %q", in, got, want)
		}
	}
}

func TestGoComparer(t *testing.T) {
	cmp := ComparerFor(EcosystemGo)
	if cmp == nil {
		t.Fatal("Go 應該有版本比較器（規劃 §3.3）")
	}
	// 不帶 v 前綴也要能比（內部會補上）
	if c, err := cmp.Compare("v0.20.0", "0.23.0"); err != nil || c != -1 {
		t.Errorf("Compare(v0.20.0, 0.23.0) = %d, %v，預期 -1", c, err)
	}
	if c, err := cmp.Compare("v1.21.8", "v1.21.8"); err != nil || c != 0 {
		t.Errorf("Compare 相同版本 = %d, %v，預期 0", c, err)
	}
	// 1.22.0-0 這種 pre-release 哨兵小於 1.22.0
	if c, err := cmp.Compare("v1.22.0-0", "v1.22.0"); err != nil || c != -1 {
		t.Errorf("Compare(v1.22.0-0, v1.22.0) = %d, %v，預期 -1", c, err)
	}
	if _, err := cmp.Compare("not-a-version", "v1.0.0"); err == nil {
		t.Error("無法解析的版本應該回傳錯誤")
	}
}

func TestComparerForEcosystems(t *testing.T) {
	// 規劃 §3.3：Go 與 PyPI 做比較；Maven / NuGet 永遠不做；
	// crates.io / npm 留到 Phase 2。
	for _, eco := range []string{EcosystemGo, EcosystemPyPI} {
		if ComparerFor(eco) == nil {
			t.Errorf("%s 應該有版本比較器", eco)
		}
	}
	for _, eco := range []string{EcosystemMaven, EcosystemNuGet, EcosystemCrates, EcosystemNPM} {
		if ComparerFor(eco) != nil {
			t.Errorf("%s 這個階段不該有版本比較器", eco)
		}
	}
}

func TestCanonicalEcosystem(t *testing.T) {
	if eco, ok := CanonicalEcosystem("pypi"); !ok || eco != EcosystemPyPI {
		t.Errorf("CanonicalEcosystem(pypi) = %q, %v，預期 PyPI, true", eco, ok)
	}
	if eco, ok := CanonicalEcosystem("CRATES.IO"); !ok || eco != EcosystemCrates {
		t.Errorf("CanonicalEcosystem(CRATES.IO) = %q, %v，預期 crates.io, true", eco, ok)
	}
	if _, ok := CanonicalEcosystem("Golang"); ok {
		t.Error("Golang 不是合法的 ecosystem 值（應填 Go）")
	}
}

func TestSamePackage(t *testing.T) {
	// PyPI 名稱要經過 PEP 503 正規化才比較
	if !SamePackage("PyPI", "zope.interface", "PyPI", "zope-interface") {
		t.Error("PyPI 名稱應該經過 PEP 503 正規化後相符")
	}
	// Go module path 大小寫有意義，但 ecosystem 名稱比較不分大小寫
	if !SamePackage("Go", "golang.org/x/net", "go", "golang.org/x/net") {
		t.Error("ecosystem 比較應該不分大小寫")
	}
	if SamePackage("Go", "golang.org/x/net", "Go", "golang.org/x/text") {
		t.Error("不同 module 不該相符")
	}
}
