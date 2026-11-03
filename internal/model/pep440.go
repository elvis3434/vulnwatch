package model

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// PEP 440 版本比較的簡化實作。規劃 §3.3 要求 PyPI 生態系必須能比較版本，
// 才能從 affected[].ranges 的多段中挑出包含目前版本的那一段。
// 規劃 §6 的相依白名單不含 PEP 440 套件，所以自己寫。
//
// 支援：epoch（N!）、release（N.N.N...）、pre（a/b/rc，含 alpha/beta/c/pre/preview 別名）、
// post（.postN，含 rev/r/-N 別名）、dev（.devN）、local（+xxx）。
// 排序規則照 PEP 440 的 reference implementation（packaging 的 _cmpkey）：
//   dev < pre < final < post，且「有 dev 但沒有 pre」要排在所有 pre 之前。

var pep440Re = regexp.MustCompile(`^\s*v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_\.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_\.]?[0-9]*)?` +
	`(?P<post>(?:-[0-9]+)|(?:[-_\.]?(?:post|rev|r)[-_\.]?[0-9]*))?` +
	`(?P<dev>[-_\.]?dev[-_\.]?[0-9]*)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?` +
	`\s*$`)

// 這三個哨兵值用來表達 PEP 440 的 Infinity / NegativeInfinity 排序語意。
const (
	pep440NegInf = -1
	pep440Exact  = 0
	pep440PosInf = 1
)

type pep440Pre struct {
	// state 為 pep440NegInf / pep440Exact / pep440PosInf
	state  int
	letter string
	num    int
}

type pep440Version struct {
	epoch   int
	release []int
	pre     pep440Pre
	// post：state 為 pep440NegInf（沒有 post）或 pep440Exact
	postState int
	postNum   int
	// dev：state 為 pep440PosInf（沒有 dev）或 pep440Exact
	devState int
	devNum   int
	local    []pep440LocalPart
}

type pep440LocalPart struct {
	// isNum 為 true 時用 num，否則用 str。PEP 440：數字段大於字串段。
	isNum bool
	num   int
	str   string
}

// ParsePEP440 解析 PyPI 版本字串。
func ParsePEP440(s string) (pep440Version, error) {
	var v pep440Version
	m := pep440Re.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return v, fmt.Errorf("不是合法的 PEP 440 版本: %q", s)
	}
	get := func(name string) string {
		return m[pep440Re.SubexpIndex(name)]
	}

	if e := get("epoch"); e != "" {
		n, err := strconv.Atoi(e)
		if err != nil {
			return v, fmt.Errorf("版本 %q 的 epoch 無法解析: %w", s, err)
		}
		v.epoch = n
	}

	for _, seg := range strings.Split(get("release"), ".") {
		n, err := strconv.Atoi(seg)
		if err != nil {
			return v, fmt.Errorf("版本 %q 的 release 段 %q 無法解析: %w", s, seg, err)
		}
		v.release = append(v.release, n)
	}

	preRaw := get("pre")
	postRaw := get("post")
	devRaw := get("dev")

	if preRaw != "" {
		letter, num, err := splitPEP440Tag(preRaw, []string{"alpha", "beta", "preview", "pre", "rc", "a", "b", "c"})
		if err != nil {
			return v, fmt.Errorf("版本 %q 的 pre 段無法解析: %w", s, err)
		}
		// PEP 440 正規化：alpha→a、beta→b、c/pre/preview→rc
		switch letter {
		case "alpha":
			letter = "a"
		case "beta":
			letter = "b"
		case "c", "pre", "preview":
			letter = "rc"
		}
		v.pre = pep440Pre{state: pep440Exact, letter: letter, num: num}
	}

	if postRaw != "" {
		v.postState = pep440Exact
		if strings.HasPrefix(postRaw, "-") && !strings.ContainsAny(postRaw, "postrev") {
			// 隱含 post 寫法：1.0-1 等同 1.0.post1
			n, err := strconv.Atoi(strings.TrimPrefix(postRaw, "-"))
			if err != nil {
				return v, fmt.Errorf("版本 %q 的 post 段無法解析: %w", s, err)
			}
			v.postNum = n
		} else {
			_, num, err := splitPEP440Tag(postRaw, []string{"post", "rev", "r"})
			if err != nil {
				return v, fmt.Errorf("版本 %q 的 post 段無法解析: %w", s, err)
			}
			v.postNum = num
		}
	} else {
		v.postState = pep440NegInf
	}

	if devRaw != "" {
		_, num, err := splitPEP440Tag(devRaw, []string{"dev"})
		if err != nil {
			return v, fmt.Errorf("版本 %q 的 dev 段無法解析: %w", s, err)
		}
		v.devState = pep440Exact
		v.devNum = num
	} else {
		v.devState = pep440PosInf
	}

	// PEP 440 reference implementation 的排序哨兵。
	// 注意不能用 v.pre.state 的零值判斷「有沒有 pre」：pep440Exact 剛好是 0。
	if preRaw == "" {
		if v.postState == pep440NegInf && v.devState == pep440Exact {
			// 只有 dev、沒有 pre 也沒有 post → 排在所有 pre 之前
			v.pre.state = pep440NegInf
		} else {
			// 沒有 pre → 排在所有 pre 之後
			v.pre.state = pep440PosInf
		}
	}

	if loc := get("local"); loc != "" {
		for _, seg := range regexp.MustCompile(`[-_\.]`).Split(loc, -1) {
			if n, err := strconv.Atoi(seg); err == nil {
				v.local = append(v.local, pep440LocalPart{isNum: true, num: n})
			} else {
				v.local = append(v.local, pep440LocalPart{str: seg})
			}
		}
	}

	return v, nil
}

// splitPEP440Tag 把 ".post3" / "-rc1" / "dev" 這類片段拆成標籤與數字。
func splitPEP440Tag(raw string, names []string) (string, int, error) {
	s := strings.Trim(raw, "-_.")
	for _, name := range names {
		if strings.HasPrefix(s, name) {
			rest := strings.Trim(strings.TrimPrefix(s, name), "-_.")
			if rest == "" {
				return name, 0, nil
			}
			n, err := strconv.Atoi(rest)
			if err != nil {
				return name, 0, err
			}
			return name, n, nil
		}
	}
	return "", 0, fmt.Errorf("無法辨識的版本標籤 %q", raw)
}

func comparePEP440(a, b pep440Version) int {
	if c := compareInt(a.epoch, b.epoch); c != 0 {
		return c
	}
	if c := compareReleases(a.release, b.release); c != 0 {
		return c
	}
	if c := comparePre(a.pre, b.pre); c != 0 {
		return c
	}
	// post：沒有 post 是 NegativeInfinity
	if c := compareInt(a.postState, b.postState); c != 0 {
		return c
	}
	if a.postState == pep440Exact {
		if c := compareInt(a.postNum, b.postNum); c != 0 {
			return c
		}
	}
	// dev：沒有 dev 是 Infinity
	if c := compareInt(a.devState, b.devState); c != 0 {
		return c
	}
	if a.devState == pep440Exact {
		if c := compareInt(a.devNum, b.devNum); c != 0 {
			return c
		}
	}
	return compareLocal(a.local, b.local)
}

func comparePre(a, b pep440Pre) int {
	if c := compareInt(a.state, b.state); c != 0 {
		return c
	}
	if a.state != pep440Exact {
		return 0
	}
	// a < b < rc，字典順序正好符合
	if c := strings.Compare(a.letter, b.letter); c != 0 {
		return c
	}
	return compareInt(a.num, b.num)
}

// compareReleases 比較 release 段，短的那邊補 0（1.2 == 1.2.0）。
func compareReleases(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := compareInt(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// compareLocal：有 local 的版本大於沒有 local 的；數字段大於字串段。
func compareLocal(a, b []pep440LocalPart) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return -1
	}
	if len(b) == 0 {
		return 1
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		x, y := a[i], b[i]
		switch {
		case x.isNum && y.isNum:
			if c := compareInt(x.num, y.num); c != 0 {
				return c
			}
		case x.isNum && !y.isNum:
			return 1
		case !x.isNum && y.isNum:
			return -1
		default:
			if c := strings.Compare(x.str, y.str); c != 0 {
				return c
			}
		}
	}
	return compareInt(len(a), len(b))
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// NormalizePyPIName 做 PEP 503 的名稱正規化：小寫，且 - _ . 連續段一律轉成單一 -。
func NormalizePyPIName(name string) string {
	return regexp.MustCompile(`[-_.]+`).ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}
