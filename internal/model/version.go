package model

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/mod/semver"
)

// 生態系名稱常數，沿用 OSV 的寫法（規劃 §3.1）。
const (
	EcosystemGo     = "Go"
	EcosystemCrates = "crates.io"
	EcosystemPyPI   = "PyPI"
	EcosystemNPM    = "npm"
	EcosystemMaven  = "Maven"
	EcosystemNuGet  = "NuGet"
	// EcosystemLanguage 不是 OSV 的生態系，是本工具內部用來標記
	// 「程式語言執行環境」這類 target 的記號。
	EcosystemLanguage = "language"
)

// KnownEcosystems 是設定檔允許填寫的 ecosystem 值。
var KnownEcosystems = []string{
	EcosystemGo, EcosystemCrates, EcosystemPyPI,
	EcosystemNPM, EcosystemMaven, EcosystemNuGet,
}

// CanonicalEcosystem 把使用者填寫的 ecosystem 正規化成 OSV 用的大小寫。
// 回傳 ok=false 表示不是支援的生態系。
func CanonicalEcosystem(s string) (string, bool) {
	t := strings.TrimSpace(s)
	for _, e := range KnownEcosystems {
		if strings.EqualFold(t, e) {
			return e, true
		}
	}
	return t, false
}

// Comparer 比較同一個生態系內的兩個版本字串。
// 回傳 -1 / 0 / 1；任一邊無法解析時回傳 error。
type Comparer interface {
	Compare(a, b string) (int, error)
	// Name 用於報表上標註採用了哪種版本比較規則。
	Name() string
}

// ComparerFor 回傳該生態系的版本比較器；nil 表示本工具刻意不做版本比較。
//
// 規劃 §3.3 的 per-ecosystem 策略：
//   - Go：用 golang.org/x/mod/semver（Phase 1a）
//   - PyPI：PEP 440 簡化版自己寫（Phase 1a）
//   - crates.io / npm：標準 semver（npm 的非 semver 版本會退回列出候選）
//   - Maven / NuGet：不做比較，列出全部 fixed 版本並標註限制
func ComparerFor(ecosystem string) Comparer {
	switch ecosystem {
	case EcosystemGo, EcosystemLanguage:
		return goComparer{}
	case EcosystemPyPI:
		return pypiComparer{}
	case EcosystemCrates:
		// Cargo 用標準 semver。
		return semverComparer{label: "semver (Cargo)"}
	case EcosystemNPM:
		// npm 也是 semver，但歷史上存在少數非 semver 的版本號
		// （規劃 §3.3 的註記）。那些版本會讓 Compare 回傳 error，
		// SelectFix 收到 error 時會退回「列出全部候選」並標註原因，
		// 不會猜錯升級方向。
		return semverComparer{label: "semver (npm)"}
	default:
		// Maven / NuGet 永遠不做版本比較（規劃 §3.3）。
		return nil
	}
}

// semverComparer 用標準 semver 比較版本，給 crates.io 與 npm 使用。
// 與 goComparer 的差別只在錯誤訊息的措辭：Go 的版本字串本來就帶 v 前綴，
// 其他生態系不帶，混在同一個型別裡會讓錯誤訊息很難讀。
type semverComparer struct {
	label string
}

func (c semverComparer) Name() string { return c.label }

func (c semverComparer) Compare(a, b string) (int, error) {
	ca, err := canonicalSemver(a)
	if err != nil {
		return 0, err
	}
	cb, err := canonicalSemver(b)
	if err != nil {
		return 0, err
	}
	return semver.Compare(ca, cb), nil
}

// canonicalSemver 補上 golang.org/x/mod/semver 需要的 v 前綴並驗證格式。
func canonicalSemver(v string) (string, error) {
	s := strings.TrimSpace(v)
	if s == "" {
		return "", fmt.Errorf("版本為空")
	}
	if !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	if !semver.IsValid(s) {
		return "", fmt.Errorf("不是合法的 semver 版本: %q", v)
	}
	return s, nil
}

// IsValidSemverVersion 供設定檔驗證使用（crates.io / npm）。
func IsValidSemverVersion(v string) bool {
	_, err := canonicalSemver(v)
	return err == nil
}

type goComparer struct{}

func (goComparer) Name() string { return "semver (golang.org/x/mod/semver)" }

func (goComparer) Compare(a, b string) (int, error) {
	ca, err := canonicalGoVersion(a)
	if err != nil {
		return 0, err
	}
	cb, err := canonicalGoVersion(b)
	if err != nil {
		return 0, err
	}
	return semver.Compare(ca, cb), nil
}

// canonicalGoVersion 補上 Go 版本需要的 v 前綴並驗證格式。
func canonicalGoVersion(v string) (string, error) {
	s := strings.TrimSpace(v)
	if s == "" {
		return "", fmt.Errorf("Go 版本為空")
	}
	if !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	if !semver.IsValid(s) {
		return "", fmt.Errorf("不是合法的 Go semver 版本: %q", v)
	}
	return s, nil
}

// EnsureGoVersionPrefix 回傳帶 v 前綴的 Go 版本字串（規劃 §3.1 / §4.1）。
func EnsureGoVersionPrefix(v string) string {
	s := strings.TrimSpace(v)
	if s == "" || strings.HasPrefix(s, "v") {
		return s
	}
	return "v" + s
}

// IsValidGoVersion 供設定檔驗證使用。
func IsValidGoVersion(v string) bool {
	_, err := canonicalGoVersion(v)
	return err == nil
}

type pypiComparer struct{}

func (pypiComparer) Name() string { return "PEP 440" }

func (pypiComparer) Compare(a, b string) (int, error) {
	pa, err := ParsePEP440(a)
	if err != nil {
		return 0, err
	}
	pb, err := ParsePEP440(b)
	if err != nil {
		return 0, err
	}
	return comparePEP440(pa, pb), nil
}

// IsValidPyPIVersion 供設定檔驗證使用。
func IsValidPyPIVersion(v string) bool {
	_, err := ParsePEP440(v)
	return err == nil
}

// NormalizePackageName 依生態系規則正規化套件名稱。
// 目前只有 PyPI 需要（PEP 503）；其餘生態系大小寫有意義，原樣保留。
func NormalizePackageName(ecosystem, name string) string {
	if ecosystem == EcosystemPyPI {
		return NormalizePyPIName(name)
	}
	return strings.TrimSpace(name)
}

// SamePackage 判斷兩個 (ecosystem, name) 是否指同一個套件。
func SamePackage(ecoA, nameA, ecoB, nameB string) bool {
	if !strings.EqualFold(strings.TrimSpace(ecoA), strings.TrimSpace(ecoB)) {
		return false
	}
	return NormalizePackageName(ecoA, nameA) == NormalizePackageName(ecoB, nameB)
}

// LanguageSpec 是一個程式語言執行環境的查詢方式對照（規劃 §4：
// 「語言對應表寫成可擴充的 map，之後加 node/java/dotnet 只需加一筆」）。
type LanguageSpec struct {
	Name string
	// OSVEcosystem / OSVPackages：用 OSV 查執行環境弱點（Go 的 stdlib 與 toolchain）。
	OSVEcosystem string
	OSVPackages  []string
	// NVDCPE 是 NVD virtualMatchString 用的 vendor:product（Phase 2）。
	NVDCPE string
	// RustSecDirs 是 RustSec advisory-db 的 rust/ 子目錄（Phase 2）。
	RustSecDirs []string
	// EOLProduct 是 endoflife.date 的產品名。
	EOLProduct string
	// VulnSupported 表示本階段是否會掃這個語言的弱點清單。
	VulnSupported bool
	// PendingNote 是 VulnSupported 為 false 時要寫進報表的說明。
	PendingNote string
}

// Languages 是支援的程式語言對照表。設定檔的 [[languages]].name 必須在這裡。
var Languages = map[string]LanguageSpec{
	"go": {
		Name:          "go",
		OSVEcosystem:  EcosystemGo,
		OSVPackages:   []string{"stdlib", "toolchain"},
		EOLProduct:    "go",
		VulnSupported: true,
	},
	"python": {
		Name:          "python",
		NVDCPE:        "python:python",
		EOLProduct:    "python",
		VulnSupported: false,
		PendingNote:   "Phase 2 才支援 CVE 清單：NVD 的 CPE 比對誤報嚴重，需要規劃 §4.2 的 configurations 後處理",
	},
	"rust": {
		Name:          "rust",
		RustSecDirs:   []string{"std", "cargo", "rustdoc"},
		EOLProduct:    "rust",
		VulnSupported: false,
		PendingNote:   "Phase 2 才支援弱點清單：OSV 與 NVD 都查不到 Rust 工具鏈，需解析 RustSec advisory-db（規劃 §4.3）",
	},
}

// LanguageNames 回傳排序後的支援語言名稱，用於錯誤訊息。
func LanguageNames() []string {
	out := make([]string, 0, len(Languages))
	for k := range Languages {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
