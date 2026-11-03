// Package config 負責 TOML 設定檔的載入與驗證、purl 解析與套件名稱正規化。
//
// 驗證失敗時回傳的錯誤帶「檔名:行號」與欄位名（規劃 §9 第一條驗收標準）。
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/elvis3434/vulnwatch/internal/model"
)

// 預設值。
const (
	DefaultKeepReports = 30
	DefaultTimezone    = "Local"
)

// General 對應 [general]。
type General struct {
	ReportDir     string   `toml:"report_dir"`
	CacheDir      string   `toml:"cache_dir"`
	LogFile       string   `toml:"log_file"`
	Timezone      string   `toml:"timezone"`
	ReportFormats []string `toml:"report_formats"`
	KeepReports   int      `toml:"keep_reports"`
	MinSeverity   string   `toml:"min_severity"`
	FailOn        string   `toml:"fail_on"`
	HTTPTimeout   string   `toml:"http_timeout"`
	CacheTTL      string   `toml:"cache_ttl"`
}

// Network 對應 [network]。刻意不提供停用憑證驗證的選項（規劃 §3.4）。
type Network struct {
	Proxy  string `toml:"proxy"`
	CAFile string `toml:"ca_file"`
}

// Sources 對應 [sources]。
type Sources struct {
	OSV     bool `toml:"osv"`
	NVD     bool `toml:"nvd"`
	RustSec bool `toml:"rustsec"`
	EOL     bool `toml:"eol"`
	DepsDev bool `toml:"deps_dev"`
	KEV     bool `toml:"kev"`
	EPSS    bool `toml:"epss"`
}

// Language 對應 [[languages]]。
type Language struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

// Package 對應 [[packages]]。ecosystem+name 與 purl 擇一填寫。
type Package struct {
	Ecosystem string `toml:"ecosystem"`
	Name      string `toml:"name"`
	Version   string `toml:"version"`
	Note      string `toml:"note"`
	Purl      string `toml:"purl"`
}

// Manifest 對應 [[manifests]]（Phase 3）。
type Manifest struct {
	Path string `toml:"path"`
}

// Ignore 對應 [[ignore]]。
type Ignore struct {
	ID        string `toml:"id"`
	Ecosystem string `toml:"ecosystem"`
	Name      string `toml:"name"`
	Reason    string `toml:"reason"`
	Expires   string `toml:"expires"`
}

// ExpiresTime 解析 expires（YYYY-MM-DD）。空字串回傳零值。
func (ig Ignore) ExpiresTime() (time.Time, error) {
	if strings.TrimSpace(ig.Expires) == "" {
		return time.Time{}, nil
	}
	return time.ParseInLocation("2006-01-02", strings.TrimSpace(ig.Expires), time.UTC)
}

// Expired 判斷這筆忽略是否已到期（到期後照常列入報表，規劃 §3.4）。
func (ig Ignore) Expired(now time.Time) bool {
	t, err := ig.ExpiresTime()
	if err != nil || t.IsZero() {
		return false
	}
	// expires = 當天仍然有效，隔天才算到期。
	return now.UTC().After(t.AddDate(0, 0, 1).Add(-time.Nanosecond))
}

// Matches 判斷這筆忽略是否命中某個弱點。
// ecosystem / name 省略時代表對所有套件忽略此 ID（規劃 §3.4）。
func (ig Ignore) Matches(eco, name, id string, aliases []string) bool {
	hit := strings.EqualFold(strings.TrimSpace(ig.ID), id)
	if !hit {
		for _, a := range aliases {
			if strings.EqualFold(strings.TrimSpace(ig.ID), a) {
				hit = true
				break
			}
		}
	}
	if !hit {
		return false
	}
	if strings.TrimSpace(ig.Ecosystem) != "" && !strings.EqualFold(strings.TrimSpace(ig.Ecosystem), eco) {
		return false
	}
	if strings.TrimSpace(ig.Name) != "" {
		if model.NormalizePackageName(eco, ig.Name) != model.NormalizePackageName(eco, name) {
			return false
		}
	}
	return true
}

// Config 是整份設定檔。
type Config struct {
	General   General    `toml:"general"`
	Network   Network    `toml:"network"`
	Sources   Sources    `toml:"sources"`
	Languages []Language `toml:"languages"`
	Packages  []Package  `toml:"packages"`
	Manifests []Manifest `toml:"manifests"`
	Ignore    []Ignore   `toml:"ignore"`

	// 以下是驗證後導出的欄位，不從 TOML 讀取。
	Path         string         `toml:"-"`
	Location     *time.Location `toml:"-"`
	HTTPTimeoutD time.Duration  `toml:"-"`
	CacheTTLD    time.Duration  `toml:"-"`
	MinLevel     model.Level    `toml:"-"`
	FailOnLevel  model.Level    `toml:"-"`
	FailOnSet    bool           `toml:"-"`
	Formats      []string       `toml:"-"`
	// Warnings 是不致命的設定問題，必須寫進報表的「錯誤 / 警告」區
	// （規劃 §3.4：不可靜默忽略）。
	Warnings []Diag `toml:"-"`
}

// Diag 是一筆設定檔診斷訊息。
type Diag struct {
	Path  string
	Line  int
	Field string
	Msg   string
}

func (d Diag) String() string {
	loc := d.Path
	if loc == "" {
		loc = "設定檔"
	}
	if d.Line > 0 {
		loc = fmt.Sprintf("%s:%d", loc, d.Line)
	}
	if d.Field != "" {
		return fmt.Sprintf("%s: %s: %s", loc, d.Field, d.Msg)
	}
	return fmt.Sprintf("%s: %s", loc, d.Msg)
}

// Errors 是多筆設定檔錯誤。check 會把全部印出來，而不是只印第一筆。
type Errors struct {
	Diags []Diag
}

func (e *Errors) Error() string {
	parts := make([]string, 0, len(e.Diags))
	for _, d := range e.Diags {
		parts = append(parts, d.String())
	}
	return strings.Join(parts, "\n")
}

// IsEmpty 回傳是否沒有任何錯誤。
func (e *Errors) IsEmpty() bool { return e == nil || len(e.Diags) == 0 }

type validator struct {
	path  string
	idx   *lineIndex
	errs  []Diag
	warns []Diag
}

func (v *validator) errf(line int, field, format string, args ...any) {
	v.errs = append(v.errs, Diag{Path: v.path, Line: line, Field: field, Msg: fmt.Sprintf(format, args...)})
}

func (v *validator) warnf(line int, field, format string, args ...any) {
	v.warns = append(v.warns, Diag{Path: v.path, Line: line, Field: field, Msg: fmt.Sprintf(format, args...)})
}

// Load 讀取並驗證設定檔。回傳的 error 若為 *Errors 代表設定檔有問題（exit code 2）。
func Load(path string) (*Config, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("讀取設定檔 %s 失敗: %w", path, err)
	}
	return Parse(src, path)
}

// Parse 解析並驗證設定檔內容。path 只用於錯誤訊息。
func Parse(src []byte, path string) (*Config, error) {
	display := filepath.Base(path)
	if display == "." || display == string(filepath.Separator) {
		display = path
	}

	// 先填預設值：go-toml 只會覆寫設定檔中出現的鍵，
	// 所以 [sources] 省略時預設全部啟用。
	cfg := &Config{
		General: General{
			Timezone:    DefaultTimezone,
			KeepReports: DefaultKeepReports,
			MinSeverity: model.LevelNameLow,
		},
		Sources: Sources{
			OSV: true, NVD: true, RustSec: true, EOL: true,
			DepsDev: true, KEV: true, EPSS: true,
		},
		Path: path,
	}

	dec := toml.NewDecoder(strings.NewReader(string(src)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, decodeErrors(err, display)
	}

	v := &validator{path: display, idx: newLineIndex(src)}
	validate(cfg, v)

	cfg.Warnings = v.warns
	if len(v.errs) > 0 {
		return cfg, &Errors{Diags: v.errs}
	}
	return cfg, nil
}

// decodeErrors 把 go-toml 的解碼錯誤轉成帶行號的 Diag。
// go-toml/v2 的 *toml.DecodeError 本身就有 Row()/Column()/Key()，
// 這正是規劃 §3 選用它的原因。
func decodeErrors(err error, path string) error {
	var strictErr *toml.StrictMissingError
	if errors.As(err, &strictErr) {
		diags := make([]Diag, 0, len(strictErr.Errors))
		for i := range strictErr.Errors {
			de := &strictErr.Errors[i]
			row, _ := de.Position()
			diags = append(diags, Diag{
				Path:  path,
				Line:  row,
				Field: strings.Join(de.Key(), "."),
				Msg:   "不認得這個設定項目（可能是拼錯了）",
			})
		}
		return &Errors{Diags: diags}
	}

	var decErr *toml.DecodeError
	if errors.As(err, &decErr) {
		row, col := decErr.Position()
		field := strings.Join(decErr.Key(), ".")
		return &Errors{Diags: []Diag{{
			Path:  path,
			Line:  row,
			Field: field,
			Msg:   fmt.Sprintf("TOML 格式錯誤（第 %d 欄）: %s", col, decErr.Error()),
		}}}
	}

	return &Errors{Diags: []Diag{{Path: path, Msg: fmt.Sprintf("TOML 解析失敗: %v", err)}}}
}

func validate(cfg *Config, v *validator) {
	validateGeneral(cfg, v)
	validateNetwork(cfg, v)
	validateLanguages(cfg, v)
	validatePackages(cfg, v)
	validateIgnore(cfg, v)

	for i := range cfg.Manifests {
		line := v.idx.arrayKey("manifests", i, "path")
		v.warnf(line, "manifests.path", "[[manifests]] 自動匯入相依檔是 Phase 3 功能，本次執行會忽略這筆設定")
	}

	if len(cfg.Packages) == 0 && len(cfg.Languages) == 0 {
		v.errf(0, "packages/languages", "設定檔沒有任何 [[packages]] 或 [[languages]]，沒有東西可以掃描")
	}

	if !cfg.Sources.OSV {
		v.warnf(v.idx.tableKey("sources", "osv"), "sources.osv",
			"[sources].osv = false：OSV 是套件弱點的主力來源，關掉之後套件弱點清單一定是空的")
	}
}

func validateGeneral(cfg *Config, v *validator) {
	g := &cfg.General

	// report_dir / cache_dir 必填且建議絕對路徑：排程器的工作目錄不一定是
	// exe 所在目錄（規劃 §8），相對路徑會讓報表跑到意想不到的地方。
	if strings.TrimSpace(g.ReportDir) == "" {
		v.errf(v.idx.tableKey("general", "report_dir"), "general.report_dir", "必填：報表輸出目錄，請填絕對路徑")
	} else if !looksAbsolute(g.ReportDir) {
		v.warnf(v.idx.tableKey("general", "report_dir"), "general.report_dir",
			"建議改用絕對路徑：Windows 工作排程器的工作目錄不一定是執行檔所在目錄（規劃 §8）")
	}
	if strings.TrimSpace(g.CacheDir) == "" {
		v.errf(v.idx.tableKey("general", "cache_dir"), "general.cache_dir", "必填：快取目錄，請填絕對路徑")
	} else if !looksAbsolute(g.CacheDir) {
		v.warnf(v.idx.tableKey("general", "cache_dir"), "general.cache_dir",
			"建議改用絕對路徑：Windows 工作排程器的工作目錄不一定是執行檔所在目錄（規劃 §8）")
	}
	if lf := strings.TrimSpace(g.LogFile); lf != "" && !looksAbsolute(lf) {
		v.warnf(v.idx.tableKey("general", "log_file"), "general.log_file", "建議改用絕對路徑")
	}

	// timezone：Windows 沒有系統 tzdata，所以 main.go 一定要 import _ "time/tzdata"（規劃 §6）。
	tz := strings.TrimSpace(g.Timezone)
	if tz == "" {
		tz = DefaultTimezone
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		v.errf(v.idx.tableKey("general", "timezone"), "general.timezone",
			"無法載入時區 %q: %v", tz, err)
		cfg.Location = time.Local
	} else {
		cfg.Location = loc
	}

	// report_formats：Phase 1 只支援 md / json；其餘要明確 warning（規劃 §3.4）。
	formatsLine := v.idx.tableKey("general", "report_formats")
	if len(g.ReportFormats) == 0 {
		cfg.Formats = []string{"md", "json"}
	} else {
		for _, f := range g.ReportFormats {
			switch strings.ToLower(strings.TrimSpace(f)) {
			case "md", "markdown":
				cfg.Formats = appendUnique(cfg.Formats, "md")
			case "json":
				cfg.Formats = appendUnique(cfg.Formats, "json")
			case "html":
				v.warnf(formatsLine, "general.report_formats",
					"html 報表是 Phase 2 功能，本次不會產生 html；已改用 md + json")
			default:
				v.warnf(formatsLine, "general.report_formats",
					"不支援的報表格式 %q（支援：md、json）", f)
			}
		}
		if len(cfg.Formats) == 0 {
			v.warnf(formatsLine, "general.report_formats", "沒有任何支援的格式，退回預設的 md + json")
			cfg.Formats = []string{"md", "json"}
		}
	}

	if g.KeepReports < 0 {
		v.errf(v.idx.tableKey("general", "keep_reports"), "general.keep_reports",
			"不可為負數（%d）；0 表示不清理舊報表", g.KeepReports)
	}

	// min_severity / fail_on 只接受 ""、LOW、MEDIUM、HIGH、CRITICAL（不接受 UNKNOWN）。
	cfg.MinLevel = model.LevelLow
	if s := strings.TrimSpace(g.MinSeverity); s != "" {
		lv, ok := parseThreshold(s)
		if !ok {
			v.errf(v.idx.tableKey("general", "min_severity"), "general.min_severity",
				"只接受 \"\"、LOW、MEDIUM、HIGH、CRITICAL（不接受 UNKNOWN），目前是 %q", g.MinSeverity)
		} else {
			cfg.MinLevel = lv
		}
	}

	if s := strings.TrimSpace(g.FailOn); s != "" {
		lv, ok := parseThreshold(s)
		if !ok {
			v.errf(v.idx.tableKey("general", "fail_on"), "general.fail_on",
				"只接受 \"\"、LOW、MEDIUM、HIGH、CRITICAL（不接受 UNKNOWN），目前是 %q", g.FailOn)
		} else {
			cfg.FailOnLevel = lv
			cfg.FailOnSet = true
		}
	}

	cfg.HTTPTimeoutD = 30 * time.Second
	if s := strings.TrimSpace(g.HTTPTimeout); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			v.errf(v.idx.tableKey("general", "http_timeout"), "general.http_timeout",
				"不是合法的時間長度（例如 \"30s\"）: %q", g.HTTPTimeout)
		} else {
			cfg.HTTPTimeoutD = d
		}
	}

	cfg.CacheTTLD = 12 * time.Hour
	if s := strings.TrimSpace(g.CacheTTL); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d < 0 {
			v.errf(v.idx.tableKey("general", "cache_ttl"), "general.cache_ttl",
				"不是合法的時間長度（例如 \"12h\"）: %q", g.CacheTTL)
		} else {
			cfg.CacheTTLD = d
		}
	}
}

// parseThreshold 解析 min_severity / fail_on。刻意不接受 UNKNOWN：
// UNKNOWN 不是門檻值，它永遠不受 min_severity 影響（規劃 §3.2）。
func parseThreshold(s string) (model.Level, bool) {
	up := strings.ToUpper(strings.TrimSpace(s))
	if up == model.LevelNameUnknown {
		return model.LevelUnknown, false
	}
	lv, ok := model.ParseLevel(up)
	if !ok || lv == model.LevelUnknown {
		return model.LevelUnknown, false
	}
	return lv, true
}

func validateNetwork(cfg *Config, v *validator) {
	if p := strings.TrimSpace(cfg.Network.Proxy); p != "" {
		if !strings.Contains(p, "://") {
			v.errf(v.idx.tableKey("network", "proxy"), "network.proxy",
				"需要完整的 URL，例如 http://proxy.example.com:8080（目前是 %q）", p)
		}
	}
	if ca := strings.TrimSpace(cfg.Network.CAFile); ca != "" {
		if st, err := os.Stat(ca); err != nil {
			v.errf(v.idx.tableKey("network", "ca_file"), "network.ca_file", "找不到憑證檔 %q: %v", ca, err)
		} else if st.IsDir() {
			v.errf(v.idx.tableKey("network", "ca_file"), "network.ca_file", "%q 是目錄，不是憑證檔", ca)
		}
	}
}

func validateLanguages(cfg *Config, v *validator) {
	for i, lang := range cfg.Languages {
		nameLine := v.idx.arrayKey("languages", i, "name")
		name := strings.ToLower(strings.TrimSpace(lang.Name))
		if name == "" {
			v.errf(v.idx.arrayLine("languages", i), "languages.name", "必填：程式語言名稱")
			continue
		}
		spec, ok := model.Languages[name]
		if !ok {
			v.errf(nameLine, "languages.name",
				"不支援的語言 %q（支援：%s）", lang.Name, strings.Join(model.LanguageNames(), "、"))
			continue
		}
		cfg.Languages[i].Name = name

		verLine := v.idx.arrayKey("languages", i, "version")
		ver := strings.TrimSpace(lang.Version)
		if ver == "" {
			v.errf(v.idx.arrayLine("languages", i), "languages.version",
				"必填：%s 實際使用的版本（例如 go 可用 `go version` 確認）", name)
			continue
		}
		cfg.Languages[i].Version = ver
		if !looksLikeDottedVersion(ver) {
			v.errf(verLine, "languages.version",
				"版本格式看起來不對 %q，預期像 1.27.3 這樣的數字版本", ver)
			continue
		}
		if !spec.VulnSupported {
			v.warnf(v.idx.arrayLine("languages", i), "languages."+name, "%s", spec.PendingNote)
		}
	}
}

func looksLikeDottedVersion(v string) bool {
	s := strings.TrimPrefix(strings.TrimSpace(v), "v")
	if s == "" {
		return false
	}
	for _, seg := range strings.Split(s, ".") {
		if seg == "" {
			return false
		}
		for _, r := range seg {
			if r < '0' || r > '9' {
				// 允許 1.82.0-beta 這類後綴，只檢查第一段必須是數字。
				return strings.IndexAny(s, "0123456789") == 0
			}
		}
	}
	return true
}

func validatePackages(cfg *Config, v *validator) {
	for i := range cfg.Packages {
		p := &cfg.Packages[i]
		entryLine := v.idx.arrayLine("packages", i)

		if purl := strings.TrimSpace(p.Purl); purl != "" {
			purlLine := v.idx.arrayKey("packages", i, "purl")
			if strings.TrimSpace(p.Ecosystem) != "" || strings.TrimSpace(p.Name) != "" {
				v.errf(purlLine, "packages.purl",
					"purl 與 ecosystem/name 只能填一種（擇一即可，規劃 §3.1）")
				continue
			}
			eco, name, ver, err := ParsePurl(purl)
			if err != nil {
				v.errf(purlLine, "packages.purl", "%v", err)
				continue
			}
			p.Ecosystem, p.Name = eco, name
			if ver != "" {
				p.Version = ver
			}
		}

		ecoLine := v.idx.arrayKey("packages", i, "ecosystem")
		if strings.TrimSpace(p.Ecosystem) == "" {
			v.errf(entryLine, "packages.ecosystem",
				"必填：生態系（支援：%s），或改用 purl", strings.Join(model.KnownEcosystems, "、"))
			continue
		}
		eco, ok := model.CanonicalEcosystem(p.Ecosystem)
		if !ok {
			v.errf(ecoLine, "packages.ecosystem",
				"不支援的生態系 %q（支援：%s）", p.Ecosystem, strings.Join(model.KnownEcosystems, "、"))
			continue
		}
		p.Ecosystem = eco

		if strings.TrimSpace(p.Name) == "" {
			v.errf(entryLine, "packages.name", "必填：套件名稱")
			continue
		}
		p.Name = strings.TrimSpace(p.Name)

		verLine := v.idx.arrayKey("packages", i, "version")
		p.Version = strings.TrimSpace(p.Version)
		if p.Version == "" {
			// 規劃 §3.1：version 省略時列出全部已知弱點並標示無法判定。
			v.warnf(entryLine, "packages.version",
				"%s/%s 未指定版本：會列出該套件全部已知弱點，無法判定是否真的受影響", p.Ecosystem, p.Name)
			continue
		}

		switch eco {
		case model.EcosystemGo:
			if !strings.HasPrefix(p.Version, "v") {
				v.warnf(verLine, "packages.version",
					"Go 版本需要 v 前綴（規劃 §3.1），已自動視為 %q", "v"+p.Version)
				p.Version = model.EnsureGoVersionPrefix(p.Version)
			}
			if !model.IsValidGoVersion(p.Version) {
				v.errf(verLine, "packages.version", "不是合法的 Go semver 版本: %q", p.Version)
			}
		case model.EcosystemPyPI:
			if !model.IsValidPyPIVersion(p.Version) {
				v.errf(verLine, "packages.version", "不是合法的 PEP 440 版本: %q", p.Version)
			}
			if strings.HasPrefix(p.Version, "v") {
				v.warnf(verLine, "packages.version", "PyPI 版本不需要 v 前綴（規劃 §3.1）")
			}
		default:
			if strings.HasPrefix(p.Version, "v") && eco != model.EcosystemGo {
				v.warnf(verLine, "packages.version", "%s 的版本通常不加 v 前綴（規劃 §3.1）", eco)
			}
		}

		if model.ComparerFor(eco) == nil {
			switch eco {
			case model.EcosystemMaven, model.EcosystemNuGet:
				v.warnf(entryLine, "packages.ecosystem",
					"%s 不做版本比較（規劃 §3.3）：%s 的「最低安全版本」會列出全部候選，請自行確認對應的版本線",
					eco, p.Name)
			default:
				v.warnf(entryLine, "packages.ecosystem",
					"%s 的版本比較是 Phase 2 功能：%s 的「最低安全版本」會列出全部候選",
					eco, p.Name)
			}
		}
	}
}

func validateIgnore(cfg *Config, v *validator) {
	for i := range cfg.Ignore {
		ig := &cfg.Ignore[i]
		entryLine := v.idx.arrayLine("ignore", i)

		if strings.TrimSpace(ig.ID) == "" {
			v.errf(entryLine, "ignore.id", "必填：要忽略的弱點 ID（例如 GO-2024-0000 或 CVE-2024-0000）")
			continue
		}
		ig.ID = strings.TrimSpace(ig.ID)

		if eco := strings.TrimSpace(ig.Ecosystem); eco != "" {
			canon, ok := model.CanonicalEcosystem(eco)
			if !ok {
				v.errf(v.idx.arrayKey("ignore", i, "ecosystem"), "ignore.ecosystem",
					"不支援的生態系 %q（支援：%s）", eco, strings.Join(model.KnownEcosystems, "、"))
			} else {
				ig.Ecosystem = canon
			}
		}

		if exp := strings.TrimSpace(ig.Expires); exp != "" {
			if _, err := ig.ExpiresTime(); err != nil {
				v.errf(v.idx.arrayKey("ignore", i, "expires"), "ignore.expires",
					"格式必須是 YYYY-MM-DD（目前是 %q）", exp)
			}
		} else {
			v.warnf(entryLine, "ignore.expires",
				"%s 沒有 expires：建議設到期日，避免永久忽略（規劃 §3.4）", ig.ID)
		}

		if strings.TrimSpace(ig.Reason) == "" {
			v.warnf(entryLine, "ignore.reason", "%s 沒有填 reason：建議寫下評估結論", ig.ID)
		}
	}
}

// looksAbsolute 判斷路徑是否為絕對路徑。
// 刻意不只用 filepath.IsAbs：在 Linux 上驗證 Windows 設定檔時，
// filepath.IsAbs(`D:\vulnwatch\reports`) 會回傳 false，造成假警告。
func looksAbsolute(p string) bool {
	s := strings.TrimSpace(p)
	if s == "" {
		return false
	}
	if filepath.IsAbs(s) {
		return true
	}
	// Windows 磁碟機路徑（D:\... 或 D:/...）
	if len(s) >= 3 && s[1] == ':' &&
		(s[2] == '\\' || s[2] == '/') &&
		((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) {
		return true
	}
	// Windows UNC 路徑
	return strings.HasPrefix(s, `\\\\`)
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// Targets 回傳設定檔中所有套件掃描對象。
func (c *Config) Targets() []model.Target {
	out := make([]model.Target, 0, len(c.Packages))
	for _, p := range c.Packages {
		out = append(out, model.Target{
			Kind:      model.TargetKindPackage,
			Ecosystem: p.Ecosystem,
			Name:      p.Name,
			Version:   p.Version,
			Note:      p.Note,
		})
	}
	return out
}

// SortedWarnings 回傳依行號排序的警告，讓報表輸出穩定。
func (c *Config) SortedWarnings() []Diag {
	out := make([]Diag, len(c.Warnings))
	copy(out, c.Warnings)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}
