// vulnwatch 是第三方套件與程式語言執行環境的已知弱點掃描工具。
//
// 用法：
//
//	vulnwatch scan  -c vulnwatch.toml   # 掃描並產生報表
//	vulnwatch check -c vulnwatch.toml   # 只驗證設定檔
//	vulnwatch version
//
// 旗標：--offline（只用快取）、--no-cache、--verbose
//
// Exit code：0 正常完成、1 發現達到 fail_on 門檻的弱點、2 設定錯誤、3 執行錯誤。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	// Windows 沒有系統 tzdata，不 import 這個的話設定檔的
	// timezone = "Asia/Taipei" 會直接失敗（規劃 §6）。代價約 +450KB。
	_ "time/tzdata"

	"github.com/elvis3434/vulnwatch/internal/config"
	"github.com/elvis3434/vulnwatch/internal/httpx"
	"github.com/elvis3434/vulnwatch/internal/model"
	"github.com/elvis3434/vulnwatch/internal/report"
	"github.com/elvis3434/vulnwatch/internal/scan"
)

// version 由 -ldflags "-X main.version=..." 覆寫；預設值供開發時使用。
var version = "0.1.0-dev"

// Exit code（規劃 §6）。
const (
	exitOK          = 0
	exitFailOn      = 1
	exitConfigError = 2
	exitRunError    = 3
)

// nvdAPIKeyEnv 是 NVD 金鑰的環境變數名。金鑰不寫在設定檔裡（規劃 §3.4）。
const nvdAPIKeyEnv = "VULNWATCH_NVD_API_KEY"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitConfigError
	}

	cmd := args[0]
	switch cmd {
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "vulnwatch %s\n", version)
		return exitOK
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	case "scan", "check":
		// 繼續往下
	default:
		fmt.Fprintf(stderr, "未知的子命令 %q\n\n", cmd)
		usage(stderr)
		return exitConfigError
	}

	fs := flag.NewFlagSet("vulnwatch "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		cfgPath = fs.String("c", "vulnwatch.toml", "設定檔路徑")
		offline = fs.Bool("offline", false, "只使用快取，不發出任何網路請求")
		noCache = fs.Bool("no-cache", false, "忽略既有快取（仍會寫入新快取）")
		verbose = fs.Bool("verbose", false, "輸出詳細執行過程")
	)
	fs.StringVar(cfgPath, "config", "vulnwatch.toml", "設定檔路徑（同 -c）")
	if err := fs.Parse(args[1:]); err != nil {
		return exitConfigError
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		var cerrs *config.Errors
		if errors.As(err, &cerrs) {
			fmt.Fprintf(stderr, "設定檔有 %d 個問題：\n", len(cerrs.Diags))
			for _, d := range cerrs.Diags {
				fmt.Fprintf(stderr, "  %s\n", d.String())
			}
			return exitConfigError
		}
		fmt.Fprintf(stderr, "%v\n", err)
		return exitConfigError
	}

	if cmd == "check" {
		return runCheck(cfg, stdout)
	}
	return runScan(cfg, *cfgPath, *offline, *noCache, *verbose, stdout, stderr)
}

func runCheck(cfg *config.Config, stdout io.Writer) int {
	fmt.Fprintf(stdout, "設定檔 %s 沒有錯誤。\n", cfg.Path)
	fmt.Fprintf(stdout, "  套件 %d 個、語言 %d 個、忽略規則 %d 條\n",
		len(cfg.Packages), len(cfg.Languages), len(cfg.Ignore))
	fmt.Fprintf(stdout, "  報表目錄 %s\n", cfg.General.ReportDir)
	fmt.Fprintf(stdout, "  快取目錄 %s\n", cfg.General.CacheDir)
	fmt.Fprintf(stdout, "  時區 %s（%s）\n", cfg.General.Timezone, cfg.Location.String())
	fmt.Fprintf(stdout, "  報表格式 %s\n", strings.Join(cfg.Formats, ", "))
	fmt.Fprintf(stdout, "  min_severity %s；fail_on %s\n",
		cfg.MinLevel.String(), failOnDesc(cfg))

	if ws := cfg.SortedWarnings(); len(ws) > 0 {
		fmt.Fprintf(stdout, "\n有 %d 個警告（不影響執行，但會寫進報表）：\n", len(ws))
		for _, w := range ws {
			fmt.Fprintf(stdout, "  %s\n", w.String())
		}
	}
	return exitOK
}

func failOnDesc(cfg *config.Config) string {
	if !cfg.FailOnSet {
		return "未設定（永遠 exit 0）"
	}
	return cfg.FailOnLevel.String()
}

func runScan(cfg *config.Config, cfgPath string, offline, noCache, verbose bool, stdout, stderr io.Writer) int {
	logFile, closeLog, err := openLog(cfg.General.LogFile)
	if err != nil {
		fmt.Fprintf(stderr, "開啟 log 檔失敗：%v\n", err)
		return exitRunError
	}
	defer closeLog()

	logf := makeLogf(logFile, stderr, verbose)

	if err := os.MkdirAll(cfg.General.ReportDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "建立報表目錄失敗：%v\n", err)
		return exitRunError
	}
	if err := os.MkdirAll(cfg.General.CacheDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "建立快取目錄失敗：%v\n", err)
		return exitRunError
	}

	httpClient, err := httpx.New(httpx.Options{
		UserAgent: "vulnwatch/" + version,
		Timeout:   cfg.HTTPTimeoutD,
		Proxy:     cfg.Network.Proxy,
		CAFile:    cfg.Network.CAFile,
		CacheDir:  cfg.General.CacheDir,
		CacheTTL:  cfg.CacheTTLD,
		Offline:   offline,
		NoCache:   noCache,
		Logf:      logf,
	})
	if err != nil {
		fmt.Fprintf(stderr, "建立 HTTP 客戶端失敗：%v\n", err)
		return exitRunError
	}

	apiKey := strings.TrimSpace(os.Getenv(nvdAPIKeyEnv))
	if apiKey != "" {
		// 有金鑰：50 req/30s，用 0.6 秒間隔序列化（規劃 §6）。
		httpClient.SetHostLimit("services.nvd.nist.gov", httpx.HostLimit{
			Concurrency: 1, MinInterval: 600 * time.Millisecond,
		})
		logf("已讀到 %s，NVD 速率限制放寬", nvdAPIKeyEnv)
	}

	// 程式不可彈出視窗、不可等待輸入（規劃 §8）；收到中斷訊號就乾淨收尾。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	now := time.Now().In(cfg.Location)
	rep, err := scan.Run(ctx, scan.Options{
		Config:      cfg,
		HTTP:        httpClient,
		ToolVersion: version,
		Now:         now,
		Logf:        logf,
		NVDAPIKey:   apiKey,
	})
	if err != nil {
		logf("掃描失敗：%v", err)
		fmt.Fprintf(stderr, "掃描失敗：%v\n", err)
		return exitRunError
	}

	written, err := report.Write(rep, cfg.General.ReportDir, cfg.Formats, now)
	if err != nil {
		logf("寫入報表失敗：%v", err)
		fmt.Fprintf(stderr, "寫入報表失敗：%v\n", err)
		return exitRunError
	}

	if removed, err := report.Cleanup(cfg.General.ReportDir, cfg.General.KeepReports); err != nil {
		logf("清理舊報表失敗：%v", err)
		fmt.Fprintf(stderr, "清理舊報表失敗（不影響本次報表）：%v\n", err)
	} else if len(removed) > 0 {
		logf("已清理 %d 份舊報表：%s", len(removed), strings.Join(removed, ", "))
	}

	exit := exitOK
	if triggered, _ := scan.FailOnTriggered(rep, cfg); triggered {
		exit = exitFailOn
	}
	// 所有來源都失敗 → 執行錯誤（規劃 §6）。
	if allSourcesFailed(rep) {
		exit = exitRunError
	}

	// log 第一行必須是結論（規劃 §8）。
	resultLine := scan.ResultLine(rep, cfg, exit)
	if logFile != nil {
		fmt.Fprintf(logFile, "%s\n", resultLine)
	}

	stats := httpClient.Stats()
	summary := fmt.Sprintf("%s；網路請求 %d 次、快取命中 %d 次",
		resultLine, stats.NetworkRequests, stats.CacheHits)
	logf("%s", summary)
	fmt.Fprintf(stdout, "%s\n", summary)
	for _, p := range written {
		fmt.Fprintf(stdout, "報表：%s\n", p)
	}
	return exit
}

// allSourcesFailed 回傳是否所有啟用的來源都失敗。
func allSourcesFailed(rep *model.Report) bool {
	enabled, failed := 0, 0
	for _, s := range rep.Sources {
		if !s.Enabled || s.Queries == 0 {
			continue
		}
		enabled++
		if !s.OK {
			failed++
		}
	}
	return enabled > 0 && enabled == failed
}

func openLog(path string) (io.Writer, func(), error) {
	p := strings.TrimSpace(path)
	if p == "" {
		return nil, func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, func() {}, err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, func() {}, err
	}
	fmt.Fprintf(f, "\n===== vulnwatch %s @ %s =====\n", version, time.Now().Format(time.RFC3339))
	return f, func() { _ = f.Close() }, nil
}

func makeLogf(logFile io.Writer, stderr io.Writer, verbose bool) func(string, ...any) {
	return func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		ts := time.Now().Format("15:04:05")
		if logFile != nil {
			fmt.Fprintf(logFile, "%s %s\n", ts, line)
		}
		if verbose {
			fmt.Fprintf(stderr, "%s %s\n", ts, line)
		}
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `vulnwatch %s — 第三方套件與程式語言執行環境的已知弱點掃描工具

用法：
  vulnwatch scan  -c vulnwatch.toml    掃描並產生報表
  vulnwatch check -c vulnwatch.toml    只驗證設定檔（會指出錯誤的欄位與行號）
  vulnwatch version                    顯示版本

旗標：
  -c, --config <path>   設定檔路徑（預設 vulnwatch.toml）
  --offline             只使用快取，不發出任何網路請求
  --no-cache            忽略既有快取（仍會寫入新快取）
  --verbose             輸出詳細執行過程

Exit code：
  0  正常完成（含「有發現但 fail_on 未設定」）
  1  發現達到 fail_on 門檻的弱點
  2  設定錯誤
  3  執行錯誤

環境變數：
  %s   NVD API 金鑰（選用，大幅提高速率限制）
`, version, nvdAPIKeyEnv)
}
