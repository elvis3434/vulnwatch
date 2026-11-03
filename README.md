# vulnwatch

第三方套件與程式語言執行環境的已知弱點掃描工具。單一執行檔 CLI，用 Go 寫，設計給 Windows 工作排程器定時執行 —— 使用者只需要定期打開報表。

**狀態：Phase 1a + 1b 已完成。** 目前可用的功能：

- 讀 TOML 設定檔並驗證（錯誤訊息帶行號與欄位名）
- OSV 查詢第三方套件弱點，含嚴重度四層回退與「挑對版本線的最低安全版本」
- Go 執行環境（OSV `stdlib` / `toolchain`）與三個語言的 EOL / 版本落後狀態
- Markdown + JSON 報表，含 UNKNOWN 獨立區塊、各來源成功/失敗狀態、錯誤/警告區
- 雙層檔案快取、`--offline`、與上次結果比對的 NEW 標記、`keep_reports` 清理

尚未實作（Phase 2 / 3）：HTML 報表、python 的 NVD CVE 清單、RustSec、
deps.dev 最新版本、KEV、EPSS、`crates.io` / `npm` 的版本比較、`[[manifests]]` 自動匯入。
各階段範圍見 [vulnwatch-plan.md](vulnwatch-plan.md) §7，實作過程的設計取捨見
[docs/decisions.md](docs/decisions.md)。

## 它做什麼

1. 讀 TOML 設定檔，取得要關注的第三方套件（含版本）與程式語言執行環境（含版本）。
2. 向公開弱點資料庫查詢已知弱點、嚴重度、**修正版本**。
3. 產生報表（Markdown / JSON，Phase 2 起加 HTML），並標示本次新增的弱點。

它**不做**原始碼靜態分析、不做可達性分析、不自動升級套件，也不保證弱點清單完整（各資料庫覆蓋範圍不同，報表會明確標示這點）。

## 資料來源

| 用途 | 來源 | 金鑰 |
|---|---|---|
| 套件弱點（主力） | OSV.dev | 否 |
| Go 標準庫 / 工具鏈 | OSV（`stdlib`、`toolchain`） | 否 |
| Rust 工具鏈 / std | RustSec advisory-db | 否 |
| Python 執行環境 | NVD API 2.0 | 選用（建議申請） |
| EOL 與最新修補版 | endoflife.date API v1 | 否 |
| 套件最新版本 | deps.dev API v3 | 否 |
| 是否已遭實際利用 | CISA KEV | 否 |
| 被利用機率 | FIRST EPSS | 否 |

各來源的覆蓋限制與誤報情況見規劃文件 §4 與 §11。

## 用法（規劃中）

```
vulnwatch scan   -c vulnwatch.toml          # 掃描並產生報表
vulnwatch check  -c vulnwatch.toml          # 只驗證設定檔
vulnwatch version
```

旗標：`--offline`（只用快取）、`--no-cache`、`--verbose`

Exit code：`0` 正常完成、`1` 發現達到 `fail_on` 門檻的弱點、`2` 設定錯誤、`3` 執行錯誤。

## 開發

完整規劃見 [vulnwatch-plan.md](vulnwatch-plan.md)，內容包含資料來源、設定檔設計、嚴重度判定策略、版本比較規則、開發階段與驗收標準。文件的 §11 記錄了各外部 API 的實測行為，實作前請先讀。

```
go test ./...        # 不會打真實網路
go test -tags=live ./...   # 打真實 API，用來重新錄製 testdata fixture
go vet ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/vulnwatch
```

需要的環境變數：

- `VULNWATCH_NVD_API_KEY`（選用，大幅提高 NVD 速率限制）

設定檔範例見 [vulnwatch.example.toml](vulnwatch.example.toml)。

## 已知限制

- **Maven / NuGet 不做版本比較**：「最低安全版本」會列出 advisory 的全部 fixed
  版本，請自行確認對應的版本線。`crates.io` / `npm` 的版本比較是 Phase 2 功能。
- **只有 CVSS 4.0 評分的項目沒有分數**：只顯示 vector 原文與質性等級
  （CVSS 4.0 計分需查 270 筆 MacroVector 對照表）。
- **沒有 CVSS 的 advisory 一律進 UNKNOWN 區塊**：Go 官方 advisory（`GO-*`）
  全部如此。這個區塊**不受 `min_severity` 影響**，請務必檢視。
- **NVD 補分數使用的 CVSS 欄位路徑尚未以真實請求驗證過**，詳見
  [docs/decisions.md](docs/decisions.md) §0 與 §6。
- `testdata/` 的 fixture 是手寫的（開發環境的網路政策封鎖了全部弱點 API），
  重新錄製方式見 [testdata/README.md](testdata/README.md)。
