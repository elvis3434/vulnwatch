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

### 各來源的覆蓋限制與誤報

這些都是用真實請求實測過的結論（規劃 §4 與 §11 有原始記錄）。**沒有任何單一來源
是完整的**，報表也會在「已知限制」區重述這點。

| 來源 | 限制 / 誤報情況 |
|---|---|
| OSV | 套件弱點的主力，覆蓋最好。但 **Go 官方 advisory（`GO-*`）完全沒有 CVSS 分數**，`severity` 一律是 `null`；`severity` 欄位本身是 CVSS **vector 字串**不是分數，且 v3.1 與 v4.0 混用 |
| OSV（語言執行環境） | `Go` 的 `stdlib` / `toolchain` 查得到。`crates.io/std`、`crates.io/rustc` 是空結果 —— **Rust 工具鏈查不到** |
| OSV（CPython） | CPython 本體的 CVE 雖然存在，但 `affected` 是 **GIT commit range**，無法用「3.12.7」這種版本號查到，只能用 ID 反查。**不能當成發現途徑** |
| NVD | **CPE 比對誤報嚴重**：查 python 3.12.7 會查出 2009 年的 CVE（那些 CVE 的 CPE 沒有版本上限，會 match 到所有版本），甚至查出 Django 的 CVE。必須用 `virtualMatchString` 並對 `configurations` 做後處理（Phase 2）。對 **Rust 工具鏈完全無用**：帶版本查 0 筆，不帶版本只有 2018–2019 年的 24 筆 |
| RustSec | Rust 工具鏈的唯一來源，但 advisory-db 的 `rust/` 目錄**不會進 OSV API**，`osv` 分支也只匯出 `crates`，必須自己解析 TOML front matter（Phase 2） |
| endoflife.date | 結構可靠，但本工具只核對到 `go`；`python` / `rust` 是否同結構尚未實測，所以解析器寫成容錯的：欄位缺漏時 EOL 標「不明」並留警告，不會給出錯誤結論 |
| deps.dev | Go module 名稱必須 URL-encode（`/` → `%2F`），否則 404（Phase 2） |

因此報表的設計是：**語言執行環境以「版本落後 / 是否 EOL」為主要結論**，CVE 清單為輔
並標明可能含誤報；而沒有 CVSS 的項目一律進 UNKNOWN 獨立區塊，不被 `min_severity` 濾掉。

## 安裝與用法

需要 Go 1.23 以上。產出是單一靜態執行檔，目標機器不需要安裝 Go。

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o vulnwatch.exe ./cmd/vulnwatch
```

把 `vulnwatch.exe` 與設定檔放到目標機器（例如 `D:\vulnwatch\`），然後：

```
vulnwatch check -c D:\vulnwatch\vulnwatch.toml    # 先驗證設定檔
```

```
vulnwatch scan  -c D:\vulnwatch\vulnwatch.toml    # 掃描並產生報表
```

```
vulnwatch version
```

旗標：

| 旗標 | 作用 |
|---|---|
| `-c`、`--config` | 設定檔路徑（預設 `vulnwatch.toml`） |
| `--offline` | 只使用快取，不發出任何網路請求。快取未命中的對象會標示「無資料」，**不是**「無弱點」 |
| `--no-cache` | 忽略既有快取（仍會寫入新快取，所以之後的 `--offline` 還有資料可用） |
| `--verbose` | 把執行過程也輸出到 stderr（平常只寫 log 檔） |

Exit code：

| Code | 意義 |
|---|---|
| `0` | 正常完成（含「有發現但 `fail_on` 未設定」） |
| `1` | 發現達到 `fail_on` 門檻的弱點 |
| `2` | 設定錯誤 |
| `3` | 執行錯誤（例如所有來源都失敗） |

報表輸出到 `report_dir\YYYY-MM-DD_HHmm\`，並在 `report_dir` 下另存
`latest.md` / `latest.json` 方便固定開啟。

## 設定檔

完整範例見 [vulnwatch.example.toml](vulnwatch.example.toml)。
`vulnwatch check` 會驗證所有欄位，錯誤訊息帶**行號與欄位名**。

### `[general]`

| 欄位 | 預設 | 說明 |
|---|---|---|
| `report_dir` | **必填** | 報表輸出目錄。請用絕對路徑：工作排程器的工作目錄不一定是執行檔所在目錄 |
| `cache_dir` | **必填** | 快取目錄。同樣請用絕對路徑 |
| `log_file` | 無 | 留空則不寫 log 檔 |
| `timezone` | `Local` | IANA 時區名，例如 `Asia/Taipei`。工具內建 tzdata，Windows 上也能用 |
| `report_formats` | `["md","json"]` | 目前支援 `md`、`json`。填 `html` 會收到明確 warning 並寫進報表 |
| `keep_reports` | `30` | 保留最近 N 份報表。`0` = 不清理。只會刪除檔名符合 `YYYY-MM-DD_HHmm` 的目錄 |
| `min_severity` | `LOW` | `LOW`/`MEDIUM`/`HIGH`/`CRITICAL`，或 `""`（等同 `LOW`）。**`UNKNOWN` 不受此設定影響** |
| `fail_on` | `""` | 空字串 = 永遠 exit 0。填 `HIGH` 則發現 >= HIGH 時 exit 1。見下方「排程部署」 |
| `http_timeout` | `30s` | 單次請求逾時 |
| `cache_ttl` | `12h` | 查詢結果的快取有效期 |

### `[network]`

| 欄位 | 說明 |
|---|---|
| `proxy` | 公司網路的代理。留空則讀取環境變數 `HTTPS_PROXY` |
| `ca_file` | 公司網路做 TLS 攔截時，自簽 CA 憑證的路徑（會加入系統 cert pool）。**刻意不提供停用憑證驗證的選項** |

### `[sources]`

`osv`、`nvd`、`rustsec`、`eol`、`deps_dev`、`kev`、`epss`，預設全部 `true`。
目前只有 `osv`、`nvd`、`eol` 會實際查詢，其餘會在報表的「資料來源狀態」標示
「Phase 2 才實作，本次未查詢」。

金鑰不寫在設定檔裡，從環境變數讀取（見下方）。

### `[[languages]]`

| 欄位 | 說明 |
|---|---|
| `name` | `go`、`python`、`rust` |
| `version` | 實際使用的版本，例如 `1.27.3`（go 可用 `go version` 確認） |

目前只有 `go` 會掃弱點清單（OSV 的 `stdlib` 與 `toolchain`）；三個語言都會查
EOL 與版本落後狀態。

### `[[packages]]`

`ecosystem` + `name` + `version`，或用 `purl` 簡寫（兩者只能填一種）。

```toml
[[packages]]
ecosystem = "Go"
name      = "github.com/gin-gonic/gin"
version   = "v1.9.1"
note      = "交易 API 閘道"       # 選填，顯示在報表

[[packages]]
purl = "pkg:golang/golang.org/x/net@v0.20.0"
```

### 套件名稱填寫規則

名稱沿用各生態系的官方命名（與 OSV 一致）：

| `ecosystem` | 名稱格式 | 範例 | 版本比較 |
|---|---|---|---|
| `Go` | 完整 module path | `golang.org/x/net` | semver |
| `PyPI` | PyPI 套件名 | `requests`、`zope.interface` | PEP 440 |
| `crates.io` | crate 名稱 | `tokio` | **Phase 2** |
| `npm` | 套件名，含 scope | `@angular/core` | **Phase 2** |
| `Maven` | `groupId:artifactId` | `org.apache.logging.log4j:log4j-core` | **不做** |
| `NuGet` | 套件 ID | `Newtonsoft.Json` | **不做** |

- **Go 的版本要加 `v` 前綴**（`v1.9.1`），其他生態系不加。漏了會自動補上並警告。
- PyPI 的名稱會做 PEP 503 正規化（小寫、`_`/`.` 轉 `-`），所以 `Zope.Interface`
  與 `zope-interface` 視為同一個套件。
- `version` 省略時會列出該套件**全部**已知弱點，並標示「未指定版本，無法判定
  是否受影響」。強烈建議填寫。
- 「版本比較」欄位是 `不做` / `Phase 2` 的生態系，其「最低安全版本」會列出
  advisory 的**全部** fixed 版本並標註限制 —— 老實標示限制，比猜錯升級方向好。

### `[[ignore]]`

已評估可接受的風險。

```toml
[[ignore]]
id        = "GO-2024-0000"      # 必填，也可以填 advisory 的 alias CVE
ecosystem = "Go"                # 選填；省略 = 對所有套件忽略此 ID
name      = "golang.org/x/net"  # 選填；「未使用受影響的函式」是針對特定套件的評估
reason    = "未使用受影響的函式"
expires   = "2026-12-31"        # YYYY-MM-DD。到期後自動恢復列入報表
```

到期的忽略項目會**照常列入報表**並標示「忽略已於 YYYY-MM-DD 到期」，避免永久忽略。

## 環境變數

| 變數 | 說明 |
|---|---|
| `VULNWATCH_NVD_API_KEY` | NVD API 金鑰（選用） |
| `HTTPS_PROXY` | 代理。`[network].proxy` 留空時會讀它 |

### 申請 NVD 金鑰

免費，在 <https://nvd.nist.gov/developers/request-an-api-key> 填表，金鑰會寄到信箱。

沒有金鑰也能用，差別是速率限制：無金鑰 5 req/30s（本工具以 6 秒間隔序列化，
每次執行最多補 25 筆分數），有金鑰 50 req/30s（0.6 秒間隔，上限 100 筆）。
NVD 的回應會進 30 天長效快取，所以第二次執行幾乎不會再打 NVD。

金鑰只用在「替沒有 CVSS 的 advisory 以 alias CVE 補分數」（嚴重度回退的第 3 層）。
不想用就設 `[sources].nvd = false`，那些項目會留在 UNKNOWN 區塊。

## Windows 排程部署

```powershell
$action  = New-ScheduledTaskAction -Execute 'D:\vulnwatch\vulnwatch.exe' `
           -Argument 'scan -c D:\vulnwatch\vulnwatch.toml' -WorkingDirectory 'D:\vulnwatch'
$trigger = New-ScheduledTaskTrigger -Daily -At 08:30
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName 'vulnwatch' -Action $action -Trigger $trigger -Settings $settings
```

注意事項：

- **設定檔與輸出一律用絕對路徑。** 排程器的工作目錄不一定是 exe 所在目錄。
- `-StartWhenAvailable`：電腦錯過排程時間（關機/睡眠）時，開機後補跑。
- **`fail_on` 預設是空字串，請維持。** 排程器會把 exit code 1 顯示成
  「上次執行結果 0x1」，看起來像程式壞了，使用者會誤判。預設讓程式永遠 exit 0，
  由報表負責告知；要接監控的人再自己設 `fail_on`。設了之後 log 第一行會寫清楚，
  例如 `RESULT: 3 findings >= HIGH (exit 1); 2 unknown-severity（不參與 fail_on，請看報表）`。
- 若需「使用者未登入也執行」，要用有權限的帳號並儲存密碼；
  `VULNWATCH_NVD_API_KEY` 要設成**該帳號的使用者變數或系統變數**,
  否則排程下讀不到。
- 公司網路有代理時，確認排程帳號讀得到 `HTTPS_PROXY`，或寫在 `[network].proxy`；
  有 TLS 攔截則設 `[network].ca_file`。
- 程式不會彈出視窗、不會等待輸入。

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
