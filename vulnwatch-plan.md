# vulnwatch — 第三方套件與程式語言弱點掃描工具 開發規劃

> 給 Claude Code（雲端執行）的開發說明。請依「開發階段」順序實作，每階段完成後 commit，並確保 `go test ./...` 通過。
>
> **版本：第二版（2026-11-03）**。第一版的外部 API 認知已用真實請求驗證過，修正結果見 §0 摘要，原始實測輸出見 §11。
> §11 列出的事實**不需要再驗證**；§11 末尾「實作時仍需確認」的項目才需要先打一次 API。

---

## 0. 第二版修訂摘要（必讀）

實測後發現 5 個會讓功能直接失效的問題，已改寫對應章節：

| # | 問題 | 修正 | 章節 |
|---|---|---|---|
| 1 | **Go 系 advisory 完全沒有 CVSS**（`severity: null`），`min_severity` 會把 Go stdlib 與 x/net 的弱點全部濾掉 —— 等於主力功能失效 | 嚴重度四層回退；`UNKNOWN` 一律不受 `min_severity` 影響，單獨列區塊 | §3.2 |
| 2 | OSV 的 `severity` 是 **CVSS vector 字串**，不是分數；v3.1 與 v4.0 混用，v4.0 計分需查 270 筆 MacroVector 表 | Phase 1 只算 CVSS 3.1；只有 v4 的項目顯示 vector + 質性等級，不硬算分數 | §3.2 |
| 3 | 要給出「最低安全版本」**必須自己比較版本**（OSV 只說有沒有中，不說該升到哪），與第一版「不要自己重寫版本比較」衝突 | 定義 per-ecosystem 策略：Go / PyPI 做比較，其他生態系列出全部 fixed 並標註限制 | §3.3 |
| 4 | **Rust 執行環境弱點 OSV 與 NVD 都查不到**（NVD 帶版本 0 筆、OSV 無 `std`/`rustc`） | 改用 RustSec advisory-db 的 `rust/{std,cargo,rustdoc}/` 目錄 | §4.3 |
| 5 | **NVD 的 CPE 查詢誤報嚴重**（python 3.12.7 會查出 2009 年的 CVE、以及 Django 的 CVE） | 改用 `virtualMatchString` + `configurations` 後處理；語言執行環境改以「版本落後 / EOL」為主軸 | §4.2 |

另有 API 細節修正：OSV 改用 `/v1/query`（querybatch 只回 ID）、endoflife.date 改用 API v1（結構已變）、deps.dev 的 Go module 名稱必須 URL-encode。設定檔與行為層面的修正見 §3.4 與 §8。

---

## 1. 目標

用 Go 開發一個單一執行檔 CLI 工具：

1. 讀取 TOML 設定檔，取得「要關注的第三方套件（含版本）」與「程式語言執行環境（含版本）」。
2. 向公開弱點資料庫查詢已知弱點（CVE / GHSA / GO-xxxx / RUSTSEC 等）、嚴重度、**修正版本（改善方案）**。
3. 產生報表（HTML + Markdown + JSON），並標示「本次新增」的弱點。
4. 部署在 Windows 工作排程器定時執行，使用者只需定期打開報表。

### 非目標（MVP 不做）
- 不做原始碼靜態分析（SAST）、不做 call-graph 可達性分析。
- 不做 GUI、不做常駐服務。
- 不自動升級套件。
- 不保證弱點清單完整（各資料庫覆蓋範圍不同），報表需明確寫出這點。

---

## 2. 資料來源

| 用途 | 來源 | 需要金鑰 | 備註 |
|---|---|---|---|
| 套件弱點（主力） | **OSV.dev** `POST https://api.osv.dev/v1/query`（單筆查詢，直接回完整 advisory） | 否 | **不要用 querybatch 當主力**，原因見 §2.1 |
| Go 標準庫 / 工具鏈 | OSV，ecosystem=`Go`、package=`stdlib` 與 `toolchain`，版本需加 `v` 前綴 | 否 | 這些 advisory **沒有 CVSS**，務必配合 §3.2 |
| Rust 工具鏈 / std | **RustSec advisory-db** 的 `rust/{std,cargo,rustdoc}/*.md` | 否 | OSV 與 NVD 都查不到，見 §4.3 |
| Python 執行環境 | **NVD API 2.0** `https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=...` | 選用（建議申請） | 誤報嚴重，必須後處理，見 §4.2 |
| 語言是否 EOL、最新修補版 | **endoflife.date API v1** `https://endoflife.date/api/v1/products/{product}` | 否 | 結構與舊版不同，見 §11 |
| 套件最新版本 | **deps.dev API v3** `https://api.deps.dev/v3/systems/{SYSTEM}/packages/{name}` | 否 | 名稱必須 URL-encode（Go module 的 `/` → `%2F`），否則 404 |
| 是否已遭實際利用 | **CISA KEV JSON feed** | 否 | 標記 `KEV` 旗標，優先處理 |
| 被利用機率 | **FIRST EPSS API** `https://api.first.org/data/v1/epss?cve=A,B,C` | 否 | 支援 comma 批次，單次 limit 100 |

所有 API 呼叫需：逾時設定、重試（指數退避）、**per-host** 速率限制、本地快取。

### 2.1 OSV 查詢方式：用 `/v1/query`，不要用 `querybatch`

`POST /v1/querybatch` 的回應**只有** `{id, modified}`，拿不到 summary / severity / affected，必須再對每個 ID 打一次 `GET /v1/vulns/{id}`。實際算起來：

```
querybatch 路線： 1 次 querybatch + N 次 vulns/{id}    （50 個套件 → 可能 200+ 次請求）
query 路線：      M 次 query，每次回完整 advisory       （50 個套件 → 50 次請求）
```

所以 Phase 1 直接用 `POST /v1/query`（帶 `package` + `version`），併發 5~8。套件數成長到上百、且 §2.2 的快取已穩定之後，再考慮 querybatch + 快取命中的混合路線。

### 2.2 快取策略（這是省請求數與支撐 `--offline` 的關鍵）

分兩層，TTL 不同：

| 快取項目 | 鍵 | TTL | 理由 |
|---|---|---|---|
| 查詢結果（哪個套件中了哪些弱點） | HTTP method + URL + **request body 的 sha256** | `cache_ttl`（預設 12h） | POST 查詢，body 必須進 hash |
| advisory 內容（`vulns/{id}`） | advisory ID + 回應中的 `modified` | 很長（30 天以上） | 內容幾乎不變；`modified` 一變就自然成為新鍵 |
| KEV feed、endoflife.date | URL | 24h | 一天更新一次就夠 |

- 快取檔名用 sha256 hex，不要用 URL 直接當檔名（Windows 非法字元與路徑長度限制）。
- advisory 物件可能很大（例如 `requests` 的 advisory 會把幾百個版本號全部列舉在 `affected[].versions`），**快取檔一律 gzip**。
- `--offline` 只讀快取、不發請求；快取未命中的項目在報表中標示為「無資料（offline）」，不可當成「無弱點」。

---

## 3. 設定檔設計（TOML）

TOML 套件**定案使用 `github.com/pelletier/go-toml/v2`**：它的解碼錯誤帶行號與欄位名，正好滿足 §9 的驗收標準第一條。

### 3.1 套件名稱填寫規則（重要）

每個套件以 **ecosystem + name + version** 識別，名稱沿用各生態系官方命名（與 OSV 一致）：

| ecosystem 值 | 名稱格式 | 範例 |
|---|---|---|
| `Go` | 完整 module path | `github.com/gin-gonic/gin`、`golang.org/x/net` |
| `crates.io` | crate 名稱 | `tokio`、`serde` |
| `PyPI` | PyPI 套件名（工具內部做 PEP 503 正規化：小寫、`_`/`.` 轉 `-`） | `requests`、`pydantic` |
| `npm` | 套件名，含 scope | `lodash`、`@angular/core` |
| `Maven` | `groupId:artifactId` | `org.apache.logging.log4j:log4j-core` |
| `NuGet` | 套件 ID | `Newtonsoft.Json` |

- `version` **強烈建議填寫**，弱點是否影響取決於版本。Go 版本含 `v` 前綴（`v1.9.1`），其他生態系不加。
- `version` 省略時：列出該套件全部已知弱點，並標示「未指定版本，無法判定是否受影響」。
- 另支援 **purl** 簡寫（擇一即可）：`purl = "pkg:golang/github.com/gin-gonic/gin@v1.9.1"`。
- 啟動時驗證：未知 ecosystem、名稱為空、版本格式錯誤 → 明確錯誤訊息（含行號）並以 exit code 2 結束。

### 3.2 嚴重度判定策略（第二版新增，務必照做）

**實測事實**：OSV 的 `severity` 欄位是 **CVSS vector 字串**，不是分數；而且不同來源差異很大：

```
GHSA（requests）：[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"}]
GHSA（urllib3）： CVSS_V3 與 CVSS_V4 兩個都有
CVE（cpython）：  只有 CVSS_V4
GO-2026-5027：    severity: null   ← Go 官方 advisory 一律沒有 CVSS
```

#### 嚴重度四層回退（依序嘗試）

1. OSV `severity` 中 **`CVSS_V3`** 的 vector → 自己算 base score（CVSS 3.1 是純公式，約 60 行，無需第三方相依）。
2. GHSA 的 `database_specific.severity`（`LOW`/`MODERATE`/`HIGH`/`CRITICAL` 質性等級）→ 直接對應等級，分數留白。
3. 取 `aliases` 中的 `CVE-*`，用 NVD 查該 CVE 的 CVSS 分數（**只在 `[sources].nvd = true` 且額度允許時做**，並進快取）。
4. 以上都沒有 → 等級 `UNKNOWN`，分數留白。

#### 兩條硬規則

- **`UNKNOWN` 永不被 `min_severity` 濾掉。** 改放進報表的「無嚴重度評級」獨立區塊。Go 的 stdlib / x/net 弱點全靠這條才不會消失 —— 這是第一版最嚴重的 bug。
- **只有 `CVSS_V4` 的項目不要硬算分數。** CVSS 4.0 base score 需要查 270 筆 MacroVector 對照表，Phase 1 不做。顯示 vector 原文 + 第 2/3 層取得的等級即可。

報表需在每個項目標明嚴重度的**來源**（`CVSS3.1(OSV)` / `GHSA` / `NVD` / `—`），讓使用者知道分數可不可信。

### 3.3 版本比較與「最低安全版本」（第二版新增）

第一版寫「不要自己重寫版本比較」，但這做不到：OSV 只告訴你「有沒有受影響」，**不告訴你該升到哪個版本**。而 `affected[].ranges` 常常有多段：

```
實測 urllib3 1.26.5，GHSA-34jh-p97f-mpxf：
  range 1: introduced 0       → fixed 1.26.19     ← 1.26.5 落在這段，正解
  range 2: introduced 2.0.0   → fixed 2.2.2
```

挑錯就會建議使用者從 1.26.5 升到 2.2.2（跨大版本、破壞性升級）。**必須判斷目前版本落在哪一段**，才能取出對應的 fixed。

#### 演算法

```
對每個 affected[]（package 相符者）：
  依 ecosystem 的版本序，把 ranges[].events 攤平成遞增的 introduced/fixed 邊界
  找出包含「目前版本」的那一段
  → 該段的 fixed 就是「最低安全版本」
  → 若該段沒有 fixed 事件（上游尚未修復）→ 標示「尚無修正版本」
```

#### per-ecosystem 比較實作

| ecosystem | 版本比較方式 | 階段 |
|---|---|---|
| `Go` | `golang.org/x/mod/semver`（現成，Phase 1 唯一允許新增的相依之一） | Phase 1a |
| `PyPI` | PEP 440 簡化版自己寫（epoch / release / pre / post / dev，約 100 行 + 單元測試） | Phase 1a |
| `crates.io`、`npm` | semver（可共用 Go 的 semver 邏輯，注意 npm 允許非 semver 的歷史版本） | Phase 2 |
| `Maven`、`NuGet` | **不做比較**。列出該 advisory 的**全部** fixed 版本，並明確標註「請自行確認對應的版本線」 | — |

老實標示限制，比猜錯升級方向好。報表上「最低安全版本」欄位要能表達三種狀態：確定值、多個候選（未比較）、尚無修正版本。

### 3.4 設定檔範例 `vulnwatch.toml`

```toml
# ========== 一般設定 ==========
[general]
report_dir      = 'D:\vulnwatch\reports'   # Windows 路徑請用單引號（literal string）避免跳脫
cache_dir       = 'D:\vulnwatch\cache'
log_file        = 'D:\vulnwatch\logs\vulnwatch.log'
timezone        = "Asia/Taipei"            # 需 import _ "time/tzdata"，見 §6
report_formats  = ["md", "json"]           # Phase 1 只支援 md/json；填 html 會收到明確 warning
keep_reports    = 30          # 保留最近 N 份報表，舊的自動刪除
min_severity    = "LOW"       # LOW / MEDIUM / HIGH / CRITICAL
                              # 注意：UNKNOWN（無評級）不受此設定影響，一律列入獨立區塊
fail_on         = ""          # 預設空字串 = 永遠 exit 0，由報表負責告知
                              # 填 "HIGH" 則發現 >= HIGH 時 exit 1（見 §8 排程器注意事項）
http_timeout    = "30s"
cache_ttl       = "12h"

[network]
# 公司網路若需代理，填這裡；留空則讀取系統環境變數 HTTPS_PROXY
proxy   = ""
# 公司網路做 TLS 攔截時，填自簽 CA 憑證路徑（會加入系統 cert pool）
# 不提供停用憑證驗證的選項
ca_file = ""

[sources]
osv      = true
nvd      = true
rustsec  = true     # Rust 工具鏈 / std，見 §4.3
eol      = true
deps_dev = true
kev      = true
epss     = true
# 金鑰不要寫在設定檔，從環境變數讀取：
#   VULNWATCH_NVD_API_KEY

# ========== 程式語言 / 執行環境 ==========
[[languages]]
name    = "go"
version = "1.27.3"        # 實際使用的版本（可用 `go version` 確認）

[[languages]]
name    = "rust"
version = "1.82.0"

[[languages]]
name    = "python"
version = "3.12.7"

# ========== 第三方套件 ==========
[[packages]]
ecosystem = "Go"
name      = "github.com/gin-gonic/gin"
version   = "v1.9.1"
note      = "交易 API 閘道"          # 選填，顯示在報表

[[packages]]
ecosystem = "crates.io"
name      = "tokio"
version   = "1.38.0"

[[packages]]
ecosystem = "PyPI"
name      = "requests"
version   = "2.31.0"

[[packages]]
purl = "pkg:golang/golang.org/x/net@v0.20.0"

# ========== 從專案相依檔自動匯入（選用，Phase 3） ==========
[[manifests]]
path = 'D:\src\par_ses\go.mod'

[[manifests]]
path = 'D:\src\myrust\Cargo.lock'

[[manifests]]
path = 'D:\src\pytool\requirements.txt'

# ========== 忽略清單（已評估可接受的風險） ==========
[[ignore]]
id        = "GO-2024-0000"
ecosystem = "Go"                            # 選填；省略 = 對所有套件忽略此 ID
name      = "golang.org/x/net"              # 選填；同一個 CVE 可能影響多個套件，
                                            # 而「未使用受影響的函式」是針對特定套件的評估
reason    = "未使用受影響的函式"
expires   = "2026-12-31"                    # 字串格式 YYYY-MM-DD，由程式自行 parse
                                            # 到期後自動恢復列入報表，避免永久忽略
```

#### 設定檔驗證規則

- `fail_on` / `min_severity` 只接受 `""`、`LOW`、`MEDIUM`、`HIGH`、`CRITICAL`（不接受 `UNKNOWN`）。
- `report_formats` 出現尚未支援的格式 → **明確 warning 並寫進報表的「錯誤 / 警告」區**，不可靜默忽略。
- `expires` 格式錯誤、`ignore` 缺 `id`、`languages[].name` 不在支援表內 → exit code 2。
- `ignore` 已過期的項目：照常列入報表，並在項目上標示「忽略已於 YYYY-MM-DD 到期」。

---

## 4. 程式語言掃描邏輯

**主軸改變**：語言執行環境的 CVE 清單誤報太多（見 §4.2），對使用者而言可操作性也低。所以報表以
**「目前版本 / 該版本線最新修補版 / 是否 EOL / 落後幾個 patch」** 為主要結論，CVE 清單為輔並標明可能含誤報。

| 語言 | 弱點來源 | EOL / 最新版 |
|---|---|---|
| go | OSV：ecosystem `Go`、package `stdlib` 與 `toolchain`（版本轉為 `v1.27.3` 形式） | endoflife.date v1 `go` |
| python | NVD `virtualMatchString`（見 §4.2） | endoflife.date v1 `python` |
| rust | RustSec advisory-db `rust/{std,cargo,rustdoc}`（見 §4.3） | endoflife.date v1 `rust` |

語言對應表寫成可擴充的 map（name → 弱點查詢方式 / CPE vendor:product / endoflife 產品名），之後加 `node`、`java`、`dotnet` 只需加一筆。

### 4.1 Go

OSV 查 `stdlib` 與 `toolchain` 兩個 package。注意這些 advisory 的 `severity` 一律是 `null` —— 依 §3.2，它們會以 `UNKNOWN` 進入報表的獨立區塊，**不可被 `min_severity` 濾掉**。可用 `aliases` 的 CVE 去 NVD 補分數。

### 4.2 Python（NVD，必須後處理）

**實測誤報情況**：

```
cpeName=cpe:2.3:a:python:python:3.12.7:*:*:*:*:*:*:*   → 17 筆
  含 CVE-2009-2940、CVE-2009-3720（2009 年，與 3.12.7 無關）
  原因：這些 CVE 的 CPE 沒有版本上限，會 match 到所有版本

virtualMatchString=cpe:2.3:a:python:python:3.12.7      → 15 筆
  含 CVE-2021-32052（這是 Django 的）
```

處理方式：

1. 用 `virtualMatchString`（會做版本範圍比對），**不要用 `cpeName`**。
2. 對每筆 CVE 檢查 `configurations[].nodes[].cpeMatch[]`：
   - 有 `versionEndExcluding` 或 `versionEndIncluding`，且目前版本落在範圍內 → 列入「需處理清單」。
   - **沒有任何版本上限** → 降級為「參考」區塊，不進需處理清單（這類幾乎都是誤報）。
   - `criteria` 的 vendor:product 不是 `python:python` → 丟棄。
3. 報表的語言執行環境區塊加註：「CVE 清單來自 NVD CPE 比對，可能含誤報，請以版本落後狀態為主要判斷依據。」

另外：OSV 其實有 CPython 本體的 CVE（例如 `CVE-2024-9287`），但 `affected` 是 **GIT commit range**（`{"type":"GIT","repo":".../cpython","events":[{"fixed":"f3994ad..."}]}`），無法用「3.12.7」查到，只能用 ID 反查。**不能當成發現途徑**，NVD 仍是唯一選擇。

### 4.3 Rust（改用 RustSec advisory-db）

**實測事實**：

```
NVD  virtualMatchString=cpe:2.3:a:rust-lang:rust:1.82.0   → total = 0
NVD  cpe:2.3:a:rust-lang:rust（不帶版本）                  → 24 筆，全部是 2018–2019 年
OSV  crates.io/std  → {}        crates.io/rustc → {}
OSV  crates.io/cargo → 有資料（走 GHSA）
```

真正的來源是 RustSec advisory-db 的 `rust/` 目錄（實測存在 `cargo`、`rustdoc`、`std` 三個子目錄），**這些不會進 OSV API**，advisory-db 的 `osv` 分支也只匯出 `crates`，所以必須自己解析。

檔案格式（實測 `rust/std/CVE-2021-28875.md`）是 fenced TOML front matter 加 markdown 本文：

````
```toml
[advisory]
id = "CVE-2021-28875"
package = "std"
categories = ["memory-corruption"]
date = "2021-01-10"
url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28875"

[versions]
patched = [">= 1.50.0"]
unaffected = ["< 1.20.0"]
```

# Logic bug in Read can cause buffer overflow in read_to_end()

（說明本文…）
````

實作方式：

- 下載 advisory-db 的 tarball（`https://github.com/rustsec/advisory-db/archive/refs/heads/main.tar.gz`），只解析 `rust/{std,cargo,rustdoc}/*.md`，進快取（TTL 24h）。
- 解析 fenced TOML front matter（取檔案開頭第一個「三反引號 + toml」圍欄區塊），本文第一個 `#` 標題當 summary。
- `[versions].patched` / `unaffected` 是 Cargo 風格的版本需求（`">= 1.50.0"`、`"< 1.20.0"`），用 semver 比對目前的 rust 版本。
- 這些 advisory **沒有 CVSS** → 依 §3.2 走 `UNKNOWN`，或用 `id`（通常就是 CVE）去 NVD 補分數。
- Phase 1 不做這塊；Phase 1 的 rust 只輸出 EOL / 版本落後狀態。

---

## 5. 報表內容

輸出至 `report_dir\YYYY-MM-DD_HHmm\`，並另存一份 `latest.html`（與 `latest.md`、`latest.json`）方便固定開啟。

1. **摘要**：掃描時間、項目數、各嚴重度數量、`UNKNOWN` 數、本次新增數、KEV 數、**每個資料來源的成功/失敗狀態**。
2. **需處理清單**（依 KEV → 嚴重度 → EPSS 排序）：
   - 套件 / 語言、目前版本、弱點 ID（含別名 CVE/GHSA）
   - 嚴重度等級 + 分數 + **分數來源**（`CVSS3.1(OSV)` / `GHSA` / `NVD` / `—`，見 §3.2）
   - **最低安全版本**（三種狀態：確定值 / 多個候選未比較 / 尚無修正版本，見 §3.3）、最新版本
   - 是否 KEV、EPSS 分數、參考連結
   - 「NEW」標記（見下方規則）
3. **無嚴重度評級（UNKNOWN）區塊**：不受 `min_severity` 影響。Go stdlib / x/net 與 RustSec 的項目多半落在這裡，**不是次要區塊**，要放在醒目位置。
4. **語言執行環境狀態**：目前版本、該版本線最新修補版、落後幾個 patch、是否 EOL、建議升級版本。CVE 清單放在後面並加註可能含誤報。
5. **參考（可能誤報）**：NVD 查到但沒有版本上限的 CVE（見 §4.2）。
6. **已忽略項目**（含原因、到期日，以及已過期的提示）。
7. **錯誤 / 警告**：某來源查詢失敗、速率限制、設定值問題、`--offline` 下快取未命中 —— 不可靜默吞掉，報表必須明確顯示「此次結果可能不完整」。

HTML 為單檔（CSS 內嵌、無外部資源），可離線開啟。JSON 為完整結構化結果，供下次比對與其他工具使用。

### 5.1 NEW 標記規則（避免假陽性）

第一版「與上一次 JSON 結果比對」會產生假 NEW：如果上次執行時某來源失敗（結果不完整），這次那些弱點會全部被標成 NEW。規則改為：

- JSON 中記錄**每個來源的成功/失敗狀態**。
- diff 時，**上次失敗的來源所涵蓋的項目不參與 NEW 判定**（標示為「無法判定是否新增」）。
- 比對基準優先選擇最近一次「全來源成功」的 JSON；若沒有，用最近一次並套用上一條規則。
- NEW 的 key = `(ecosystem, name, 弱點主 ID)`，**不含版本** —— 否則使用者升版後，舊弱點會重新被標成 NEW。

### 5.2 `keep_reports` 清理

只刪除 `report_dir` 下檔名符合 `^\d{4}-\d{2}-\d{2}_\d{4}$` 的目錄，**絕不對整個 `report_dir` 做 glob 刪除**（使用者可能在裡面放自己的東西）。`latest.*` 必須指向仍保留的那一份。

---

## 6. 架構與專案結構

Phase 1 刻意壓到 6 個 package（第一版的 11 個對這個規模偏多，會浪費點數在搬檔案上）：

```
vulnwatch/
├── cmd/vulnwatch/main.go        # CLI 進入點
├── internal/config/             # TOML 載入、驗證、purl 解析、名稱正規化
├── internal/httpx/              # HTTP：逾時、重試、per-host 限流、代理、CA、User-Agent + 檔案快取
├── internal/model/              # Finding、Severity、CVSS 3.1 計分、per-ecosystem 版本比較
├── internal/source/osv/         # OSV client
├── internal/scan/               # 調度：併發查詢、合併、去重、與上次結果 diff
├── internal/report/             # md / json 輸出（Phase 2 加 html，html/template + embed）
├── testdata/                    # 錄製好的 API 回應 fixture
├── vulnwatch.example.toml
└── README.md
```

Phase 2 再加 `internal/source/{nvd,rustsec,eol,depsdev,kev,epss}/`，Phase 3 再加 `internal/manifest/` 與 `scripts/`。

### 技術要求

- Go 1.23+，`CGO_ENABLED=0`，產出單一靜態執行檔；以 `GOOS=windows GOARCH=amd64` 交叉編譯。
- **必須 `import _ "time/tzdata"`**。Go 在 Windows 上沒有系統 tzdata，`time.LoadLocation("Asia/Taipei")` 會直接回錯 —— 設定檔的 `timezone` 一定會踩到。代價約 +450KB，接受。
- 相依控制（本工具本身也是供應鏈的一環），Phase 1 只允許：
  - `github.com/pelletier/go-toml/v2`（錯誤訊息帶行號）
  - `golang.org/x/mod/semver`（Go 版本比較）
  - 其餘一律標準庫。CVSS 3.1 計分與 PEP 440 比較自己寫。
- 檔案路徑一律用 `path/filepath`，需支援 Windows 路徑與中文路徑。
- 所有 HTTP 請求設定 `User-Agent: vulnwatch/<version>`。
- **per-host 速率限制**，不是一個全域值：
  - `services.nvd.nist.gov`：無金鑰 5 req/30s（實務上請用 6 秒間隔序列化），有金鑰 50 req/30s
  - `api.osv.dev`：可併發，自我節流 5~8
  - 其餘來源：一次性請求，不需特別處理

### CLI

```
vulnwatch scan   -c vulnwatch.toml          # 掃描並產生報表
vulnwatch check  -c vulnwatch.toml          # 只驗證設定檔
vulnwatch version
旗標：--offline（只用快取）、--no-cache、--verbose
```

Exit code：`0` 正常完成（含「有發現但 `fail_on` 未設定」）、`1` 發現 >= `fail_on` 的弱點、`2` 設定錯誤、`3` 執行錯誤（例如全部來源失敗）。

---

## 7. 開發階段（點數有限，依序完成，每階段都可單獨使用）

### Phase 1a — 最小可用（優先）
- 設定檔載入與驗證（`[general]`、`[network]`、`[sources]`、`[[packages]]`、`[[ignore]]`），錯誤訊息含行號
- `internal/httpx`：逾時、指數退避重試、per-host 限流、proxy、`ca_file`、檔案快取（含 gzip 與 §2.2 的雙層 TTL）
- OSV `POST /v1/query` 查詢套件弱點
- §3.2 嚴重度四層回退的第 1、2、4 層（CVSS 3.1 自算 + GHSA 質性等級 + UNKNOWN）
- §3.3 的 Go 與 PyPI 版本比較，取出正確的「最低安全版本」
- Markdown + JSON 報表（含 UNKNOWN 獨立區塊、錯誤/警告區）
- 單元測試：`httptest` + `testdata` fixture，**測試不可打真實網路**

### Phase 1b — Go 執行環境與完整度
- OSV `stdlib` / `toolchain` 掃描（版本加 `v` 前綴）
- `[[languages]]` 中的 go：endoflife.date v1 查 EOL 與該版本線最新修補版
- 嚴重度第 3 層（alias CVE → NVD 補分數）
- `min_severity`、`fail_on`、exit code、`keep_reports` 清理
- 與上次結果比對（§5.1 的 NEW 規則，含 per-source 狀態）
- 寫入 log 檔

### Phase 2 — 其他語言與 HTML 報表
- NVD（python）含 §4.2 的 `configurations` 後處理與誤報降級
- RustSec advisory-db（§4.3），rust 的 `std`/`cargo`/`rustdoc`
- deps.dev 最新版本（Go module 名稱記得 URL-encode）
- KEV、EPSS（以 `aliases` 中的 CVE 為 key）
- HTML 報表、`latest.html`
- `crates.io` / `npm` 的版本比較

### Phase 3 — 便利性（點數允許再做）
- `[[manifests]]`：解析 go.mod、Cargo.lock、requirements.txt（只處理有固定版本 `==` 的行），自動加入套件清單
- `scripts/install-task.ps1`
- （選用）掃描完成後發送通知：Email (SMTP) 或 Teams/Slack webhook，網址從環境變數讀，**必須有 `--dry-run`**

---

## 8. Windows 排程部署

`scripts/install-task.ps1` 需完成：

```powershell
# 範例：每天 08:30 執行
$action  = New-ScheduledTaskAction -Execute 'D:\vulnwatch\vulnwatch.exe' `
           -Argument 'scan -c D:\vulnwatch\vulnwatch.toml' -WorkingDirectory 'D:\vulnwatch'
$trigger = New-ScheduledTaskTrigger -Daily -At 08:30
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName 'vulnwatch' -Action $action -Trigger $trigger -Settings $settings
```

注意事項（寫進 README）：

- 設定檔與輸出一律使用**絕對路徑**；排程器的工作目錄不一定是 exe 所在目錄。
- `-StartWhenAvailable`：電腦錯過排程時間（關機/睡眠）時，開機後補跑。
- **`fail_on` 預設為空字串**。原因：排程器會把 exit code 1 顯示成「上次執行結果 0x1」，看起來像程式壞了，使用者會誤判。預設讓程式永遠 exit 0，由報表負責告知；要接監控的人再自己設 `fail_on`。設了之後，log 第一行必須寫清楚，例如 `RESULT: 3 findings >= HIGH (exit 1)`。
- 若需「使用者未登入也執行」，要用有權限的帳號並儲存密碼；`VULNWATCH_NVD_API_KEY` 等環境變數需設為**該帳號的使用者變數或系統變數**，否則排程下讀不到。
- 公司網路若有代理，確認排程帳號能讀到 `HTTPS_PROXY`，或寫在 `[network].proxy`；若有 TLS 攔截，設 `[network].ca_file`。
- 程式不可彈出視窗、不可等待輸入。

---

## 9. 驗收標準

- [ ] `vulnwatch check` 能指出設定檔錯誤的具體欄位與行數。
- [ ] 以已知有弱點的版本掃描，能列出弱點與修正版本。
- [ ] **回歸案例（§3.3）**：`PyPI/urllib3@1.26.5` 的 `GHSA-34jh-p97f-mpxf`，最低安全版本必須是 **1.26.19**，不能是 2.2.2。
- [ ] **回歸案例（§3.2）**：`min_severity = "HIGH"` 時，`Go/golang.org/x/net@v0.20.0` 的 `GO-*` 弱點（無 CVSS）仍必須出現在 UNKNOWN 區塊，不可消失。
- [ ] **回歸案例（§4.2）**：掃描 python 3.12.7 時，`CVE-2009-2940`、`CVE-2009-3720` 不得出現在需處理清單（應在「參考（可能誤報）」區）。
- [ ] 以最新版掃描，報表顯示無弱點。
- [ ] 某個資料來源失敗時，其餘照常產出，報表明確標示不完整，且**該來源涵蓋的項目不被標成 NEW**。
- [ ] 第二次執行時，相同結果不會標 NEW；新增弱點會標 NEW；升版後舊弱點不會重新變 NEW。
- [ ] `--offline` 在有快取時可產出報表，未命中項目標示「無資料」而非「無弱點」。
- [ ] 第二次執行的網路請求數明顯下降（§2.2 的 advisory 長效快取生效）。
- [ ] Windows 上 `timezone = "Asia/Taipei"` 能正常載入（`time/tzdata` 已 import）。
- [ ] `go test ./...`、`go vet ./...` 通過；Windows amd64 可交叉編譯；CI 另跑 `govulncheck`（本工具自己也要被掃）。
- [ ] README 說明：安裝、設定檔各欄位、套件命名規則、排程設定、NVD 金鑰申請、**各來源的覆蓋限制與誤報說明**。

---

## 10. 給 Claude Code 的工作指示

1. 先讀完本文件（特別是 §0 摘要與 §11 實測記錄），從 Phase 1a 開始；每完成一個 Phase 就 commit 並回報進度。
2. §11 已驗證的事實**不要再花請求去確認**。只有 §11 末尾「實作時仍需確認」的項目，才在實作該來源前先打一次 API，並把回應存成 `testdata/` fixture。
3. 錄 fixture 用 `//go:build live` 的測試檔（`go test -tags=live ./...`），平常 `go test ./...` 絕不碰網路。
4. 不確定的設計決策，選最簡單可行的做法並記在 `docs/decisions.md`，不要停下來等待。
5. 點數有限：避免大範圍重構與不必要的相依；§6 的相依白名單之外不要加。Phase 3 只在前兩階段穩定後才做。
6. 第一個 commit 建議包含：本規劃文件、`README.md` 骨架、`.gitignore`、`LICENSE`、`go.mod`。

---

## 11. 實測記錄（2026-11-03）

以下都是實際發出請求得到的結果，**不需要再驗證**。

### 已驗證

| 項目 | 結果 |
|---|---|
| OSV `POST /v1/querybatch` | 回應**只有** `{"id","modified"}`，無 summary/severity/affected |
| OSV `POST /v1/query`（帶 version） | 回完整 advisory 物件，可直接使用 |
| OSV `severity` 欄位 | CVSS **vector 字串**；GHSA 可能同時有 `CVSS_V3` 與 `CVSS_V4`；CVE 條目可能只有 `CVSS_V4` |
| `GO-2026-5027` | `severity: null`，只有 `database_specific.review_status`；Go 官方 advisory 一律無 CVSS |
| `GHSA-9hjg-9r4m-mvj7`（requests） | `database_specific.severity = "MODERATE"`，可當質性等級回退 |
| `GHSA-34jh-p97f-mpxf`（urllib3） | `affected[].ranges` 有兩段：`[0,1.26.19)` 與 `[2.0.0,2.2.2)` → 必須挑對版本線 |
| OSV advisory 大小 | `affected[].versions` 可能列舉數百個版本號，快取需 gzip |
| OSV `crates.io/std`、`crates.io/rustc` | 空結果 `{}`；`crates.io/cargo` 有資料 |
| RustSec OSV 條目（RUSTSEC-2024-0006 等） | `affected` 一律是 `crates.io` 的 crate，沒有 std/rustc |
| RustSec advisory-db `rust/` 目錄 | 存在 `cargo`、`rustdoc`、`std`；檔名即 CVE（如 `CVE-2021-28875.md`） |
| RustSec `rust/std/*.md` 格式 | fenced TOML front matter：`[advisory]`（id/package/categories/date/url）+ `[versions]`（`patched = [">= 1.50.0"]`、`unaffected`），之後是 markdown 本文 |
| RustSec `osv` 分支 | 只有 `README.md` 與 `crates` —— **`rust/` 沒有 OSV 格式匯出**，必須自己解析 TOML |
| NVD `cpeName=cpe:2.3:a:python:python:3.12.7:*:*:*:*:*:*:*` | 17 筆，含 `CVE-2009-2940`、`CVE-2009-3720`（誤報，CPE 無版本上限） |
| NVD `virtualMatchString=cpe:2.3:a:python:python:3.12.7` | 15 筆，含 `CVE-2021-32052`（Django 的，誤報）；但會做版本範圍比對，仍優於 `cpeName` |
| NVD `virtualMatchString=cpe:2.3:a:rust-lang:rust:1.82.0` | **0 筆** |
| NVD `cpe:2.3:a:rust-lang:rust`（不帶版本） | 24 筆，全部 2018–2019 年 → NVD 對 Rust 工具鏈無用 |
| OSV `CVE-2024-9287`（CPython） | 存在，但 `affected` 是 `{"type":"GIT","repo":".../cpython"}` 的 commit range，**無法用版本查詢** |
| endoflife.date 舊端點 `/api/go.json` | 仍回 200（未移除，但已非主推） |
| endoflife.date v1 `/api/v1/products/go` | `result.releases[]`，每筆有 `name`、`latest{name,date,link}`、`isEol`、`eolFrom`、`isMaintained`。實測 go 1.25 已 EOL（`eolFrom: 2026-08-19`），1.27 最新 `1.27.3` |
| deps.dev v3 Go module | `github.com%2Fgin-gonic%2Fgin` → 200；未 URL-encode → **404** |
| EPSS `?cve=A,B` | 正常，回 `{cve, epss, percentile, date}`，回應含 `"limit":100` |
| CISA KEV feed | 正常，`catalogVersion 2026.10.30`、`count 1766`；每筆有 `cveID`、`vendorProject`、`product`、`knownRansomwareCampaignUse`、`dueDate` |

### 實作時仍需確認（打一次 API 並錄 fixture）

- NVD `configurations[].nodes[].cpeMatch[]` 的確切欄位名（`criteria`、`versionStartIncluding`、`versionEndExcluding`、`vulnerable`）—— §4.2 的後處理邏輯依賴這些欄位，本輪未印出完整結構。
- NVD 回應中的 CVSS 區塊路徑（`cve.metrics.cvssMetricV31[]` / `cvssMetricV40[]`）與 `baseScore` 取法 —— §3.2 第 3 層回退需要。
- endoflife.date v1 的 `python`、`rust` 產品是否與 `go` 同結構（`releases[]` 欄位一致）。
- OSV `/v1/query` 在無金鑰下的實際併發容忍度（先保守用 5，觀察是否出現 429）。
