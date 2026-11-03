# 設計決策紀錄

規劃文件（`vulnwatch-plan.md`）說「不確定的設計決策，選最簡單可行的做法並記在這裡，
不要停下來等待」（§10.4）。以下是實作 Phase 1a / 1b 時自己決定的取捨。

**本文件不修改規劃。** 實作過程中發現的規劃問題也記在這裡（見最後一節），
規劃文件本身保持原樣。

---

## 0. 開發環境的限制（影響最大，請先讀）

本次開發是在雲端 session 裡進行的，而該環境的網路政策**封鎖了全部弱點 API 主機**：

```
api.osv.dev            CONNECT → 403（政策拒絕）
services.nvd.nist.gov  CONNECT → 403
endoflife.date         CONNECT → 403
api.deps.dev           CONNECT → 403
api.first.org          CONNECT → 403
```

後果：

1. **無法錄製真實 fixture。** `testdata/` 下的檔案是依規劃 §11「已驗證」表格中的
   實測記錄**手寫**的（欄位名、型別、關鍵資料形狀都照記錄還原），不是逐位元組
   相同的真實回應。`testdata/README.md` 有說明與重新錄製的指令。
2. **規劃 §11「實作時仍需確認」的第 2 項（NVD 的 CVSS 欄位路徑）無法確認。**
   這是 Phase 1a/1b 唯一會用到的待確認項目。處理方式見 §6。
3. `//go:build live` 的錄製測試已經寫好（`internal/source/osv/record_live_test.go`、
   `internal/scan/record_live_test.go`），在網路可通的機器上跑一次就能補齊：

   ```
   go test -tags=live ./internal/source/... ./internal/scan/... -run Record -v
   ```

這個限制不影響 `go test ./...` 的有效性（本來就不准打網路），但**第一次在真實網路上
執行 `vulnwatch scan` 時，請人工核對一次 NVD 補分數的結果**。

---

## 1. package 結構：eol / nvd 放在 `internal/scan`，不另開 package

規劃 §6 列的 Phase 1 結構是 6 個 package，並說 `internal/source/{nvd,eol,...}`
是 Phase 2 才加。但 §7 的 **Phase 1b 要求做 endoflife.date 與「第 3 層 NVD 補分數」**。
兩者矛盾。

決定：**維持 6 個 package**，把這兩個小客戶端放成 `internal/scan/eol.go` 與
`internal/scan/nvd.go`（同屬 package `scan`）。理由：

- 使用者的硬性約束是「Phase 1 的 package 結構照 §6 那 6 個，不要擴張」。
- 兩者都很小（各約 150 行），且只有 scan 會用到。
- Phase 2 要加 `rustsec` / `depsdev` / `kev` / `epss` 時，再把這兩個檔案搬到
  `internal/source/{eol,nvd}/` —— 那時本來就要動這塊，搬移成本一次付。

## 2. 嚴重度：分數 0.0 視為 LOW，不是 UNKNOWN

CVSS 3.1 把 base score 0.0 定義為 None。但 OSV 不會為「完全無影響」的項目建立
advisory，所以實務上 0.0 只會出現在 vector 填得很保守的情況。

決定：`LevelFromScore(0.0)` 回傳 `LOW`。如果回傳 `UNKNOWN`，這個項目就會跳過
`min_severity`（UNKNOWN 永不被濾掉），反而讓最無害的項目最醒目。

## 3. 嚴重度：第 1 層（CVSS_V3 自算）優先於第 2 層（GHSA 質性等級）

同一筆 GHSA 常常同時有 `severity[].CVSS_V3` 與 `database_specific.severity`。
規劃 §3.2 的回退是有序的，所以第 1 層命中就不再看第 2 層 —— 即使兩者結論不同
（例如 GHSA 標 MODERATE 但算出來是 HIGH）。報表上的「來源」欄位會顯示
`CVSS3.1(OSV)`，使用者看得出分數怎麼來的。

vector 解析失敗時會往下一層走，不會讓整筆資料消失。

## 4. 嚴重度：`UNKNOWN` 不參與 `fail_on`

規劃明確寫了 UNKNOWN 不受 `min_severity` 影響，但沒寫 `fail_on`。

決定：**UNKNOWN 不觸發 `fail_on`**。理由：`fail_on` 是「嚴重度 >= 門檻」的比較，
而 UNKNOWN 沒有分數可以比。若讓 UNKNOWN 觸發 exit 1，設了 `fail_on = "CRITICAL"`
的人會因為一筆 `GO-*` 就收到 exit 1，而那筆的真實嚴重度可能是 LOW。
UNKNOWN 的告知責任由報表的獨立區塊承擔（這也是規劃的設計意圖）。

## 5. 版本比較：挑不出「包含目前版本的那一段」時列候選，不猜

規劃 §3.3 的演算法假設 `ranges` 一定有一段包含目前版本。實際上有例外：
advisory 只用 `affected[].versions` 列舉版本（沒有 ranges）、range 是 GIT
commit range、或版本字串無法解析。

決定：這幾種情況一律回到 `FixKindCandidates`（列出全部 fixed 並標註原因），
而不是硬挑第一個 fixed。老實標示限制，比猜錯升級方向好。

同一個 advisory 有多段同時包含目前版本時（理論上不該發生），取版本序**最小**的
fixed 當建議值，其餘列為候選並標註。

## 6. NVD 的 CVSS 欄位路徑：寫得寬容，並在報表留痕

因為 §0 說的原因無法實測。實作採用 NVD API 2.0 公開文件的路徑：

```
vulnerabilities[].cve.metrics.cvssMetricV31[].cvssData.baseScore
                                            .cvssData.baseSeverity
                              cvssMetricV30[]   （同結構，次選）
                              cvssMetricV40[]   （只取 baseSeverity，不取分數）
```

容錯設計：
- `type == "Primary"` 優先，找不到就取第一筆。
- `baseScore` 缺漏或為 0 時，退而用 `baseSeverity` 字串（只得到等級，沒有分數）。
- 整個 `metrics` 區塊都讀不到 → 該項目保持 UNKNOWN，並在報表的警告區寫出
  「NVD 回應中找不到 CVSS 欄位」。**不會靜默失敗。**

## 7. NVD 補分數有次數上限

規劃 §3.2 說第 3 層「只在 `[sources].nvd = true` 且額度允許時做」，但沒定義額度。

決定：每次執行最多查 **25 筆**（無金鑰）/ **100 筆**（有 `VULNWATCH_NVD_API_KEY`）。
無金鑰時 per-host 限流是 6 秒間隔，25 筆約 150 秒，對每日排程可接受。
超過上限的項目保持 UNKNOWN，並在報表警告區寫出「已達本次 NVD 查詢上限」。

NVD 的回應用長效快取（30 天，鍵為 `nvd-cve:<CVE-ID>`），所以第二次執行幾乎不會
再打 NVD。

## 8. NVD 補分數成功後，項目會離開 UNKNOWN 區塊

這是回退鏈的設計本意，但有個副作用要知道：`Go/golang.org/x/net` 的 `GO-2024-2687`
在 `[sources].nvd = false` 時留在 UNKNOWN 區塊（規劃 §9 的回歸案例）；
在 `nvd = true` 且查到 CVE-2023-45288 的分數（7.5 / HIGH）時，它會變成
HIGH 進入需處理清單，**此時就會受 `min_severity` 影響**。

兩個行為都正確。測試兩種情境都有覆蓋（`TestGoAdvisoryStaysInUnknownBlock`
與 `TestNVDFillsSeverityForGoAdvisory`）。

## 9. `report_dir` / `cache_dir` 必填，相對路徑只警告

規劃沒說這兩個是必填。決定設為**必填**（缺少 → exit 2 並指出行號），因為規劃 §8
強調排程器的工作目錄不確定，沒有這兩個值的話報表會跑到意想不到的地方。

填了但不是絕對路徑 → 只警告，不阻止執行（開發時用相對路徑很方便）。
判斷絕對路徑時刻意不只用 `filepath.IsAbs`：在 Linux 上驗證 Windows 設定檔時，
`filepath.IsAbs(\`D:\vulnwatch\reports\`)` 會回傳 false，造成假警告。

## 10. `min_severity = ""` 等同 `LOW`

規劃 §3.4 的驗證規則說 `min_severity` 接受 `""`，但沒說空字串的語意。
決定：空字串 = 不過濾 = `LOW`。

## 11. `keep_reports = 0` 表示不清理

規劃沒定義 0。決定 0 = 不清理（負數才是錯誤，exit 2）。

## 12. `--no-cache` 只是不「讀」快取，仍然會「寫」

規劃只說「忽略既有快取」。決定仍然寫入新快取，否則 `--no-cache` 跑過一次之後，
`--offline` 會完全沒有資料可用。

## 13. `--offline` 時連過期的快取也用

`cache_ttl` 過期的快取在正常模式下不會被使用，但在 `--offline` 下會回傳，
並在報表標示。理由：offline 的唯一替代方案是「完全沒有資料」，過期資料仍然
比沒有資料有用，只要標示清楚。

## 14. JSON 報表保留被 `min_severity` 濾掉的項目

`filtered_out` 欄位會寫進 JSON。如果不寫，使用者把 `min_severity` 從 `HIGH` 調成
`LOW` 之後，那些本來就存在的 MEDIUM 項目會全部被誤判成 NEW（規劃 §5.1 要避免的
正是這類假 NEW）。同理，`ignored` 也會寫進 JSON 並參與 NEW 判定。

## 15. 首次執行時，所有項目標為「無法判定是否新增」

沒有比對基準時，可以選「全部標 NEW」或「全部標否」或「全部標無法判定」。
決定選**無法判定**，並在報表的基準欄位寫「首次執行，無比對基準」。
這與規劃 §5.1 的精神一致（寧可說不知道，不要給假 NEW）。

## 16. `--offline` 的快取未命中會讓 `AllSourcesOK = false`

即使 OSV 這個「來源」本身沒有失敗。理由：下一次執行要靠 `all_sources_ok`
決定能不能當 NEW 判定的基準，而這次有對象完全沒被檢查，拿它當基準會產生假 NEW。

## 17. 程式語言的 EOL：go / python / rust 都查，弱點清單只有 go

規劃 §7 的 Phase 1b 只寫了 go 的 EOL，但 §4.3 寫「Phase 1 的 rust 只輸出
EOL / 版本落後狀態」。決定三個語言的 EOL 都查（同一個端點、同一個解析器），
但弱點清單只有 go（OSV `stdlib` + `toolchain`）。

規劃 §11 把「endoflife.date v1 的 python、rust 是否與 go 同結構」列為待確認項目，
所以解析器寫成容錯的：欄位缺漏時 `eol` 會是 `unknown`、`patches_behind` 不顯示，
並在報表警告區寫出「endoflife.date 回應結構與預期不符」，**不會給出錯誤的結論**。

## 18. 「版本線」一律取 major.minor

go `1.27.3` → `1.27`、python `3.12.7` → `3.12`、rust `1.82.0` → `1.82`。
三者的 endoflife.date `releases[].name` 都是這個形式。

## 19. 已撤回（withdrawn）的 advisory 直接丟棄

OSV 的 `withdrawn` 欄位非空表示該 advisory 已被撤回。決定在客戶端就過濾掉，
不進報表 —— 提醒使用者處理一個已撤回的弱點是純噪音。

---

## 實作過程中發現的規劃問題（未修改規劃）

1. **§6 的 package 結構與 §7 的 Phase 1b 內容矛盾。** §6 說 `internal/source/{nvd,eol}`
   是 Phase 2，但 §7 的 Phase 1b 要求做 endoflife.date 與 NVD 補分數。
   處理方式見本文件 §1。

2. **§3.3 的演算法沒有定義「找不到包含目前版本的那一段」時怎麼辦。**
   處理方式見 §5。

3. **§3.2 沒有定義 `fail_on` 與 UNKNOWN 的關係。** 處理方式見 §4。

4. **§3.4 的驗證規則說 `min_severity` 接受 `""`，但沒說語意。** 處理方式見 §10。

5. **§3.2 第 3 層回退（NVD 補分數）會讓項目離開 UNKNOWN 區塊**，
   這與 §9 的回歸案例「`GO-*` 必須出現在 UNKNOWN 區塊」在 `nvd = true` 時會衝突。
   不是規劃的錯，但驗收時要知道這點，見 §8。

6. **§2.2 的「advisory 內容長效快取」在 Phase 1 幾乎用不到。**
   因為 §2.1 決定用 `POST /v1/query`（直接回完整 advisory），不需要再打
   `GET /v1/vulns/{id}`，所以沒有「advisory id + modified」這個鍵可以用。
   `httpx` 已經把這一層做成通用能力（`CacheKey` + `CacheTTL`），Phase 1b 的
   NVD 補分數就是用它；真正按 advisory id 快取要等 Phase 2 走 querybatch 混合路線。
   「第二次執行請求數明顯下降」目前是靠第一層（查詢結果）快取達成的。

---

## Phase 1b 補充決策

## 20. NVD 的「沒有 CVSS 資料」不算來源失敗

NVD 回應讀得到、但裡面沒有該 CVE 的 CVSS 資料（很多 CVE 本來就還沒評分）時，
只留警告，**不把 NVD 的來源狀態標成失敗**。只有真正的 HTTP / 傳輸錯誤才算失敗。

理由：如果資料缺口算失敗，`all_sources_ok` 幾乎永遠是 false，那麼 §5.1 的
「優先選最近一次全來源成功的 JSON 當基準」就永遠選不到基準，所有項目會一直停在
「無法判定是否新增」，NEW 功能等於廢掉。來源狀態欄位會顯示
「N 筆 CVE 在 NVD 沒有 CVSS 資料」，使用者仍然看得到這件事。

## 21. 第 3 層回退只對 UNKNOWN 的項目做

已經有分數（第 1 層）或有質性等級（第 2 層）的項目不會再去打 NVD。
這是回退鏈的定義，同時也大幅省請求數 —— 多數項目在第 1/2 層就有結果。

## 22. 語言執行環境的弱點也走同一條 Finding 管線

`stdlib` / `toolchain` 的查詢結果用 `Target.Kind = "language"` 標記，
但分類、嚴重度回退、修正版本挑選、NEW 判定全部與套件共用同一套邏輯。
報表第 4 節（語言執行環境狀態）只放 EOL / 版本落後的結論，
弱點本身照規矩落在需處理清單或 UNKNOWN 區塊 —— 這樣 `GO-*` 才不會被
「語言區塊」藏起來。
