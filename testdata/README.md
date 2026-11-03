# testdata — 測試用 fixture

`go test ./...` **絕不會打真實網路**（規劃 §6）。所有外部 API 的回應都來自這個目錄，
由 `httptest` 伺服器回放。

## 這些 fixture 的來源

本次開發環境的網路政策封鎖了全部弱點 API 主機（`api.osv.dev`、
`services.nvd.nist.gov`、`endoflife.date`、`api.deps.dev`、`api.first.org`
的 CONNECT 都被代理以 403 拒絕），所以**無法錄製真實回應**。

目前的 fixture 是依規劃 §11「已驗證」表格中記錄的實測事實**手寫**的：
欄位名稱、型別、以及關鍵的資料形狀（例如 `severity` 是 vector 字串、
`GO-*` 的 `severity` 為 `null`、urllib3 的兩段 ranges）都照實測記錄還原，
但不是逐位元組相同的真實回應。

受影響最大的是 NVD：規劃 §11 把「NVD 回應中的 CVSS 區塊路徑」列為
**實作時仍需確認**的項目，而本次無法確認。`testdata/nvd/` 的結構是依
NVD API 2.0 的公開文件寫的（`vulnerabilities[].cve.metrics.cvssMetricV31[].cvssData.baseScore`），
程式端刻意寫得寬容（找不到就退回 UNKNOWN 並在報表留警告），但這條路徑
**尚未用真實請求驗證過**。

## 重新錄製

網路可通時，用 live 測試重新錄製（這些測試只在 `-tags=live` 時編譯）：

```
go test -tags=live ./internal/source/... ./internal/scan/... -run Record -v
```

錄製完成後再跑一次 `go test ./...`，確認離線測試仍然通過。
