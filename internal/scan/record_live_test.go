//go:build live

// 這個檔案只在 `go test -tags=live ./...` 時編譯，用來重新錄製 testdata fixture。
// 平常的 `go test ./...` 絕不會打真實網路（規劃 §6 / §10 第 3 點）。
package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elvis3434/vulnwatch/internal/httpx"
)

func liveClient(t *testing.T) *httpx.Client {
	t.Helper()
	h, err := httpx.New(httpx.Options{
		UserAgent: "vulnwatch/live-record",
		Timeout:   30 * time.Second,
		CacheDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func recordJSON(t *testing.T, path string, raw []byte) {
	t.Helper()
	var pretty any
	if err := json.Unmarshal(raw, &pretty); err != nil {
		t.Fatalf("%s 的回應不是合法 JSON: %v", path, err)
	}
	out, err := json.MarshalIndent(pretty, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("已錄製 %s（%d bytes）", path, len(out))
}

// TestRecordNVDFixtures 錄製 NVD fixture。
//
// 這是規劃 §11「實作時仍需確認」的第 1、2 項：
//   - configurations[].nodes[].cpeMatch[] 的確切欄位名（§4.2 的後處理依賴它，Phase 2）
//   - CVSS 區塊路徑 cve.metrics.cvssMetricV31[].cvssData.baseScore（§3.2 第 3 層回退）
//
// 錄完之後請核對 internal/scan/nvd.go 的 nvdResponse 結構是否與實際回應一致。
//
//	go test -tags=live ./internal/scan -run TestRecordNVDFixtures -v
func TestRecordNVDFixtures(t *testing.T) {
	cves := []string{
		"CVE-2023-45288", // Go x/net，用於第 3 層回退的測試
		"CVE-2023-45289", // Go stdlib
	}
	h := liveClient(t)
	apiKey := os.Getenv("VULNWATCH_NVD_API_KEY")
	if apiKey != "" {
		h.SetHostLimit("services.nvd.nist.gov", httpx.HostLimit{
			Concurrency: 1, MinInterval: 600 * time.Millisecond,
		})
	}

	outDir := filepath.Join("..", "..", "testdata", "nvd")
	for _, cve := range cves {
		req := httpx.Request{
			Method: http.MethodGet,
			URL:    DefaultNVDEndpoint + "/rest/json/cves/2.0?cveId=" + cve,
		}
		if apiKey != "" {
			req.Header = map[string]string{"apiKey": apiKey}
		}
		resp, err := h.Do(context.Background(), req)
		if err != nil {
			t.Errorf("%s 查詢失敗: %v", cve, err)
			continue
		}
		recordJSON(t, filepath.Join(outDir, cve+".json"), resp.Body)

		// 順便檢查本工具假設的欄位路徑是否真的存在
		var parsed nvdResponse
		if err := json.Unmarshal(resp.Body, &parsed); err != nil {
			t.Errorf("%s 無法以 nvdResponse 結構解析: %v", cve, err)
			continue
		}
		if _, ok := severityFromNVD(&parsed, cve); !ok {
			t.Errorf("%s：nvd.go 假設的 CVSS 欄位路徑讀不到資料 —— "+
				"請依實際回應修正 nvdResponse（見 docs/decisions.md §6）", cve)
		} else {
			t.Logf("%s：CVSS 欄位路徑驗證通過", cve)
		}
	}
}

// TestRecordEOLFixtures 錄製 endoflife.date fixture。
//
// 這是規劃 §11「實作時仍需確認」的第 3 項：python / rust 是否與 go 同結構。
//
//	go test -tags=live ./internal/scan -run TestRecordEOLFixtures -v
func TestRecordEOLFixtures(t *testing.T) {
	h := liveClient(t)
	outDir := filepath.Join("..", "..", "testdata", "eol")

	for _, product := range []string{"go", "python", "rust"} {
		resp, err := h.Do(context.Background(), httpx.Request{
			Method: http.MethodGet,
			URL:    DefaultEOLEndpoint + "/api/v1/products/" + product,
		})
		if err != nil {
			t.Errorf("%s 查詢失敗: %v", product, err)
			continue
		}
		recordJSON(t, filepath.Join(outDir, product+".json"), resp.Body)

		var parsed eolResponse
		if err := json.Unmarshal(resp.Body, &parsed); err != nil {
			t.Errorf("%s 無法以 eolResponse 結構解析: %v", product, err)
			continue
		}
		if len(parsed.Result.Releases) == 0 {
			t.Errorf("%s：result.releases 是空的，結構可能已變更", product)
			continue
		}
		rel := parsed.Result.Releases[0]
		if rel.Name == "" || rel.Latest.Name == "" {
			t.Errorf("%s：releases[0] 缺少 name 或 latest.name（%+v）"+
				" —— python / rust 與 go 的結構可能不同（規劃 §11）", product, rel)
		} else {
			t.Logf("%s：結構驗證通過（最新版本線 %s，最新版本 %s）",
				product, rel.Name, rel.Latest.Name)
		}
	}
}
