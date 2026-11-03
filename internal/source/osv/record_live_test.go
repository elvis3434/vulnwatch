//go:build live

// 這個檔案只在 `go test -tags=live ./...` 時編譯，用來重新錄製 testdata fixture。
// 平常的 `go test ./...` 絕不會打真實網路（規劃 §6 / §10 第 3 點）。
package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elvis3434/vulnwatch/internal/httpx"
	"github.com/elvis3434/vulnwatch/internal/model"
)

// TestRecordOSVFixtures 重新錄製 OSV 的 fixture。
//
//	go test -tags=live ./internal/source/osv -run TestRecordOSVFixtures -v
func TestRecordOSVFixtures(t *testing.T) {
	cases := []struct {
		file      string
		ecosystem string
		name      string
		version   string
	}{
		{"pypi_urllib3_1.26.5.json", model.EcosystemPyPI, "urllib3", "1.26.5"},
		{"pypi_requests_2.31.0.json", model.EcosystemPyPI, "requests", "2.31.0"},
		{"go_x_net_v0.20.0.json", model.EcosystemGo, "golang.org/x/net", "v0.20.0"},
		{"go_stdlib_v1.21.0.json", model.EcosystemGo, "stdlib", "v1.21.0"},
		{"go_toolchain_v1.21.0.json", model.EcosystemGo, "toolchain", "v1.21.0"},
		{"maven_log4j_2.14.1.json", model.EcosystemMaven, "org.apache.logging.log4j:log4j-core", "2.14.1"},
	}

	h, err := httpx.New(httpx.Options{
		UserAgent: "vulnwatch/live-record",
		Timeout:   30 * time.Second,
		CacheDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join("..", "..", "..", "testdata", "osv")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, c := range cases {
		body, err := json.Marshal(queryRequest{
			Version: c.version,
			Package: &Package{Ecosystem: c.ecosystem, Name: c.name},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := h.Do(context.Background(), httpx.Request{
			Method:      http.MethodPost,
			URL:         DefaultEndpoint + "/v1/query",
			Body:        body,
			ContentType: "application/json",
		})
		if err != nil {
			t.Errorf("%s 查詢失敗: %v", c.file, err)
			continue
		}

		var pretty map[string]any
		if err := json.Unmarshal(resp.Body, &pretty); err != nil {
			t.Errorf("%s 回應不是 JSON: %v", c.file, err)
			continue
		}
		out, err := json.MarshalIndent(pretty, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(outDir, c.file)
		if err := os.WriteFile(p, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("已錄製 %s（%d bytes）", p, len(out))
	}
}

// TestLiveURLLib3Regression 用真實 API 驗證規劃 §9 的回歸案例。
func TestLiveURLLib3Regression(t *testing.T) {
	h, err := httpx.New(httpx.Options{
		UserAgent: "vulnwatch/live-record",
		Timeout:   30 * time.Second,
		CacheDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	advs, err := New(h, "").Query(context.Background(), model.EcosystemPyPI, "urllib3", "1.26.5")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range advs {
		if a.ID != "GHSA-34jh-p97f-mpxf" {
			continue
		}
		fix := SelectFix(a, model.EcosystemPyPI, "urllib3", "1.26.5", model.ComparerFor(model.EcosystemPyPI))
		if fix.Version != "1.26.19" {
			t.Fatalf("最低安全版本 = %q，預期 1.26.19", fix.Version)
		}
		return
	}
	t.Fatal("真實 API 回應中找不到 GHSA-34jh-p97f-mpxf")
}
