package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/elvis3434/vulnwatch/internal/httpx"
)

// DefaultEndpoint 是 OSV.dev 的 API 根路徑。
const DefaultEndpoint = "https://api.osv.dev"

// Client 是 OSV 查詢客戶端。
type Client struct {
	http     *httpx.Client
	endpoint string
}

// New 建立 Client。endpoint 留空時用 DefaultEndpoint（測試時指向 httptest 伺服器）。
func New(h *httpx.Client, endpoint string) *Client {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	return &Client{http: h, endpoint: strings.TrimRight(endpoint, "/")}
}

// Query 用 POST /v1/query 查詢單一套件的弱點。
//
// 刻意不用 /v1/querybatch：它的回應只有 {id, modified}，拿不到 summary /
// severity / affected，必須再對每個 ID 打一次 GET /v1/vulns/{id}
// —— 50 個套件會變成 200+ 次請求（規劃 §2.1 的實測結論）。
func (c *Client) Query(ctx context.Context, ecosystem, name, version string) ([]Advisory, error) {
	body, err := json.Marshal(queryRequest{
		Version: strings.TrimSpace(version),
		Package: &Package{Ecosystem: ecosystem, Name: name},
	})
	if err != nil {
		return nil, err
	}

	url := c.endpoint + "/v1/query"
	resp, err := c.http.Do(ctx, httpx.Request{
		Method:      http.MethodPost,
		URL:         url,
		Body:        body,
		ContentType: "application/json",
		// 查詢結果用設定檔的 cache_ttl（規劃 §2.2 第一層）。
		// 快取鍵含 request body 的 sha256，由 httpx 自動計算。
	})
	if err != nil {
		return nil, err
	}

	var qr queryResponse
	if err := json.Unmarshal(resp.Body, &qr); err != nil {
		return nil, fmt.Errorf("OSV 回應不是合法的 JSON（%s/%s）: %w", ecosystem, name, err)
	}

	// 已撤回（withdrawn）的 advisory 不應該再提醒使用者。
	out := make([]Advisory, 0, len(qr.Vulns))
	for _, a := range qr.Vulns {
		if strings.TrimSpace(a.Withdrawn) != "" {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}
