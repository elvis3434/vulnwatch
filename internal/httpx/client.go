// Package httpx 是所有外部 API 呼叫的共用出口：逾時、指數退避重試、
// per-host 速率限制、代理、自簽 CA，以及規劃 §2.2 的雙層檔案快取。
package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

// ErrOfflineMiss 表示 --offline 模式下快取未命中。
// 呼叫端必須把這類項目標示為「無資料（offline）」，不可當成「無弱點」（規劃 §2.2）。
var ErrOfflineMiss = errors.New("offline 模式且快取未命中")

// DefaultCacheTTL 是查詢結果的預設 TTL（設定檔的 cache_ttl）。
const DefaultCacheTTL = 12 * time.Hour

// LongCacheTTL 是 advisory 內容這類「幾乎不變」資料的長效 TTL（規劃 §2.2：30 天以上）。
const LongCacheTTL = 30 * 24 * time.Hour

// NoCacheTTL 放進 Request.CacheTTL 表示這筆請求不要快取。
const NoCacheTTL = -1 * time.Second

// HostLimit 是單一 host 的速率限制設定（規劃 §6：per-host，不是一個全域值）。
type HostLimit struct {
	// Concurrency 是同時進行的請求數上限。
	Concurrency int
	// MinInterval 是同一個 host 兩次請求之間的最小間隔。
	MinInterval time.Duration
}

// DefaultHostLimits 依規劃 §6 的實測建議設定。
func DefaultHostLimits() map[string]HostLimit {
	return map[string]HostLimit{
		// 可併發，自我節流 5~8；Phase 1 保守取 5（規劃 §11 最後一項）。
		"api.osv.dev": {Concurrency: 5},
		// 無金鑰 5 req/30s，實務上序列化並以 6 秒間隔最穩。
		// 有金鑰時由 SetHostLimit 覆寫成 50 req/30s（0.6s 間隔）。
		"services.nvd.nist.gov": {Concurrency: 1, MinInterval: 6 * time.Second},
		// 其餘來源都是一次性請求，用預設值即可。
		"endoflife.date": {Concurrency: 2},
		"api.deps.dev":   {Concurrency: 4},
		"api.first.org":  {Concurrency: 2},
	}
}

// Options 是建立 Client 的參數。
type Options struct {
	UserAgent  string
	Timeout    time.Duration
	Proxy      string
	CAFile     string
	CacheDir   string
	CacheTTL   time.Duration
	Offline    bool
	NoCache    bool
	MaxRetries int
	HostLimits map[string]HostLimit
	// Logf 為 nil 時不輸出任何東西。
	Logf func(format string, args ...any)
	// Now 與 Sleep 只給測試覆寫，正式執行用 time.Now / time.Sleep。
	Now   func() time.Time
	Sleep func(time.Duration)
}

// Stats 是請求統計，用來驗收「第二次執行的網路請求數明顯下降」（規劃 §9）。
type Stats struct {
	NetworkRequests int
	CacheHits       int
	StaleCacheHits  int
	Retries         int
	OfflineMisses   int
}

// Client 是帶快取與限流的 HTTP 客戶端。
type Client struct {
	opts  Options
	http  *http.Client
	cache *fileCache

	mu       sync.Mutex
	limiters map[string]*hostLimiter
	stats    Stats
}

// Request 是一筆要發出（或從快取取得）的請求。
type Request struct {
	Method      string
	URL         string
	Body        []byte
	ContentType string
	Header      map[string]string
	// CacheKey 非空時直接當快取鍵使用（規劃 §2.2 的長效層，例如
	// AdvisoryCacheKey(id, modified)）。留空則用 QueryCacheKey 自動計算。
	CacheKey string
	// CacheTTL 為 0 時用 Options.CacheTTL；設成 NoCacheTTL 則不快取。
	CacheTTL time.Duration
}

// Response 是請求結果。
type Response struct {
	Status    int
	Body      []byte
	URL       string
	FromCache bool
	// Stale 為 true 表示這是 --offline 模式下回傳的過期快取。
	Stale bool
}

// New 建立 Client。
func New(opts Options) (*Client, error) {
	if opts.UserAgent == "" {
		opts.UserAgent = "vulnwatch"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = DefaultCacheTTL
	}
	if opts.MaxRetries < 0 {
		opts.MaxRetries = 0
	}
	if opts.MaxRetries == 0 {
		opts.MaxRetries = 3
	}
	if opts.HostLimits == nil {
		opts.HostLimits = DefaultHostLimits()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Sleep == nil {
		opts.Sleep = time.Sleep
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	if opts.Proxy != "" {
		u, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("[network].proxy 不是合法的 URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(u)
	}

	// 公司網路做 TLS 攔截時，把自簽 CA 加入系統 cert pool。
	// 刻意不提供停用憑證驗證的選項（規劃 §3.4）。
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("讀取 [network].ca_file 失敗: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("[network].ca_file %q 不含任何可用的 PEM 憑證", opts.CAFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}

	c := &Client{
		opts:     opts,
		http:     &http.Client{Transport: transport, Timeout: opts.Timeout},
		cache:    &fileCache{dir: opts.CacheDir},
		limiters: map[string]*hostLimiter{},
	}
	return c, nil
}

// Stats 回傳目前的請求統計快照。
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// Offline 回傳是否處於 --offline 模式。
func (c *Client) Offline() bool { return c.opts.Offline }

// SetHostLimit 覆寫某個 host 的速率限制（例如拿到 NVD 金鑰後放寬）。
func (c *Client) SetHostLimit(host string, limit HostLimit) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.opts.HostLimits[host] = limit
	delete(c.limiters, host)
}

func (c *Client) logf(format string, args ...any) {
	if c.opts.Logf != nil {
		c.opts.Logf(format, args...)
	}
}

// Do 執行一筆請求：先查快取，未命中才發網路請求，成功後寫回快取。
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	if req.Method == "" {
		req.Method = http.MethodGet
	}

	ttl := req.CacheTTL
	if ttl == 0 {
		ttl = c.opts.CacheTTL
	}
	useCache := ttl > 0 && c.opts.CacheDir != ""

	key := req.CacheKey
	if key == "" {
		key = QueryCacheKey(req.Method, req.URL, req.Body)
	}

	// --no-cache 只是不「讀」快取；仍然會寫入，否則 --offline 永遠沒有資料可用。
	if useCache && !c.opts.NoCache {
		e, stale, err := c.cache.get(key, c.opts.Now(), c.opts.Offline)
		if err == nil && e != nil {
			c.mu.Lock()
			c.stats.CacheHits++
			if stale {
				c.stats.StaleCacheHits++
			}
			c.mu.Unlock()
			c.logf("快取命中 %s %s (stale=%v)", req.Method, req.URL, stale)
			return &Response{Status: e.Status, Body: e.Body, URL: e.URL, FromCache: true, Stale: stale}, nil
		} else if err != nil && !errors.Is(err, ErrCacheMiss) {
			c.logf("讀取快取失敗 %s: %v", req.URL, err)
		}
	}

	if c.opts.Offline {
		c.mu.Lock()
		c.stats.OfflineMisses++
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: %s %s", ErrOfflineMiss, req.Method, req.URL)
	}

	resp, err := c.doNetwork(ctx, req)
	if err != nil {
		return nil, err
	}

	if useCache {
		entry := &cacheEntry{
			Key:      key,
			Method:   req.Method,
			URL:      req.URL,
			Status:   resp.Status,
			StoredAt: c.opts.Now(),
			TTLSec:   int64(ttl / time.Second),
			Body:     resp.Body,
		}
		if err := c.cache.put(entry); err != nil {
			c.logf("寫入快取失敗 %s: %v", req.URL, err)
		}
	}
	return resp, nil
}

// doNetwork 真的發出請求，含指數退避重試。
func (c *Client) doNetwork(ctx context.Context, req Request) (*Response, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("URL 不合法 %q: %w", req.URL, err)
	}
	lim := c.limiterFor(u.Host)

	var lastErr error
	attempts := c.opts.MaxRetries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			wait := backoff(attempt)
			c.mu.Lock()
			c.stats.Retries++
			c.mu.Unlock()
			c.logf("重試 %s %s（第 %d 次，等待 %s）：%v", req.Method, req.URL, attempt, wait, lastErr)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			c.opts.Sleep(wait)
		}

		resp, retryAfter, err := c.attempt(ctx, req, lim)
		if err == nil {
			return resp, nil
		}
		lastErr = err

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var re *retryableError
		if !errors.As(err, &re) {
			return nil, err
		}
		if retryAfter > 0 {
			c.opts.Sleep(retryAfter)
		}
	}
	return nil, fmt.Errorf("重試 %d 次後仍失敗: %w", attempts, lastErr)
}

type retryableError struct{ err error }

func (e *retryableError) Error() string { return e.err.Error() }
func (e *retryableError) Unwrap() error { return e.err }

func (c *Client) attempt(ctx context.Context, req Request, lim *hostLimiter) (*Response, time.Duration, error) {
	if err := lim.acquire(ctx, c.opts.Sleep, c.opts.Now); err != nil {
		return nil, 0, err
	}
	defer lim.release()

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, 0, err
	}
	hreq.Header.Set("User-Agent", c.opts.UserAgent)
	hreq.Header.Set("Accept", "application/json")
	if req.ContentType != "" {
		hreq.Header.Set("Content-Type", req.ContentType)
	}
	for k, v := range req.Header {
		hreq.Header.Set(k, v)
	}

	c.mu.Lock()
	c.stats.NetworkRequests++
	c.mu.Unlock()

	hresp, err := c.http.Do(hreq)
	if err != nil {
		// 網路層錯誤一律可重試。
		return nil, 0, &retryableError{err: err}
	}
	defer hresp.Body.Close()

	raw, readErr := io.ReadAll(hresp.Body)
	if readErr != nil {
		return nil, 0, &retryableError{err: fmt.Errorf("讀取回應失敗: %w", readErr)}
	}

	switch {
	case hresp.StatusCode == http.StatusTooManyRequests,
		hresp.StatusCode >= 500 && hresp.StatusCode <= 599:
		ra := parseRetryAfter(hresp.Header.Get("Retry-After"))
		return nil, ra, &retryableError{
			err: fmt.Errorf("%s %s 回應 HTTP %d", req.Method, req.URL, hresp.StatusCode),
		}
	case hresp.StatusCode >= 400:
		// 4xx（除了 429）重試沒有意義。
		return nil, 0, fmt.Errorf("%s %s 回應 HTTP %d: %s",
			req.Method, req.URL, hresp.StatusCode, truncate(string(raw), 200))
	}

	return &Response{Status: hresp.StatusCode, Body: raw, URL: req.URL}, 0, nil
}

func (c *Client) limiterFor(host string) *hostLimiter {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.limiters[host]; ok {
		return l
	}
	limit, ok := c.opts.HostLimits[host]
	if !ok {
		limit = HostLimit{Concurrency: 4}
	}
	if limit.Concurrency <= 0 {
		limit.Concurrency = 1
	}
	l := newHostLimiter(limit)
	c.limiters[host] = l
	return l
}

// backoff 回傳第 n 次重試前要等待的時間：1s、2s、4s…，上限 16s。
func backoff(attempt int) time.Duration {
	d := time.Second << (attempt - 1)
	if d > 16*time.Second {
		d = 16 * time.Second
	}
	return d
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		if secs > 60 {
			secs = 60
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d > 0 {
			if d > time.Minute {
				d = time.Minute
			}
			return d
		}
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
