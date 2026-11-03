package httpx

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, mod func(*Options)) *Client {
	t.Helper()
	opts := Options{
		UserAgent: "vulnwatch/test",
		CacheDir:  t.TempDir(),
		CacheTTL:  time.Hour,
		// 測試不可真的 sleep。
		Sleep: func(time.Duration) {},
	}
	if mod != nil {
		mod(&opts)
	}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("httpx.New 失敗: %v", err)
	}
	return c
}

// TestCacheHitAvoidsSecondRequest 是驗收標準「第二次執行的網路請求數明顯下降」
// 的最小驗證（規劃 §9 / §2.2）。
func TestCacheHitAvoidsSecondRequest(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	req := Request{Method: http.MethodPost, URL: srv.URL + "/v1/query", Body: []byte(`{"a":1}`)}

	c1 := newTestClient(t, func(o *Options) { o.CacheDir = dir })
	if _, err := c1.Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	// 同一個 client 再打一次
	if _, err := c1.Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	// 換一個 client（模擬第二次執行），共用同一個快取目錄
	c2 := newTestClient(t, func(o *Options) { o.CacheDir = dir })
	resp, err := c2.Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.FromCache {
		t.Error("第二次執行應該命中快取")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("伺服器收到 %d 次請求，預期 1 次（其餘應由快取服務）", got)
	}
	if c2.Stats().NetworkRequests != 0 {
		t.Errorf("第二次執行的網路請求數 = %d，預期 0", c2.Stats().NetworkRequests)
	}
}

// TestCacheKeyIncludesBody 驗證 POST 查詢的 body 有進快取鍵（規劃 §2.2）。
func TestCacheKeyIncludesBody(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(t, nil)
	url := srv.URL + "/v1/query"
	for _, body := range []string{`{"name":"a"}`, `{"name":"b"}`, `{"name":"a"}`} {
		if _, err := c.Do(context.Background(), Request{
			Method: http.MethodPost, URL: url, Body: []byte(body),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("伺服器收到 %d 次請求，預期 2 次（不同 body 要是不同快取鍵）", got)
	}

	if QueryCacheKey("POST", url, []byte(`{"name":"a"}`)) == QueryCacheKey("POST", url, []byte(`{"name":"b"}`)) {
		t.Error("不同 body 必須產生不同的快取鍵")
	}
}

// TestCacheFileIsGzipAndSha256Named 驗證規劃 §2.2 的兩個檔案層面要求：
// 檔名用 sha256 hex（避開 Windows 非法字元與路徑長度限制）、內容 gzip。
func TestCacheFileIsGzipAndSha256Named(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"big":"` + strings.Repeat("x", 5000) + `"}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	c := newTestClient(t, func(o *Options) { o.CacheDir = dir })
	if _, err := c.Do(context.Background(), Request{URL: srv.URL + "/a?b=c&d=/e"}); err != nil {
		t.Fatal(err)
	}

	var found string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(p, ".gz") {
			found = p
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == "" {
		t.Fatal("找不到快取檔")
	}

	base := filepath.Base(found)
	name := strings.TrimSuffix(base, ".json.gz")
	if len(name) != 64 {
		t.Errorf("快取檔名 %q 不是 64 位 sha256 hex", base)
	}
	for _, r := range name {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Errorf("快取檔名 %q 含非 hex 字元", base)
			break
		}
	}

	f, err := os.Open(found)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("快取檔不是 gzip: %v", err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	var e cacheEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("快取內容不是合法 JSON: %v", err)
	}
	if e.Status != 200 || len(e.Body) == 0 {
		t.Errorf("快取信封內容有問題: %+v", e.Status)
	}
}

// TestOfflineMiss 驗證 --offline 快取未命中時回傳 ErrOfflineMiss，
// 讓呼叫端能標示「無資料」而不是「無弱點」（規劃 §2.2）。
func TestOfflineMiss(t *testing.T) {
	c := newTestClient(t, func(o *Options) { o.Offline = true })
	_, err := c.Do(context.Background(), Request{URL: "https://api.osv.dev/v1/query"})
	if !errors.Is(err, ErrOfflineMiss) {
		t.Fatalf("err = %v，預期 ErrOfflineMiss", err)
	}
	if c.Stats().NetworkRequests != 0 {
		t.Error("offline 模式不可發出網路請求")
	}
	if c.Stats().OfflineMisses != 1 {
		t.Errorf("OfflineMisses = %d，預期 1", c.Stats().OfflineMisses)
	}
}

// TestOfflineServesStaleCache 驗證 --offline 時連過期快取也能用（這才是 offline 的意義）。
func TestOfflineServesStaleCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"cached":true}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	req := Request{URL: srv.URL + "/v1/x"}

	base := time.Now()
	warm := newTestClient(t, func(o *Options) {
		o.CacheDir = dir
		o.CacheTTL = time.Minute
		o.Now = func() time.Time { return base }
	})
	if _, err := warm.Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	// 快取已過期，但處於 offline 模式 → 仍然回傳，並標記 Stale。
	late := newTestClient(t, func(o *Options) {
		o.CacheDir = dir
		o.CacheTTL = time.Minute
		o.Offline = true
		o.Now = func() time.Time { return base.Add(time.Hour) }
	})
	resp, err := late.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("offline 應該回傳過期快取: %v", err)
	}
	if !resp.FromCache || !resp.Stale {
		t.Errorf("resp.FromCache=%v Stale=%v，預期都是 true", resp.FromCache, resp.Stale)
	}

	// 非 offline 模式下，過期快取不可使用。
	fresh := newTestClient(t, func(o *Options) {
		o.CacheDir = dir
		o.CacheTTL = time.Minute
		o.Now = func() time.Time { return base.Add(time.Hour) }
	})
	resp2, err := fresh.Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.FromCache {
		t.Error("非 offline 模式下不該使用過期快取")
	}
}

// TestNoCacheStillWrites 驗證 --no-cache 只是不讀快取，仍會寫入
// （否則 --offline 永遠沒有資料可用）。
func TestNoCacheStillWrites(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	req := Request{URL: srv.URL + "/x"}

	c := newTestClient(t, func(o *Options) {
		o.CacheDir = dir
		o.NoCache = true
	})
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("--no-cache 下伺服器收到 %d 次，預期 2 次（不讀快取）", got)
	}

	reader := newTestClient(t, func(o *Options) { o.CacheDir = dir })
	resp, err := reader.Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.FromCache {
		t.Error("--no-cache 仍應寫入快取，供後續 --offline 使用")
	}
}

// TestLongLivedCacheKey 驗證 advisory 的長效快取層（規劃 §2.2 第二層）。
func TestLongLivedCacheKey(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	base := time.Now()
	c := newTestClient(t, func(o *Options) {
		// 查詢層 TTL 很短，但長效層自己帶 TTL。
		o.CacheTTL = time.Second
		o.Now = func() time.Time { return base }
	})

	req := Request{
		URL:      srv.URL + "/v1/vulns/GHSA-x",
		CacheKey: AdvisoryCacheKey("GHSA-x", "2024-06-18T10:12:03Z"),
		CacheTTL: LongCacheTTL,
	}
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	// 兩週後仍應命中（advisory 內容幾乎不變）。
	later := newTestClient(t, func(o *Options) {
		o.CacheDir = c.opts.CacheDir
		o.CacheTTL = time.Second
		o.Now = func() time.Time { return base.Add(14 * 24 * time.Hour) }
	})
	resp, err := later.Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.FromCache {
		t.Error("advisory 長效快取應該仍然命中")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("伺服器收到 %d 次請求，預期 1 次", got)
	}

	// modified 一變就是新鍵。
	if AdvisoryCacheKey("GHSA-x", "2024-06-18T10:12:03Z") == AdvisoryCacheKey("GHSA-x", "2024-07-01T00:00:00Z") {
		t.Error("modified 不同時必須是不同的快取鍵")
	}
}

// TestRetryOn5xxAnd429 驗證指數退避重試。
func TestRetryOn5xxAnd429(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		switch n {
		case 1:
			w.WriteHeader(http.StatusInternalServerError)
		case 2:
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	c := newTestClient(t, func(o *Options) { o.MaxRetries = 3 })
	resp, err := c.Do(context.Background(), Request{URL: srv.URL + "/x"})
	if err != nil {
		t.Fatalf("重試後應該成功: %v", err)
	}
	if resp.Status != 200 {
		t.Errorf("status = %d", resp.Status)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("伺服器收到 %d 次請求，預期 3 次", got)
	}
	if c.Stats().Retries != 2 {
		t.Errorf("Retries = %d，預期 2", c.Stats().Retries)
	}
}

// TestNoRetryOn404 驗證 4xx（除 429）不重試。
func TestNoRetryOn404(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(t, func(o *Options) { o.MaxRetries = 3 })
	if _, err := c.Do(context.Background(), Request{URL: srv.URL + "/x"}); err == nil {
		t.Fatal("404 應該回傳錯誤")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("伺服器收到 %d 次請求，預期 1 次（404 不重試）", got)
	}
}

// TestFailedResponseIsNotCached 驗證失敗的回應不會被寫進快取。
func TestFailedResponseIsNotCached(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	req := Request{URL: srv.URL + "/x"}
	c := newTestClient(t, func(o *Options) { o.CacheDir = dir })
	if _, err := c.Do(context.Background(), req); err == nil {
		t.Fatal("第一次應該失敗")
	}
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("第二次應該成功: %v", err)
	}
	if resp.FromCache {
		t.Error("失敗的回應不該被快取")
	}
}

// TestPerHostRateLimit 驗證 per-host 的最小間隔（規劃 §6：NVD 無金鑰要 6 秒間隔）。
func TestPerHostRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	var slept []time.Duration
	c := newTestClient(t, nil)
	c.opts.Sleep = func(d time.Duration) { slept = append(slept, d) }

	host := strings.TrimPrefix(srv.URL, "http://")
	c.SetHostLimit(host, HostLimit{Concurrency: 1, MinInterval: 6 * time.Second})

	fixed := time.Now()
	c.opts.Now = func() time.Time { return fixed }

	for i := 0; i < 3; i++ {
		if _, err := c.Do(context.Background(), Request{
			Method: http.MethodPost, URL: srv.URL + "/x", Body: []byte(`{"i":` + string(rune('0'+i)) + `}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(slept) < 2 {
		t.Fatalf("等待次數 = %d，預期至少 2 次（第 2、3 次請求要等間隔）", len(slept))
	}
	if slept[0] != 6*time.Second {
		t.Errorf("第一次等待 = %v，預期 6s", slept[0])
	}
	if slept[1] != 12*time.Second {
		t.Errorf("第二次等待 = %v，預期 12s（累積排隊）", slept[1])
	}
}

// TestDefaultHostLimitsCoverKnownSources 驗證規劃 §6 列出的 per-host 設定存在。
func TestDefaultHostLimitsCoverKnownSources(t *testing.T) {
	limits := DefaultHostLimits()
	if l := limits["api.osv.dev"]; l.Concurrency != 5 {
		t.Errorf("api.osv.dev 併發 = %d，預期 5（規劃 §11 保守值）", l.Concurrency)
	}
	nvd := limits["services.nvd.nist.gov"]
	if nvd.Concurrency != 1 || nvd.MinInterval != 6*time.Second {
		t.Errorf("NVD 限制 = %+v，預期序列化 + 6 秒間隔", nvd)
	}
}

// TestCAFileRejectsBadPEM 驗證 ca_file 的錯誤處理（不提供停用憑證驗證的選項）。
func TestCAFileRejectsBadPEM(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(p, []byte("not a pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{CAFile: p}); err == nil {
		t.Fatal("無效的 CA 檔應該回傳錯誤")
	}
	if _, err := New(Options{CAFile: filepath.Join(t.TempDir(), "missing.pem")}); err == nil {
		t.Fatal("不存在的 CA 檔應該回傳錯誤")
	}
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	if got := backoff(1); got != time.Second {
		t.Errorf("backoff(1) = %v，預期 1s", got)
	}
	if got := backoff(2); got != 2*time.Second {
		t.Errorf("backoff(2) = %v，預期 2s", got)
	}
	if got := backoff(10); got != 16*time.Second {
		t.Errorf("backoff(10) = %v，預期上限 16s", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("5"); got != 5*time.Second {
		t.Errorf("parseRetryAfter(5) = %v", got)
	}
	if got := parseRetryAfter("99999"); got != time.Minute {
		t.Errorf("parseRetryAfter 應該有上限，得到 %v", got)
	}
	if got := parseRetryAfter(""); got != 0 {
		t.Errorf("parseRetryAfter(\"\") = %v", got)
	}
}
