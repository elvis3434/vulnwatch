package httpx

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// 檔案快取。規劃 §2.2 的要點：
//   - 鍵用 sha256 hex 當檔名，不要用 URL 當檔名（Windows 非法字元與路徑長度限制）。
//   - 快取檔一律 gzip（OSV advisory 的 affected[].versions 可能列舉數百個版本號）。
//   - 兩層 TTL：查詢結果用 cache_ttl，advisory 內容用長效 TTL。

// ErrCacheMiss 表示快取沒有這筆資料，或已經過期（非 offline 模式）。
var ErrCacheMiss = errors.New("快取未命中")

// cacheEntry 是寫進快取檔的信封。
type cacheEntry struct {
	Key      string    `json:"key"`
	Method   string    `json:"method"`
	URL      string    `json:"url"`
	Status   int       `json:"status"`
	StoredAt time.Time `json:"stored_at"`
	TTLSec   int64     `json:"ttl_seconds"`
	Body     []byte    `json:"body"`
}

// QueryCacheKey 是查詢結果（POST 查詢）的快取鍵：
// method + URL + request body 的 sha256（規劃 §2.2：POST 查詢的 body 必須進 hash）。
func QueryCacheKey(method, url string, body []byte) string {
	bodySum := sha256.Sum256(body)
	h := sha256.New()
	fmt.Fprintf(h, "v1\n%s\n%s\n%s", method, url, hex.EncodeToString(bodySum[:]))
	return hex.EncodeToString(h.Sum(nil))
}

// AdvisoryCacheKey 是 advisory 內容的長效快取鍵：advisory ID + 回應中的 modified
// （規劃 §2.2：modified 一變就自然成為新鍵，所以 TTL 可以設很長）。
func AdvisoryCacheKey(id, modified string) string {
	h := sha256.New()
	fmt.Fprintf(h, "advisory\n%s\n%s", id, modified)
	return hex.EncodeToString(h.Sum(nil))
}

// NamedCacheKey 給非 HTTP-URL 導向的快取項目使用（例如 "nvd-cve:CVE-2023-1234"）。
func NamedCacheKey(name string) string {
	h := sha256.New()
	fmt.Fprintf(h, "named\n%s", name)
	return hex.EncodeToString(h.Sum(nil))
}

type fileCache struct {
	dir string
}

// path 把 sha256 hex 鍵轉成快取檔路徑，前兩碼當分層目錄避免單一目錄檔案過多。
// 一律用 path/filepath，支援 Windows 路徑與中文路徑（規劃 §6）。
func (c *fileCache) path(key string) string {
	if len(key) < 4 {
		return filepath.Join(c.dir, key+".json.gz")
	}
	return filepath.Join(c.dir, key[:2], key+".json.gz")
}

// get 讀取快取。allowStale 為 true 時（--offline）連過期的也回傳，
// 並以第二個回傳值告知是否已過期。
func (c *fileCache) get(key string, now time.Time, allowStale bool) (*cacheEntry, bool, error) {
	if c.dir == "" {
		return nil, false, ErrCacheMiss
	}
	f, err := os.Open(c.path(key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, ErrCacheMiss
		}
		return nil, false, err
	}
	defer f.Close()

	zr, err := gzip.NewReader(f)
	if err != nil {
		// 快取檔壞了就當未命中，不要讓整次掃描失敗。
		return nil, false, ErrCacheMiss
	}
	defer zr.Close()

	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, false, ErrCacheMiss
	}
	var e cacheEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, false, ErrCacheMiss
	}

	stale := false
	if e.TTLSec > 0 {
		expiry := e.StoredAt.Add(time.Duration(e.TTLSec) * time.Second)
		if now.After(expiry) {
			stale = true
		}
	}
	if stale && !allowStale {
		return nil, true, ErrCacheMiss
	}
	return &e, stale, nil
}

func (c *fileCache) put(e *cacheEntry) error {
	if c.dir == "" {
		return nil
	}
	p := c.path(e.Key)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}

	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}

	// 先寫暫存檔再 rename，避免寫入中途被中斷留下半截快取檔。
	tmp, err := os.CreateTemp(filepath.Dir(p), "tmp-*.gz")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	zw := gzip.NewWriter(tmp)
	if _, err := zw.Write(raw); err != nil {
		zw.Close()
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	// Windows 上 rename 到已存在的檔案會失敗，先移除舊檔。
	_ = os.Remove(p)
	if err := os.Rename(tmpName, p); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
