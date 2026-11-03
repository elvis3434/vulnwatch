package scan

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeAPI 是回放 testdata fixture 的假伺服器。
// go test ./... 絕不打真實網路（規劃 §6），所有回應都來自 testdata。
type fakeAPI struct {
	t       *testing.T
	srv     *httptest.Server
	hits    int32
	mu      sync.Mutex
	paths   []string
	failOSV bool
	osv500  bool
	failNVD bool
}

func testdataPath(t *testing.T, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
}

func readFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(testdataPath(t, parts...))
	if err != nil {
		t.Fatalf("讀取 fixture %v 失敗: %v", parts, err)
	}
	return raw
}

// osvFixtureFor 把 (ecosystem, name, version) 對應到 fixture 檔。
func osvFixtureFor(ecosystem, name, version string) []string {
	switch {
	case ecosystem == "PyPI" && name == "urllib3":
		return []string{"osv", "pypi_urllib3_1.26.5.json"}
	case ecosystem == "PyPI" && name == "requests":
		return []string{"osv", "pypi_requests_2.31.0.json"}
	case ecosystem == "Go" && name == "golang.org/x/net":
		return []string{"osv", "go_x_net_v0.20.0.json"}
	case ecosystem == "Go" && name == "stdlib":
		return []string{"osv", "go_stdlib_v1.21.0.json"}
	case ecosystem == "Go" && name == "toolchain":
		return []string{"osv", "go_toolchain_v1.21.0.json"}
	case ecosystem == "Maven":
		return []string{"osv", "maven_log4j_2.14.1.json"}
	default:
		return []string{"osv", "empty.json"}
	}
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{t: t}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&f.hits, 1)
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()

	switch {
	case r.URL.Path == "/v1/query":
		if f.failOSV {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		if f.osv500 {
			http.Error(w, "oops", http.StatusInternalServerError)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Version string `json:"version"`
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
		}
		_ = json.Unmarshal(raw, &req)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(readFixture(f.t, osvFixtureFor(req.Package.Ecosystem, req.Package.Name, req.Version)...))

	case r.URL.Path == "/rest/json/cves/2.0":
		if f.failNVD {
			http.Error(w, "nvd down", http.StatusServiceUnavailable)
			return
		}
		id := r.URL.Query().Get("cveId")
		p := testdataPath(f.t, "nvd", id+".json")
		if _, err := os.Stat(p); err != nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(readFixture(f.t, "nvd", "empty.json"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(readFixture(f.t, "nvd", id+".json"))

	case strings.HasPrefix(r.URL.Path, "/api/v1/products/"):
		product := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/products/"), "/")
		p := testdataPath(f.t, "eol", product+".json")
		if _, err := os.Stat(p); err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(readFixture(f.t, "eol", product+".json"))

	default:
		http.NotFound(w, r)
	}
}

func (f *fakeAPI) Hits() int { return int(atomic.LoadInt32(&f.hits)) }

func (f *fakeAPI) ResetHits() { atomic.StoreInt32(&f.hits, 0) }

func (f *fakeAPI) Paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.paths))
	copy(out, f.paths)
	return out
}

func (f *fakeAPI) ResetPaths() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = nil
}
