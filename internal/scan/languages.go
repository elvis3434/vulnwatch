package scan

import (
	"context"
	"time"
)

// scanLanguages 是 Phase 1b 的程式語言執行環境掃描。
// Phase 1a 先留空，讓 Phase 1a 的報表只包含套件結果。
func (r *runner) scanLanguages(ctx context.Context, now time.Time) {
	_ = ctx
	_ = now
}

// fillSeverityFromNVD 是規劃 §3.2 第 3 層回退（alias CVE → NVD 補分數），Phase 1b 實作。
func (r *runner) fillSeverityFromNVD(ctx context.Context) {
	_ = ctx
}
