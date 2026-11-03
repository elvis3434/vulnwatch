package httpx

import (
	"context"
	"sync"
	"time"
)

// hostLimiter 實作 per-host 的併發上限與最小請求間隔（規劃 §6）。
type hostLimiter struct {
	sem chan struct{}

	mu       sync.Mutex
	interval time.Duration
	last     time.Time
}

func newHostLimiter(limit HostLimit) *hostLimiter {
	return &hostLimiter{
		sem:      make(chan struct{}, limit.Concurrency),
		interval: limit.MinInterval,
	}
}

// acquire 取得一個併發額度，並在必要時等到距離上次請求已達最小間隔。
func (l *hostLimiter) acquire(ctx context.Context, sleep func(time.Duration), now func() time.Time) error {
	select {
	case l.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}

	if l.interval <= 0 {
		return nil
	}

	l.mu.Lock()
	wait := time.Duration(0)
	t := now()
	if !l.last.IsZero() {
		elapsed := t.Sub(l.last)
		if elapsed < l.interval {
			wait = l.interval - elapsed
		}
	}
	// 先把 last 推到「這次請求預計發出的時間」，讓同時等待的呼叫端自然排隊。
	l.last = t.Add(wait)
	l.mu.Unlock()

	if wait > 0 {
		sleep(wait)
	}
	return nil
}

func (l *hostLimiter) release() {
	select {
	case <-l.sem:
	default:
	}
}
