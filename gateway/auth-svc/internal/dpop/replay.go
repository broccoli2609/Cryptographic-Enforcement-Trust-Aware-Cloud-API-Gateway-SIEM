package dpop

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Lỗi của ReplayCache.
var (
	ErrReplay    = errors.New("dpop proof already used")
	ErrCacheFull = errors.New("dpop replay cache full")
)

// ReplayCache nhớ các proof đã dùng (RFC 9449 §11.1) cho tới khi chúng hết cửa sổ iat.
//
// Quyết định 2026-10-03: map trong bộ nhớ có TTL (chưa cần Redis — chỉ một auth-svc).
//   - Khoá = SHA-256(jkt ‖ 0x00 ‖ jti): 32 byte cố định dù jti dài bao nhiêu; gộp jkt để hai
//     client tình cờ trùng jti không chặn nhầm nhau.
//   - Đầy thì TỪ CHỐI request mới, KHÔNG xoá mục còn hạn: xoá mục còn hạn = mở lại cửa cho đúng
//     proof đó bị phát lại. Chỉ mục đã hết hạn mới được dọn (T10: trần bộ nhớ có giới hạn).
//
// Hạn chế (ghi vào báo cáo): restart auth-svc là mất cache → proof chưa hết 30 s có thể dùng lại
// một lần ngay sau restart; nhiều bản auth-svc cần cache dùng chung (Redis).
type ReplayCache struct {
	mu      sync.Mutex
	entries map[[32]byte]time.Time // khoá → thời điểm hết hạn
	max     int
	now     func() time.Time
}

// NewReplayCache tạo cache chứa tối đa max mục.
func NewReplayCache(max int) *ReplayCache {
	if max <= 0 {
		max = 100_000
	}
	return &ReplayCache{entries: make(map[[32]byte]time.Time), max: max, now: time.Now}
}

// Store ghi khoá nếu chưa thấy. Kiểm-và-ghi nằm trong cùng một khoá mutex, nên hai request
// song song mang cùng một proof thì đúng một request qua.
func (c *ReplayCache) Store(key [32]byte, expires time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if exp, seen := c.entries[key]; seen {
		if now.Before(exp) {
			return ErrReplay
		}
		c.entries[key] = expires // mục cũ đã hết hạn: ghi đè, không làm cache lớn thêm
		return nil
	}
	if len(c.entries) >= c.max {
		c.sweepLocked(now)
		if len(c.entries) >= c.max {
			return ErrCacheFull
		}
	}
	c.entries[key] = expires
	return nil
}

// Sweep xoá các mục đã hết hạn, trả số mục đã xoá.
func (c *ReplayCache) Sweep() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sweepLocked(c.now())
}

func (c *ReplayCache) sweepLocked(now time.Time) int {
	n := 0
	for k, exp := range c.entries {
		if !now.Before(exp) {
			delete(c.entries, k)
			n++
		}
	}
	return n
}

// Len là số mục đang giữ.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Run dọn định kỳ cho tới khi ctx bị huỷ, để lúc bình thường cache chỉ chứa proof của
// khoảng một cửa sổ iat gần nhất.
func (c *ReplayCache) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Sweep()
		}
	}
}
