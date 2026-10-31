package dpop

import (
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func key(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func newCache(max int, now *time.Time) *ReplayCache {
	c := NewReplayCache(max)
	c.now = func() time.Time { return *now }
	return c
}

func TestReplayCacheDetectsReuse(t *testing.T) {
	now := t0
	c := newCache(10, &now)
	if err := c.Store(key("a"), now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := c.Store(key("a"), now.Add(30*time.Second)); err != ErrReplay {
		t.Fatalf("lần hai phải ErrReplay, nhận %v", err)
	}
}

func TestReplayCacheForgetsExpiredEntries(t *testing.T) {
	now := t0
	c := newCache(10, &now)
	_ = c.Store(key("a"), now.Add(30*time.Second))
	now = now.Add(31 * time.Second)
	if err := c.Store(key("a"), now.Add(30*time.Second)); err != nil {
		t.Fatalf("mục đã hết hạn thì ghi lại được: %v", err)
	}
	if n := c.Sweep(); n != 0 || c.Len() != 1 {
		t.Fatalf("sweep xoá %d, còn %d", n, c.Len())
	}
}

// Đầy mà mọi mục còn hạn → TỪ CHỐI, và các mục cũ vẫn còn (vẫn bắt được replay).
func TestReplayCacheFullRejectsAndKeepsUnexpired(t *testing.T) {
	now := t0
	c := newCache(2, &now)
	_ = c.Store(key("a"), now.Add(30*time.Second))
	_ = c.Store(key("b"), now.Add(30*time.Second))
	if err := c.Store(key("c"), now.Add(30*time.Second)); err != ErrCacheFull {
		t.Fatalf("cache đầy phải ErrCacheFull, nhận %v", err)
	}
	if err := c.Store(key("a"), now.Add(30*time.Second)); err != ErrReplay {
		t.Fatalf("mục còn hạn đã bị xoá khi đầy (mở cửa cho replay): %v", err)
	}
}

func TestReplayCacheFullSweepsExpiredFirst(t *testing.T) {
	now := t0
	c := newCache(2, &now)
	_ = c.Store(key("a"), now.Add(5*time.Second))
	_ = c.Store(key("b"), now.Add(60*time.Second))
	now = now.Add(10 * time.Second) // "a" hết hạn
	if err := c.Store(key("c"), now.Add(30*time.Second)); err != nil {
		t.Fatalf("có mục hết hạn để dọn thì phải ghi được: %v", err)
	}
	if err := c.Store(key("b"), now.Add(30*time.Second)); err != ErrReplay {
		t.Fatal("mục b còn hạn phải vẫn còn")
	}
}

// Nhiều request song song mang cùng một proof: đúng MỘT request qua.
func TestReplayCacheConcurrentSameKey(t *testing.T) {
	now := t0
	c := newCache(100, &now)
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.Store(key("same"), now.Add(30*time.Second)) == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d request qua, muốn đúng 1", ok.Load())
	}
}
