package store

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"topic09-lab/telemetry/digester/internal/digest"
)

func rec(seq uint64) digest.Record {
	return digest.Record{Payload: digest.Payload{DigestSeq: seq}}
}

func server(t *testing.T, codes map[string]int, seen *[]string) *OpenSearch {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Method+" "+r.URL.Path)
		code := codes[r.URL.Path]
		if code == 0 {
			code = http.StatusCreated
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	return &OpenSearch{URL: srv.URL, Index: "topic09-digests", Client: &http.Client{Timeout: time.Second}}
}

func TestFlushInOrderWithCreate(t *testing.T) {
	var seen []string
	s := server(t, nil, &seen)
	s.Enqueue(rec(1))
	s.Enqueue(rec(2))
	n, err := s.Flush(context.Background())
	if err != nil || n != 2 || s.Pending() != 0 {
		t.Fatalf("n=%d err=%v pending=%d", n, err, s.Pending())
	}
	if strings.Join(seen, ",") != "PUT /topic09-digests/_create/1,PUT /topic09-digests/_create/2" {
		t.Fatalf("request = %v (phải là _create, không ghi đè, đúng thứ tự)", seen)
	}
}

// Lỗi 5xx: dừng, giữ lại digest chưa gửi (kể cả cái lỗi) để thử lại, không nhảy cóc.
func TestFlushStopsOnError(t *testing.T) {
	var seen []string
	s := server(t, map[string]int{"/topic09-digests/_create/2": 503}, &seen)
	for i := uint64(1); i <= 3; i++ {
		s.Enqueue(rec(i))
	}
	n, err := s.Flush(context.Background())
	if err == nil || n != 1 || s.Pending() != 2 {
		t.Fatalf("n=%d err=%v pending=%d, muốn 1 / lỗi / 2", n, err, s.Pending())
	}
}

// 409 (id đã có) không được ghi đè; bỏ khỏi hàng đợi và báo ErrConflict.
func TestFlushConflict(t *testing.T) {
	var seen []string
	s := server(t, map[string]int{"/topic09-digests/_create/1": 409}, &seen)
	s.Enqueue(rec(1))
	if _, err := s.Flush(context.Background()); !errors.Is(err, ErrConflict) || s.Pending() != 0 {
		t.Fatalf("err=%v pending=%d", err, s.Pending())
	}
}

func TestQueueBounded(t *testing.T) {
	s := &OpenSearch{}
	for i := 0; i < maxQueue+5; i++ {
		s.Enqueue(rec(uint64(i + 1)))
	}
	if s.Pending() != maxQueue || s.Dropped != 5 || s.queue[0].DigestSeq != 6 {
		t.Fatalf("pending=%d dropped=%d first=%d", s.Pending(), s.Dropped, s.queue[0].DigestSeq)
	}
}
