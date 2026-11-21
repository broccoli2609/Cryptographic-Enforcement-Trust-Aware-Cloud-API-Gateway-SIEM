// Package store ghi digest vào OpenSearch (index topic09-digests, mapping strict do
// opensearch-init nạp). Chỉ GHI, không đọc: digester không lấy gì từ OpenSearch (luật telemetry).
//
// PUT /<index>/_create/<digest_seq>: "_create" không ghi đè — 409 nếu id đã có. Ghi lỗi thì digest
// nằm trong hàng đợi và thử lại ở lần sau; sổ cục bộ (/state/digests.jsonl) luôn có bản đầy đủ.
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"topic09-lab/telemetry/digester/internal/digest"
)

// ErrConflict — id đã có trong index (digest_seq trùng: sổ cục bộ bị xoá rồi đánh số lại).
var ErrConflict = errors.New("digest_store_conflict")

// maxQueue — giữ tối đa chừng này digest chưa gửi được (5 phút/digest → ~3,5 ngày).
const maxQueue = 1000

// OpenSearch — client ghi digest.
type OpenSearch struct {
	URL    string // http://opensearch:9200
	Index  string // topic09-digests
	Client *http.Client
	queue  []digest.Record
	// Dropped — số digest bị bỏ khỏi hàng đợi vì đầy (vẫn còn trong sổ cục bộ).
	Dropped int
}

// Enqueue thêm digest vào hàng đợi gửi.
func (s *OpenSearch) Enqueue(r digest.Record) {
	if len(s.queue) >= maxQueue {
		s.queue = s.queue[1:]
		s.Dropped++
	}
	s.queue = append(s.queue, r)
}

// Pending — số digest chưa gửi được.
func (s *OpenSearch) Pending() int { return len(s.queue) }

// Flush gửi lần lượt theo thứ tự; dừng ở lỗi đầu tiên (giữ thứ tự). 409 = đã có → bỏ khỏi hàng
// đợi nhưng báo lỗi để digester ghi log.
func (s *OpenSearch) Flush(ctx context.Context) (sent int, err error) {
	for len(s.queue) > 0 {
		e := s.put(ctx, s.queue[0])
		if e != nil && !errors.Is(e, ErrConflict) {
			return sent, e
		}
		s.queue = s.queue[1:]
		if e != nil {
			return sent, e
		}
		sent++
	}
	return sent, nil
}

func (s *OpenSearch) put(ctx context.Context, r digest.Record) error {
	body, _ := json.Marshal(r)
	url := fmt.Sprintf("%s/%s/_create/%d", strings.TrimRight(s.URL, "/"), s.Index, r.DigestSeq)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return errors.New("opensearch_unavailable")
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return nil
	case http.StatusConflict:
		return ErrConflict
	default:
		return fmt.Errorf("opensearch_http_%d", resp.StatusCode)
	}
}
