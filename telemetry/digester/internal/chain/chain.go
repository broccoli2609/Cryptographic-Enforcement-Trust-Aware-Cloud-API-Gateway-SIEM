// Package chain đọc file chuỗi do Vector ghi (/chain/<epoch>.jsonl, mỗi dòng
// {"chain_epoch","chain_seq","event_hash"}) và nối hash chain của SIEM:
//
//	H_0 = SHA-256("topic09/hash-chain/v1|" ‖ epoch)          (khởi đầu, tách miền theo epoch)
//	H_i = SHA-256(H_{i-1} ‖ event_hash_i)                     (event_hash_i: 32 byte, giải hex)
//
// event_hash_i = SHA-256 của chính sự kiện (Vector tính, phủ cả chain_epoch/chain_seq), nên H_i
// phụ thuộc vào toàn bộ nội dung và thứ tự của sự kiện 1..i. Chỉ dùng crypto/sha256.
//
// Digester KHÔNG đọc OpenSearch (luật telemetry): file này nằm trong volume chỉ Vector ghi, ngoài
// mạng telemetry — người sửa được OpenSearch không sửa được nó.
package chain

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// GenesisPrefix — chuỗi tách miền của H_0. Đổi định dạng chuỗi thì tăng v1 → v2.
const GenesisPrefix = "topic09/hash-chain/v1|"

// maxLine — dòng dài hơn là dòng hỏng (bản ghi thật ~130 byte).
const maxLine = 1024

var (
	epochRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)
	hashRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidEpoch báo epoch có đúng dạng Vector sinh không.
func ValidEpoch(s string) bool { return epochRe.MatchString(s) }

// Genesis trả H_0 của một epoch.
func Genesis(epoch string) [32]byte { return sha256.Sum256([]byte(GenesisPrefix + epoch)) }

// Next trả H_i = SHA-256(H_{i-1} ‖ event_hash_i).
func Next(prev, eventHash [32]byte) [32]byte {
	var b [64]byte
	copy(b[:32], prev[:])
	copy(b[32:], eventHash[:])
	return sha256.Sum256(b[:])
}

// Range — khoảng seq [First, Last] (gồm cả hai đầu).
type Range struct{ First, Last uint64 }

func (r Range) String() string { return fmt.Sprintf("%d-%d", r.First, r.Last) }

// Các loại bất thường — trở thành decision_reason của sự kiện chain_anomaly (H9).
const (
	BadRecord     = "bad_record"     // dòng không phải JSON / sai dạng / sai epoch
	SeqGap        = "seq_gap"        // thiếu seq quá thời gian chờ → bỏ qua, ghi vào digest
	LateRecord    = "late_record"    // seq tới sau khi đã bị tuyên bố thiếu
	DuplicateSeq  = "duplicate_seq"  // seq đã nối rồi (hoặc đang chờ) lại xuất hiện
	FileTruncated = "file_truncated" // file chuỗi ngắn đi — bị sửa hoặc thay
	HeadMismatch  = "head_mismatch"  // đầu chuỗi tính lại ≠ đầu chuỗi đã ký trước đây
)

// Anomaly — một bất thường cần ghi log; digester không dừng vì nó.
type Anomaly struct {
	Kind  string
	Epoch string
	First uint64
	Last  uint64
}

// Epoch — trạng thái nối chuỗi của một epoch.
type Epoch struct {
	Name         string
	next         uint64              // seq kế tiếp cần để nối
	head         [32]byte            // H tại seq next-1
	pending      map[uint64][32]byte // seq tới sớm (sai thứ tự), chờ seq còn thiếu
	pendingSince time.Time
	gaps         []Range
	expect       map[uint64][32]byte // đầu chuỗi đã ký trước đây (từ sổ digest) — để đối chiếu
	offset       int64
	truncated    bool
}

func newEpoch(name string) *Epoch {
	return &Epoch{Name: name, next: 1, head: Genesis(name), pending: map[uint64][32]byte{}, expect: map[uint64][32]byte{}}
}

// Last — seq cuối cùng đã nối (0 = chưa có gì).
func (e *Epoch) Last() uint64 { return e.next - 1 }

// Head — đầu chuỗi H tại Last().
func (e *Epoch) Head() [32]byte { return e.head }

// Pending — số bản ghi đang chờ vì thiếu seq phía trước.
func (e *Epoch) Pending() int { return len(e.pending) }

// GapsIn — các khoảng seq bị tuyên bố thiếu nằm trong [first, last].
func (e *Epoch) GapsIn(first, last uint64) []Range {
	out := []Range{}
	for _, g := range e.gaps {
		if g.Last >= first && g.First <= last {
			out = append(out, Range{max(g.First, first), min(g.Last, last)})
		}
	}
	return out
}

func (e *Epoch) inGap(seq uint64) bool {
	for _, g := range e.gaps {
		if seq >= g.First && seq <= g.Last {
			return true
		}
	}
	return false
}

func (e *Epoch) absorb(seq uint64, h [32]byte) []Anomaly {
	e.head = Next(e.head, h)
	e.next = seq + 1
	if want, ok := e.expect[seq]; ok {
		delete(e.expect, seq)
		if want != e.head {
			return []Anomaly{{Kind: HeadMismatch, Epoch: e.Name, First: seq, Last: seq}}
		}
	}
	return nil
}

// add nhận một bản ghi; nối ngay nếu đúng seq kế tiếp, không thì để chờ.
func (e *Epoch) add(seq uint64, h [32]byte, now time.Time) []Anomaly {
	switch {
	case seq < e.next:
		kind := DuplicateSeq
		if e.inGap(seq) {
			kind = LateRecord
		}
		return []Anomaly{{Kind: kind, Epoch: e.Name, First: seq, Last: seq}}
	case seq > e.next:
		if _, dup := e.pending[seq]; dup {
			return []Anomaly{{Kind: DuplicateSeq, Epoch: e.Name, First: seq, Last: seq}}
		}
		if len(e.pending) == 0 {
			e.pendingSince = now
		}
		e.pending[seq] = h
		return nil
	}
	out := e.absorb(seq, h)
	out = append(out, e.drain()...)
	if len(e.pending) > 0 {
		e.pendingSince = now // phần còn chờ đang chờ một seq KHÁC — tính thời gian chờ lại từ đầu
	}
	return out
}

// drain nối tiếp các bản ghi đang chờ đã liền mạch.
func (e *Epoch) drain() []Anomaly {
	var out []Anomaly
	for {
		h, ok := e.pending[e.next]
		if !ok {
			break
		}
		delete(e.pending, e.next)
		out = append(out, e.absorb(e.next, h)...)
	}
	if len(e.pending) == 0 {
		e.pendingSince = time.Time{}
	}
	return out
}

// Tracker theo dõi mọi file chuỗi trong một thư mục.
type Tracker struct {
	dir    string
	epochs map[string]*Epoch
	Now    func() time.Time
}

// NewTracker tạo tracker cho thư mục chuỗi.
func NewTracker(dir string) *Tracker {
	return &Tracker{dir: dir, epochs: map[string]*Epoch{}, Now: time.Now}
}

func (t *Tracker) epoch(name string) *Epoch {
	e, ok := t.epochs[name]
	if !ok {
		e = newEpoch(name)
		t.epochs[name] = e
	}
	return e
}

// Expect ghi nhận đầu chuỗi đã ký trước đây tại (epoch, seq). Khi đọc lại file và nối tới seq đó,
// đầu chuỗi tính lại phải bằng giá trị này — khác là file chuỗi đã bị sửa sau khi ký (HeadMismatch).
func (t *Tracker) Expect(epoch string, seq uint64, head [32]byte) {
	if seq == 0 {
		return
	}
	t.epoch(epoch).expect[seq] = head
}

// Epochs trả các epoch theo thứ tự tên (tên bắt đầu bằng thời điểm khởi động của Vector).
func (t *Tracker) Epochs() []*Epoch {
	out := make([]*Epoch, 0, len(t.epochs))
	for _, e := range t.epochs {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Poll đọc phần mới của mọi file <epoch>.jsonl và nối được bao nhiêu thì nối.
func (t *Tracker) Poll() ([]Anomaly, error) {
	files, err := filepath.Glob(filepath.Join(t.dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []Anomaly
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".jsonl")
		if !ValidEpoch(name) {
			continue // không phải file chuỗi của Vector
		}
		a, err := t.readFile(t.epoch(name), f)
		out = append(out, a...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func (t *Tracker) readFile(e *Epoch, path string) ([]Anomaly, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() < e.offset {
		if e.truncated {
			return nil, nil
		}
		e.truncated = true
		return []Anomaly{{Kind: FileTruncated, Epoch: e.Name, First: e.next, Last: e.next}}, nil
	}
	if st.Size() == e.offset {
		return nil, nil
	}
	if _, err := f.Seek(e.offset, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, st.Size()-e.offset))
	if err != nil {
		return nil, err
	}
	// Chỉ xử lý tới ký tự xuống dòng cuối cùng: phần sau đó có thể là dòng Vector đang ghi dở.
	end := bytes.LastIndexByte(data, '\n')
	if end < 0 {
		if len(data) > maxLine {
			e.offset += int64(len(data))
			return []Anomaly{{Kind: BadRecord, Epoch: e.Name}}, nil
		}
		return nil, nil
	}
	e.offset += int64(end + 1)
	var out []Anomaly
	now := t.Now()
	sc := bufio.NewScanner(bytes.NewReader(data[:end+1]))
	sc.Buffer(make([]byte, 0, 4096), len(data)+1)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		seq, h, err := ParseRecord(line, e.Name)
		if err != nil {
			out = append(out, Anomaly{Kind: BadRecord, Epoch: e.Name, First: seq, Last: seq})
			continue
		}
		out = append(out, e.add(seq, h, now)...)
	}
	return out, sc.Err()
}

// ParseRecord kiểm một dòng của file chuỗi. Trả seq (nếu đọc được) kể cả khi lỗi, để log.
func ParseRecord(line []byte, epoch string) (uint64, [32]byte, error) {
	var h [32]byte
	if len(line) > maxLine {
		return 0, h, errors.New("dòng quá dài")
	}
	var r struct {
		Epoch     string `json:"chain_epoch"`
		Seq       uint64 `json:"chain_seq"`
		EventHash string `json:"event_hash"`
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return 0, h, fmt.Errorf("không phải bản ghi chuỗi: %w", err)
	}
	if r.Epoch != epoch {
		return r.Seq, h, errors.New("epoch trong dòng khác tên file")
	}
	if r.Seq == 0 {
		return 0, h, errors.New("chain_seq phải ≥ 1")
	}
	if !hashRe.MatchString(r.EventHash) {
		return r.Seq, h, errors.New("event_hash không phải 64 ký tự hex thường")
	}
	b, _ := hex.DecodeString(r.EventHash)
	copy(h[:], b)
	return r.Seq, h, nil
}

// CloseGaps: epoch nào có bản ghi chờ lâu hơn grace (seq phía trước không bao giờ tới) thì tuyên
// bố khoảng thiếu, bỏ qua nó và nối tiếp từ seq nhỏ nhất đang chờ. Đầu chuỗi đi thẳng qua khoảng
// thiếu (seq thiếu không góp gì vào H); digest ghi lại khoảng thiếu để người kiểm làm giống hệt.
func (t *Tracker) CloseGaps(grace time.Duration) []Anomaly {
	var out []Anomaly
	now := t.Now()
	for _, e := range t.Epochs() {
		for len(e.pending) > 0 && !e.pendingSince.IsZero() && now.Sub(e.pendingSince) >= grace {
			lo := uint64(0)
			for s := range e.pending {
				if lo == 0 || s < lo {
					lo = s
				}
			}
			g := Range{First: e.next, Last: lo - 1}
			e.gaps = append(e.gaps, g)
			out = append(out, Anomaly{Kind: SeqGap, Epoch: e.Name, First: g.First, Last: g.Last})
			e.next = lo
			// drain giữ nguyên pendingSince nếu còn bản ghi chờ: chúng đã chờ từ trước, nên khoảng
			// thiếu kế tiếp (nếu có) cũng được tuyên bố ngay trong vòng lặp này.
			out = append(out, e.drain()...)
		}
	}
	return out
}
