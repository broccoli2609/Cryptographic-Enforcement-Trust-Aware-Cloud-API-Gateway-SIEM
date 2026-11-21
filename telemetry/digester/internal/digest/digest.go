// Package digest — định dạng digest SIEM và sổ digest cục bộ của digester.
//
// Một digest cam kết "tới thời điểm created_at, epoch E của hash chain có các sự kiện
// first_seq..last_seq (trừ gaps), đầu chuỗi là head". Các digest nối nhau bằng digest_seq liên
// tục và prev_signature = chữ ký của digest trước (decision 2026-10-03) — xoá hay sửa một digest
// làm đứt mắt xích. Chữ ký Ed25519 do Vault Transit (khoá siem-digest, không export) tạo.
//
// Byte được ký = json.Marshal(Payload): thứ tự trường cố định theo struct, không khoảng trắng.
// Bản ghi lưu kèm signed_payload (base64 của đúng các byte đó), public key và version khoá —
// Vault dev mất khoá khi restart nên người kiểm phải có public key đi kèm (luật telemetry).
package digest

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"topic09-lab/telemetry/digester/internal/chain"
)

// Version của định dạng payload.
const Version = 1

// Payload — phần được ký.
type Payload struct {
	V             int      `json:"v"`
	DigestSeq     uint64   `json:"digest_seq"`
	CreatedAt     string   `json:"created_at"`
	Key           string   `json:"key"`
	ChainEpoch    string   `json:"chain_epoch"`
	FirstSeq      uint64   `json:"first_seq"`
	LastSeq       uint64   `json:"last_seq"`
	PrevHead      string   `json:"prev_head"`
	Head          string   `json:"head"`
	Gaps          []string `json:"gaps"`
	PrevSignature string   `json:"prev_signature"`
}

// Bytes — đúng chuỗi byte đem ký.
func (p Payload) Bytes() []byte {
	if p.Gaps == nil {
		p.Gaps = []string{} // "gaps":[] chứ không phải null — một dạng duy nhất
	}
	b, _ := json.Marshal(p) // struct chỉ có chuỗi/số: không thể lỗi
	return b
}

// Record — một digest đã ký, như lưu trong sổ và trong OpenSearch (index topic09-digests).
type Record struct {
	Payload
	Signature     string `json:"signature"`
	KeyVersion    int    `json:"key_version"`
	PublicKey     string `json:"public_key"`
	SignedPayload string `json:"signed_payload"`
}

// New dựng payload cho khoảng (first..last] của một epoch.
func New(seq uint64, prevSig, key, epoch string, first, last uint64, prevHead, head [32]byte, gaps []chain.Range, now time.Time) Payload {
	g := make([]string, 0, len(gaps))
	for _, r := range gaps {
		g = append(g, r.String())
	}
	return Payload{
		V: Version, DigestSeq: seq, CreatedAt: now.UTC().Format(time.RFC3339Nano), Key: key,
		ChainEpoch: epoch, FirstSeq: first, LastSeq: last,
		PrevHead: hex.EncodeToString(prevHead[:]), Head: hex.EncodeToString(head[:]),
		Gaps: g, PrevSignature: prevSig,
	}
}

// Verify kiểm một bản ghi tự nhất quán: signed_payload đúng bằng payload, chữ ký Ed25519 hợp lệ
// với public key đi kèm. (Người kiểm từ bên ngoài còn phải đối chiếu public key với Vault /
// danh sách đã ghim — public key đi kèm tự nó không chứng minh được nguồn gốc.)
func Verify(r Record) error {
	signed, err := base64.StdEncoding.DecodeString(r.SignedPayload)
	if err != nil || string(signed) != string(r.Payload.Bytes()) {
		return errors.New("signed_payload không khớp các trường của digest")
	}
	parts := strings.SplitN(r.Signature, ":", 3) // vault : vN : <base64>
	if len(parts) != 3 || parts[0] != "vault" || parts[1] != "v"+strconv.Itoa(r.KeyVersion) || r.KeyVersion < 1 {
		return errors.New("chữ ký sai dạng vault:vN:… hoặc lệch key_version")
	}
	sig, err1 := base64.StdEncoding.DecodeString(parts[2])
	pub, err2 := base64.StdEncoding.DecodeString(r.PublicKey)
	if err1 != nil || err2 != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, signed, sig) {
		return errors.New("chữ ký không hợp lệ")
	}
	return nil
}

// Checkpoint — điểm đã ký gần nhất của một epoch.
type Checkpoint struct {
	LastSeq uint64
	Head    [32]byte
}

// Ledger — sổ digest cục bộ (/state/digests.jsonl): chỉ ghi thêm, fsync sau mỗi digest. Là
// nguồn sự thật của digester khi khởi động lại (digest_seq, prev_signature, điểm đã ký của từng
// epoch) — digester không đọc lại digest từ OpenSearch. Cũng là bản thứ hai để so với OpenSearch.
type Ledger struct {
	path   string
	last   *Record
	epochs map[string]Checkpoint
}

// OpenLedger đọc sổ; sổ đứt mắt xích hay chữ ký sai → lỗi (digester dừng: không nối tiếp lên
// một sổ không tin được).
func OpenLedger(path string) (*Ledger, error) {
	l := &Ledger{path: path, epochs: map[string]Checkpoint{}}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 8192), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("sổ digest dòng %d: không phải JSON", n)
		}
		if err := l.check(r); err != nil {
			return nil, fmt.Errorf("sổ digest dòng %d: %w", n, err)
		}
		l.remember(r)
	}
	return l, sc.Err()
}

func (l *Ledger) check(r Record) error {
	wantSeq, wantPrev := l.Next()
	if r.DigestSeq != wantSeq || r.PrevSignature != wantPrev {
		return fmt.Errorf("đứt mắt xích (digest_seq %d, muốn %d)", r.DigestSeq, wantSeq)
	}
	return Verify(r)
}

func (l *Ledger) remember(r Record) {
	rc := r
	l.last = &rc
	var h [32]byte
	b, _ := hex.DecodeString(r.Head)
	copy(h[:], b)
	l.epochs[r.ChainEpoch] = Checkpoint{LastSeq: r.LastSeq, Head: h}
}

// Next trả digest_seq và prev_signature cho digest kế tiếp.
func (l *Ledger) Next() (uint64, string) {
	if l.last == nil {
		return 1, ""
	}
	return l.last.DigestSeq + 1, l.last.Signature
}

// Checkpoint trả điểm đã ký của epoch; chưa có thì (0, H_0).
func (l *Ledger) Checkpoint(epoch string) Checkpoint {
	if c, ok := l.epochs[epoch]; ok {
		return c
	}
	return Checkpoint{LastSeq: 0, Head: chain.Genesis(epoch)}
}

// Epochs trả mọi epoch đã có digest (để digester đối chiếu đầu chuỗi khi đọc lại file).
func (l *Ledger) Epochs() map[string]Checkpoint { return l.epochs }

// Append ghi một digest vào cuối sổ và fsync.
func (l *Ledger) Append(r Record) error {
	if err := l.check(r); err != nil {
		return err
	}
	b, _ := json.Marshal(r)
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	l.remember(r)
	return nil
}
