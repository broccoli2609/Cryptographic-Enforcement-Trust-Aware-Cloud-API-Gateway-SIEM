package digest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"topic09-lab/telemetry/digester/internal/chain"
)

const ep = "20261121T060000Z-0a1b2c3d"

var t0 = time.Date(2026, 11, 21, 6, 5, 0, 123, time.UTC)

// sign giả lập Vault: ký đúng byte của payload, trả bản ghi đầy đủ.
func sign(priv ed25519.PrivateKey, p Payload) Record {
	b := p.Bytes()
	return Record{
		Payload:       p,
		Signature:     "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b)),
		KeyVersion:    1,
		PublicKey:     base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		SignedPayload: base64.StdEncoding.EncodeToString(b),
	}
}

// chainOf dựng n digest nối nhau của cùng một epoch.
func chainOf(t *testing.T, priv ed25519.PrivateKey, n int) []Record {
	t.Helper()
	var out []Record
	prevSig := ""
	prevHead := chain.Genesis(ep)
	for i := 1; i <= n; i++ {
		head := chain.Next(prevHead, [32]byte{byte(i)})
		p := New(uint64(i), prevSig, "siem-digest", ep, uint64(10*(i-1)+1), uint64(10*i), prevHead, head, nil, t0)
		r := sign(priv, p)
		out = append(out, r)
		prevSig, prevHead = r.Signature, head
	}
	return out
}

func TestPayloadBytesStable(t *testing.T) {
	p := New(3, "vault:v1:AAAA", "siem-digest", ep, 11, 20, [32]byte{1}, [32]byte{2}, []chain.Range{{First: 14, Last: 15}}, t0)
	want := `{"v":1,"digest_seq":3,"created_at":"2026-11-21T06:05:00.000000123Z","key":"siem-digest",` +
		`"chain_epoch":"` + ep + `","first_seq":11,"last_seq":20,` +
		`"prev_head":"0100000000000000000000000000000000000000000000000000000000000000",` +
		`"head":"0200000000000000000000000000000000000000000000000000000000000000",` +
		`"gaps":["14-15"],"prev_signature":"vault:v1:AAAA"}`
	if got := string(p.Bytes()); got != want {
		t.Fatalf("payload:\n got %s\nwant %s", got, want)
	}
	p.Gaps = nil
	if !strings.Contains(string(p.Bytes()), `"gaps":[]`) {
		t.Fatal(`gaps rỗng phải là [] (một dạng duy nhất)`)
	}
}

func TestVerify(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	good := chainOf(t, priv, 1)[0]
	cases := []struct {
		name string
		mut  func(*Record)
		ok   bool
	}{
		{"nguyên vẹn", func(*Record) {}, true},
		{"sửa head (trường) nhưng giữ signed_payload", func(r *Record) { r.Head = strings.Repeat("0", 64) }, false},
		{"sửa last_seq", func(r *Record) { r.LastSeq++ }, false},
		{"sửa signed_payload cho khớp trường mới nhưng giữ chữ ký", func(r *Record) {
			r.LastSeq++
			r.SignedPayload = base64.StdEncoding.EncodeToString(r.Payload.Bytes())
		}, false},
		{"thay public key bằng khoá khác", func(r *Record) {
			r.PublicKey = base64.StdEncoding.EncodeToString(other.Public().(ed25519.PublicKey))
		}, false},
		{"key_version lệch tiền tố chữ ký", func(r *Record) { r.KeyVersion = 2 }, false},
		{"chữ ký không có tiền tố vault:", func(r *Record) { r.Signature = strings.TrimPrefix(r.Signature, "vault:") }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := good
			c.mut(&r)
			if err := Verify(r); (err == nil) != c.ok {
				t.Fatalf("Verify = %v, muốn ok=%v", err, c.ok)
			}
		})
	}
}

func TestLedgerAppendAndReopen(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "digests.jsonl")
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if seq, prev := l.Next(); seq != 1 || prev != "" {
		t.Fatalf("sổ rỗng: Next = %d %q", seq, prev)
	}
	if c := l.Checkpoint(ep); c.LastSeq != 0 || c.Head != chain.Genesis(ep) {
		t.Fatal("epoch chưa ký phải bắt đầu từ (0, H_0)")
	}
	recs := chainOf(t, priv, 3)
	for _, r := range recs {
		if err := l.Append(r); err != nil {
			t.Fatalf("Append %d: %v", r.DigestSeq, err)
		}
	}
	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("mở lại: %v", err)
	}
	if seq, prev := l2.Next(); seq != 4 || prev != recs[2].Signature {
		t.Fatalf("Next sau khi mở lại = %d", seq)
	}
	if c := l2.Checkpoint(ep); c.LastSeq != 30 {
		t.Fatalf("Checkpoint.LastSeq = %d, muốn 30", c.LastSeq)
	}
}

// Append từ chối digest không nối đúng mắt xích (seq nhảy, prev_signature sai, chữ ký hỏng).
func TestLedgerRejectsBrokenLink(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	recs := chainOf(t, priv, 3)
	cases := []struct {
		name string
		r    Record
	}{
		{"nhảy digest_seq (bỏ qua #2)", recs[2]},
		{"prev_signature sai", func() Record {
			p := recs[1].Payload
			p.PrevSignature = "vault:v1:AAAA"
			return sign(priv, p)
		}()},
		{"chữ ký hỏng", func() Record { r := recs[1]; r.Signature = recs[0].Signature; return r }()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, _ := OpenLedger(filepath.Join(t.TempDir(), "d.jsonl"))
			if err := l.Append(recs[0]); err != nil {
				t.Fatal(err)
			}
			if err := l.Append(c.r); err == nil {
				t.Fatal("Append nhận digest đứt mắt xích")
			}
		})
	}
}

// Sổ bị sửa trên đĩa (xoá một dòng giữa, sửa một trường) → mở sổ báo lỗi.
func TestLedgerTamperedOnDisk(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	recs := chainOf(t, priv, 3)
	lines := make([]string, len(recs))
	for i, r := range recs {
		b, _ := json.Marshal(r)
		lines[i] = string(b)
	}
	cases := []struct {
		name    string
		content string
	}{
		{"xoá digest giữa", lines[0] + "\n" + lines[2] + "\n"},
		{"sửa head của digest #2", lines[0] + "\n" + strings.Replace(lines[1], recs[1].Head, strings.Repeat("f", 64), 1) + "\n" + lines[2] + "\n"},
		{"dòng rác", lines[0] + "\nxyz\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "d.jsonl")
			os.WriteFile(path, []byte(c.content), 0o640)
			if _, err := OpenLedger(path); err == nil {
				t.Fatal("mở được sổ đã bị sửa")
			}
		})
	}
}
