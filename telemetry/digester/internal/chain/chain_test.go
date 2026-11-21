package chain

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Giá trị mong đợi tính bằng hashlib của Python (bản cài SHA-256 độc lập với Go, 21/11):
//
//	H0 = sha256("topic09/hash-chain/v1|" + epoch); e_i = sha256("event-i"); H_i = sha256(H_{i-1} + e_i)
const (
	kEpoch = "20261121T060000Z-0a1b2c3d"
	kH0    = "5aca0acd794b6b1b820170d96a0f193df4d3f7b8bfd8e75b6cad854e86341b48"
	kE1    = "ce36863f51b6baf9d16397ffb3e9af506b284a816f72d487e55943c1fd974d6d"
	kH1    = "89a2da63352eec1f86b7df3d5bc09adabb76b2ba92f36db25f6fac34496df6f8"
	kE2    = "b4e3d14e7519279e6a352f776d75a905a9de9a27efdb6d802fe4e700224ade2e"
	kH2    = "a3e9e8d9fd4536c0a1e6804248d09eb363181590d75874c7823b59d65b63ee4d"
	kE3    = "1441ba5507f9658d9bea29b0d9567e6900468e0153fa990194e0f0f94699694b"
	kH3    = "ff8f03065f3dfab79e38b0991f9e3e037b9459aa4f45d76489827e519c6ca40b"
)

func h32(t *testing.T, s string) [32]byte {
	t.Helper()
	var h [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("hex hỏng: %q", s)
	}
	copy(h[:], b)
	return h
}

func rec(seq int, eh string) string {
	return fmt.Sprintf(`{"chain_epoch":%q,"chain_seq":%d,"event_hash":%q}`+"\n", kEpoch, seq, eh)
}

// setup tạo thư mục chuỗi với nội dung cho trước, trả tracker có đồng hồ điều khiển được.
func setup(t *testing.T, content string) (*Tracker, string, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, kEpoch+".jsonl")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC)
	tr := NewTracker(dir)
	tr.Now = func() time.Time { return now }
	return tr, path, &now
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func onlyEpoch(t *testing.T, tr *Tracker) *Epoch {
	t.Helper()
	eps := tr.Epochs()
	if len(eps) != 1 {
		t.Fatalf("muốn 1 epoch, có %d", len(eps))
	}
	return eps[0]
}

func kinds(as []Anomaly) string {
	var s []string
	for _, a := range as {
		s = append(s, fmt.Sprintf("%s[%d-%d]", a.Kind, a.First, a.Last))
	}
	return strings.Join(s, ",")
}

func TestKnownAnswer(t *testing.T) {
	if got := hex.EncodeToString(func() []byte { h := Genesis(kEpoch); return h[:] }()); got != kH0 {
		t.Fatalf("H0 = %s, muốn %s", got, kH0)
	}
	h := Genesis(kEpoch)
	for i, c := range []struct{ e, want string }{{kE1, kH1}, {kE2, kH2}, {kE3, kH3}} {
		h = Next(h, h32(t, c.e))
		if got := hex.EncodeToString(h[:]); got != c.want {
			t.Fatalf("H%d = %s, muốn %s", i+1, got, c.want)
		}
	}
}

func TestGenesisDiffersPerEpoch(t *testing.T) {
	if Genesis(kEpoch) == Genesis("20261121T060000Z-0a1b2c3e") {
		t.Fatal("hai epoch khác nhau cho cùng H0 — thiếu tách miền")
	}
}

// Cùng một tập bản ghi, mọi thứ tự ghi vào file phải cho cùng đầu chuỗi.
func TestOrdering(t *testing.T) {
	cases := []struct {
		name  string
		order []int
	}{
		{"đúng thứ tự", []int{1, 2, 3}},
		{"đảo 2 và 3", []int{1, 3, 2}},
		{"ngược hoàn toàn", []int{3, 2, 1}},
	}
	hashes := map[int]string{1: kE1, 2: kE2, 3: kE3}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var b strings.Builder
			for _, s := range c.order {
				b.WriteString(rec(s, hashes[s]))
			}
			tr, _, _ := setup(t, b.String())
			as, err := tr.Poll()
			if err != nil || len(as) != 0 {
				t.Fatalf("Poll: err=%v anomalies=%s", err, kinds(as))
			}
			e := onlyEpoch(t, tr)
			if e.Last() != 3 || e.Head() != h32(t, kH3) || e.Pending() != 0 {
				t.Fatalf("Last=%d Pending=%d Head=%x, muốn 3/0/%s", e.Last(), e.Pending(), e.Head(), kH3)
			}
		})
	}
}

// Dòng chưa có '\n' (Vector đang ghi dở) chưa được đọc; ghi nốt thì đọc tiếp đúng chỗ.
func TestPartialLine(t *testing.T) {
	full := rec(2, kE2)
	tr, path, _ := setup(t, rec(1, kE1)+full[:20])
	if _, err := tr.Poll(); err != nil {
		t.Fatal(err)
	}
	e := onlyEpoch(t, tr)
	if e.Last() != 1 {
		t.Fatalf("Last = %d, muốn 1 (dòng 2 còn dở)", e.Last())
	}
	appendFile(t, path, full[20:])
	if as, err := tr.Poll(); err != nil || len(as) != 0 {
		t.Fatalf("err=%v anomalies=%s", err, kinds(as))
	}
	if e.Last() != 2 || e.Head() != h32(t, kH2) {
		t.Fatalf("Last=%d Head=%x, muốn 2/%s", e.Last(), e.Head(), kH2)
	}
}

// Mỗi kiểu dòng hỏng một ca: bị báo bad_record và KHÔNG làm đổi chuỗi.
func TestBadRecords(t *testing.T) {
	cases := []struct{ name, line string }{
		{"không phải JSON", "xin chao\n"},
		{"sai epoch", `{"chain_epoch":"20261121T060000Z-ffffffff","chain_seq":2,"event_hash":"` + kE2 + `"}` + "\n"},
		{"hash chữ hoa", rec(2, strings.ToUpper(kE2))},
		{"hash ngắn", rec(2, kE2[:62])},
		{"seq = 0", rec(0, kE2)},
		{"seq âm", `{"chain_epoch":"` + kEpoch + `","chain_seq":-2,"event_hash":"` + kE2 + `"}` + "\n"},
		{"trường lạ", `{"chain_epoch":"` + kEpoch + `","chain_seq":2,"event_hash":"` + kE2 + `","x":1}` + "\n"},
		{"dòng quá dài", rec(2, kE2+strings.Repeat("0", 2000))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr, _, _ := setup(t, rec(1, kE1)+c.line)
			as, err := tr.Poll()
			if err != nil {
				t.Fatal(err)
			}
			if len(as) != 1 || as[0].Kind != BadRecord {
				t.Fatalf("anomalies = %s, muốn đúng 1 bad_record", kinds(as))
			}
			e := onlyEpoch(t, tr)
			if e.Last() != 1 || e.Head() != h32(t, kH1) {
				t.Fatalf("dòng hỏng làm đổi chuỗi: Last=%d", e.Last())
			}
		})
	}
}

func TestDuplicateSeq(t *testing.T) {
	cases := []struct{ name, content string }{
		{"trùng seq đã nối", rec(1, kE1) + rec(2, kE2) + rec(2, kE3)},
		{"trùng seq đang chờ", rec(1, kE1) + rec(3, kE3) + rec(3, kE2)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr, _, _ := setup(t, c.content)
			as, _ := tr.Poll()
			if len(as) != 1 || as[0].Kind != DuplicateSeq {
				t.Fatalf("anomalies = %s, muốn 1 duplicate_seq", kinds(as))
			}
		})
	}
}

// Thiếu seq 2: chưa quá thời gian chờ thì chưa tuyên bố; quá thì bỏ qua seq 2, nối 3; seq 2 tới
// muộn → late_record, chuỗi không đổi.
func TestGap(t *testing.T) {
	tr, path, now := setup(t, rec(1, kE1)+rec(3, kE3))
	if _, err := tr.Poll(); err != nil {
		t.Fatal(err)
	}
	e := onlyEpoch(t, tr)
	if as := tr.CloseGaps(30 * time.Second); len(as) != 0 || e.Last() != 1 {
		t.Fatalf("tuyên bố thiếu quá sớm: %s", kinds(as))
	}
	*now = now.Add(31 * time.Second)
	as := tr.CloseGaps(30 * time.Second)
	if kinds(as) != "seq_gap[2-2]" {
		t.Fatalf("anomalies = %s, muốn seq_gap[2-2]", kinds(as))
	}
	want := Next(h32(t, kH1), h32(t, kE3)) // seq 2 không góp vào H
	if e.Last() != 3 || e.Head() != want {
		t.Fatalf("Last=%d, đầu chuỗi sai sau khoảng thiếu", e.Last())
	}
	if g := e.GapsIn(1, 3); len(g) != 1 || g[0] != (Range{2, 2}) {
		t.Fatalf("GapsIn = %v", g)
	}
	if g := e.GapsIn(3, 3); len(g) != 0 {
		t.Fatalf("GapsIn ngoài khoảng = %v", g)
	}
	appendFile(t, path, rec(2, kE2))
	as, _ = tr.Poll()
	if kinds(as) != "late_record[2-2]" || e.Head() != want {
		t.Fatalf("anomalies = %s, muốn late_record[2-2] và chuỗi không đổi", kinds(as))
	}
}

// Hai khoảng thiếu liên tiếp đã chờ đủ lâu được tuyên bố cùng một lần.
func TestTwoGapsAtOnce(t *testing.T) {
	tr, _, now := setup(t, rec(1, kE1)+rec(3, kE3)+rec(5, kE2))
	tr.Poll()
	*now = now.Add(time.Minute)
	if got := kinds(tr.CloseGaps(30 * time.Second)); got != "seq_gap[2-2],seq_gap[4-4]" {
		t.Fatalf("anomalies = %s", got)
	}
	if e := onlyEpoch(t, tr); e.Last() != 5 || e.Pending() != 0 {
		t.Fatalf("Last=%d Pending=%d", e.Last(), e.Pending())
	}
}

func TestTruncatedFile(t *testing.T) {
	tr, path, _ := setup(t, rec(1, kE1)+rec(2, kE2))
	tr.Poll()
	if err := os.WriteFile(path, []byte(rec(1, kE1)), 0o644); err != nil {
		t.Fatal(err)
	}
	as, _ := tr.Poll()
	if len(as) != 1 || as[0].Kind != FileTruncated {
		t.Fatalf("anomalies = %s, muốn file_truncated", kinds(as))
	}
	if as, _ := tr.Poll(); len(as) != 0 {
		t.Fatalf("báo file_truncated lặp lại: %s", kinds(as))
	}
}

// Đầu chuỗi đã ký trước đây (sổ digest) phải khớp khi tính lại từ file.
func TestExpectHead(t *testing.T) {
	cases := []struct {
		name string
		head string
		want string
	}{
		{"khớp", kH2, ""},
		{"file đã bị sửa sau khi ký", kH3, "head_mismatch[2-2]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr, _, _ := setup(t, rec(1, kE1)+rec(2, kE2))
			tr.Expect(kEpoch, 2, h32(t, c.head))
			as, _ := tr.Poll()
			if kinds(as) != c.want {
				t.Fatalf("anomalies = %q, muốn %q", kinds(as), c.want)
			}
		})
	}
}

func TestIgnoresForeignFiles(t *testing.T) {
	tr, _, _ := setup(t, rec(1, kE1))
	dir := tr.dir
	os.WriteFile(filepath.Join(dir, "notes.jsonl"), []byte("x\n"), 0o644)
	os.WriteFile(filepath.Join(dir, kEpoch+".txt"), []byte("x\n"), 0o644)
	if as, err := tr.Poll(); err != nil || len(as) != 0 || len(tr.Epochs()) != 1 {
		t.Fatalf("err=%v anomalies=%s epochs=%d", err, kinds(as), len(tr.Epochs()))
	}
}
