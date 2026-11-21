package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testToken = "t09-test-token-not-a-secret"

// fakeVault giả lập transit/sign: ký bằng khoá thật (sinh lúc test) rồi trả theo kiểu hành vi.
type fakeVault struct {
	priv   ed25519.PrivateKey
	mode   string // ok | 403 | 500 | garbage | badsig | wrongkey | ver2 | slow
	gotTok string
	gotIn  []byte
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.gotTok = r.Header.Get("X-Vault-Token")
	var body struct{ Input string }
	b, _ := io.ReadAll(r.Body)
	json.Unmarshal(b, &body)
	f.gotIn, _ = base64.StdEncoding.DecodeString(body.Input)
	sig := ed25519.Sign(f.priv, f.gotIn)
	ver := 1
	switch f.mode {
	case "403":
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors":["permission denied"]}`))
		return
	case "500":
		w.WriteHeader(http.StatusInternalServerError)
		return
	case "garbage":
		w.Write([]byte(`{"data":{"signature":"không phải chữ ký"}}`))
		return
	case "badsig":
		sig[0] ^= 0xff
	case "wrongkey":
		_, other, _ := ed25519.GenerateKey(rand.Reader)
		sig = ed25519.Sign(other, f.gotIn)
	case "ver2":
		ver = 2
	case "slow":
		time.Sleep(300 * time.Millisecond)
	}
	fmt.Fprintf(w, `{"data":{"signature":"vault:v%d:%s","key_version":%d}}`, ver, base64.StdEncoding.EncodeToString(sig), ver)
}

func newSigner(t *testing.T, mode string) (*Signer, *fakeVault) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fv := &fakeVault{priv: priv, mode: mode}
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	os.WriteFile(tok, []byte(testToken+"\n"), 0o600)
	pk := filepath.Join(dir, "pub.json")
	js := fmt.Sprintf(`{"data":{"type":"ed25519","latest_version":1,"keys":{"1":{"public_key":%q}}}}`, base64.StdEncoding.EncodeToString(pub))
	os.WriteFile(pk, []byte(js), 0o644)
	return &Signer{Addr: srv.URL, Key: "siem-digest", TokenFile: tok, PubKeyFile: pk, Client: NewClient(200 * time.Millisecond)}, fv
}

func TestSignOK(t *testing.T) {
	s, fv := newSigner(t, "ok")
	msg := []byte(`{"v":1,"digest_seq":1}`)
	sig, err := s.Sign(context.Background(), msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if fv.gotTok != testToken {
		t.Fatalf("token gửi đi = %q (phải bỏ khoảng trắng cuối file)", fv.gotTok)
	}
	if string(fv.gotIn) != string(msg) {
		t.Fatal("Vault không nhận đúng thông điệp")
	}
	if sig.KeyVersion != 1 || len(sig.PublicKey) == 0 {
		t.Fatalf("sig = %+v", sig)
	}
}

// Mọi ca lỗi đều trả lỗi đúng loại — không ca nào trả "chữ ký" (fail-closed, SR-11).
func TestSignFailures(t *testing.T) {
	cases := []struct {
		name, mode string
		want       error
	}{
		{"Vault từ chối (403)", "403", ErrDenied},
		{"Vault lỗi (500)", "500", ErrUnavailable},
		{"phản hồi sai dạng", "garbage", ErrBadResponse},
		{"chữ ký bị sửa 1 byte", "badsig", ErrPubKeyMismatch},
		{"ký bằng khoá khác khoá đã công bố", "wrongkey", ErrPubKeyMismatch},
		{"version khoá chưa có trong file public key", "ver2", ErrPubKeyMismatch},
		{"Vault chậm quá timeout", "slow", ErrUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newSigner(t, c.mode)
			sig, err := s.Sign(context.Background(), []byte("m"))
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, muốn %v", err, c.want)
			}
			if sig.Value != "" {
				t.Fatal("lỗi mà vẫn trả chữ ký")
			}
		})
	}
}

func TestSignMissingFiles(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Signer)
		want error
	}{
		{"không có file token", func(s *Signer) { s.TokenFile = "/không/có" }, ErrNoToken},
		{"không có file public key", func(s *Signer) { s.PubKeyFile = "/không/có" }, ErrNoPubKey},
		{"Vault không chạy", func(s *Signer) { s.Addr = "http://127.0.0.1:1" }, ErrUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newSigner(t, "ok")
			c.mut(s)
			if _, err := s.Sign(context.Background(), []byte("m")); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, muốn %v", err, c.want)
			}
		})
	}
}

func TestEmptyTokenFile(t *testing.T) {
	s, _ := newSigner(t, "ok")
	os.WriteFile(s.TokenFile, []byte("  \n"), 0o600)
	if _, err := s.Sign(context.Background(), []byte("m")); !errors.Is(err, ErrNoToken) {
		t.Fatalf("err = %v, muốn ErrNoToken", err)
	}
}

// Không theo redirect: Vault (hay kẻ đứng giữa) trả 307 sang nơi khác → không đi theo, không gửi token.
func TestNoRedirect(t *testing.T) {
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer other.Close()
	red := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer red.Close()
	s, _ := newSigner(t, "ok")
	s.Addr = red.URL
	if _, err := s.Sign(context.Background(), []byte("m")); !errors.Is(err, ErrUnavailable) || hit {
		t.Fatalf("err=%v, đã theo redirect=%v", err, hit)
	}
}
