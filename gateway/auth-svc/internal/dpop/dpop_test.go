package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Mỗi luật của RFC 9449 §4.3 có ít nhất một ca sai riêng, tên test nói rõ ca đó (luật go.md).

const (
	testURL   = "https://localhost:8445/orders/whoami"
	testToken = "header.payload.signature-of-access-token"
)

var t0 = time.Unix(1_793_000_000, 0)

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signer gói một khoá riêng + JWK công khai tương ứng.
type signer struct {
	alg  string
	jwk  map[string]any
	sign func(input string) []byte
}

func ecSigner(t *testing.T) signer {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pt, _ := k.PublicKey.Bytes() // 04 ‖ X ‖ Y
	return signer{
		alg: "ES256",
		jwk: map[string]any{"kty": "EC", "crv": "P-256", "x": enc(pt[1:33]), "y": enc(pt[33:])},
		sign: func(in string) []byte {
			d := sha256.Sum256([]byte(in))
			r, s, _ := ecdsa.Sign(rand.Reader, k, d[:])
			out := make([]byte, 64)
			r.FillBytes(out[:32])
			s.FillBytes(out[32:])
			return out
		},
	}
}

func edSigner(t *testing.T) signer {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return signer{alg: "EdDSA", jwk: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": enc(pub)},
		sign: func(in string) []byte { return ed25519.Sign(priv, []byte(in)) }}
}

func rsaSigner(t *testing.T, bits int) signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return signer{alg: "RS256", jwk: map[string]any{"kty": "RSA", "n": enc(k.N.Bytes()), "e": enc([]byte{1, 0, 1})},
		sign: func(in string) []byte {
			d := sha256.Sum256([]byte(in))
			s, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
			return s
		}}
}

func (s signer) jkt(t *testing.T) string {
	t.Helper()
	raw, _ := json.Marshal(s.jwk)
	jkt, err := Thumbprint(raw, s.alg)
	if err != nil {
		t.Fatal(err)
	}
	return jkt
}

func ath(tok string) string { sum := sha256.Sum256([]byte(tok)); return enc(sum[:]) }

// proof dựng một proof hợp lệ; edit sửa header/claims trước khi ký để tạo ca sai.
func proof(s signer, edit func(h, c map[string]any)) string {
	h := map[string]any{"typ": "dpop+jwt", "alg": s.alg, "jwk": s.jwk}
	c := map[string]any{"jti": enc([]byte(time.Now().String() + randStr())), "htm": "GET", "htu": testURL,
		"iat": t0.Unix(), "ath": ath(testToken)}
	if edit != nil {
		edit(h, c)
	}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(c)
	in := enc(hb) + "." + enc(cb)
	return in + "." + enc(s.sign(in))
}

func randStr() string { b := make([]byte, 12); _, _ = rand.Read(b); return enc(b) }

func newVerifier(t *testing.T, algs ...string) *Verifier {
	t.Helper()
	if len(algs) == 0 {
		algs = []string{"ES256"}
	}
	v, err := New(Config{AllowedAlgs: algs, IATWindow: 30 * time.Second}, NewReplayCache(1000))
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return t0 }
	v.cache.now = v.now
	return v
}

func req(p, jkt string) Request {
	return Request{Proof: p, Method: "GET", URL: testURL, AccessToken: testToken, BoundJKT: jkt}
}

func wantReason(t *testing.T, err error, r Reason) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Reason != r {
		t.Fatalf("muốn lý do %s, nhận %v", r, err)
	}
}

func TestVerifyAcceptsValidProofs(t *testing.T) {
	for _, s := range []signer{ecSigner(t), edSigner(t), rsaSigner(t, 2048)} {
		t.Run(s.alg, func(t *testing.T) {
			v := newVerifier(t, "ES256", "EdDSA", "RS256")
			res, err := v.Verify(req(proof(s, nil), s.jkt(t)))
			if err != nil {
				t.Fatal(err)
			}
			if res.JKT != s.jkt(t) || res.Alg != s.alg {
				t.Fatalf("result sai: %+v", res)
			}
		})
	}
}

// Bảng ca sai: mỗi dòng một vi phạm, khoá ES256 của "chủ token".
func TestVerifyRejects(t *testing.T) {
	owner := ecSigner(t)
	attacker := ecSigner(t)
	jkt := owner.jkt(t)
	cases := []struct {
		name  string
		proof func() string
		mod   func(r *Request)
		want  Reason
	}{
		{"(1) không có header DPoP", func() string { return "" }, nil, ReasonMissing},
		{"(1) hai header DPoP (Envoy gộp bằng dấu phẩy)", func() string { p := proof(owner, nil); return p + ", " + p }, nil, ReasonMultiple},
		{"proof quá lớn", func() string {
			return proof(owner, func(_, c map[string]any) { c["pad"] = strings.Repeat("a", 5000) })
		}, nil, ReasonTooLarge},
		{"(2) không phải JWT 3 phần", func() string { return "abc.def" }, nil, ReasonMalformed},
		{"(2) header không phải base64url", func() string { return "!!!.e30.c2ln" }, nil, ReasonMalformed},
		{"(4) typ = JWT", func() string { return proof(owner, func(h, _ map[string]any) { h["typ"] = "JWT" }) }, nil, ReasonBadTyp},
		{"(4) thiếu typ", func() string { return proof(owner, func(h, _ map[string]any) { delete(h, "typ") }) }, nil, ReasonBadTyp},
		{"(5) alg none, không chữ ký", func() string {
			hb, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "none", "jwk": owner.jwk})
			cb, _ := json.Marshal(map[string]any{"jti": "x", "htm": "GET", "htu": testURL, "iat": t0.Unix()})
			return enc(hb) + "." + enc(cb) + "."
		}, nil, ReasonAlgNotAllowed},
		{"(5) alg HS256 (đối xứng)", func() string {
			hb, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "HS256", "jwk": owner.jwk})
			cb, _ := json.Marshal(map[string]any{"jti": "x", "htm": "GET", "htu": testURL, "iat": t0.Unix()})
			in := enc(hb) + "." + enc(cb)
			m := hmac.New(sha256.New, []byte("secret"))
			m.Write([]byte(in))
			return in + "." + enc(m.Sum(nil))
		}, nil, ReasonAlgNotAllowed},
		{"(5) RS256 ngoài allow-list", func() string { return proof(rsaSigner(t, 2048), nil) }, nil, ReasonAlgNotAllowed},
		{"crit lạ", func() string { return proof(owner, func(h, _ map[string]any) { h["crit"] = []string{"exp"} }) }, nil, ReasonCrit},
		{"(2) thiếu chữ ký", func() string { p := proof(owner, nil); return p[:strings.LastIndex(p, ".")+1] }, nil, ReasonMalformed},
		{"(7) thiếu jwk", func() string { return proof(owner, func(h, _ map[string]any) { delete(h, "jwk") }) }, nil, ReasonBadJWK},
		{"(7) jwk chứa khoá riêng d", func() string {
			return proof(owner, func(h, _ map[string]any) {
				j := map[string]any{}
				for k, v := range owner.jwk {
					j[k] = v
				}
				j["d"] = enc(make([]byte, 32))
				h["jwk"] = j
			})
		}, nil, ReasonPrivateKey},
		{"(7) jwk RSA cho alg ES256", func() string {
			return proof(owner, func(h, _ map[string]any) { h["jwk"] = rsaSigner(t, 2048).jwk })
		}, nil, ReasonBadJWK},
		{"(7) jwk crv P-384 cho ES256", func() string {
			return proof(owner, func(h, _ map[string]any) {
				h["jwk"] = map[string]any{"kty": "EC", "crv": "P-384", "x": owner.jwk["x"], "y": owner.jwk["y"]}
			})
		}, nil, ReasonBadJWK},
		{"(7) điểm không nằm trên P-256 (invalid curve)", func() string {
			return proof(owner, func(h, _ map[string]any) {
				h["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": owner.jwk["x"], "y": enc(make([]byte, 32))}
			})
		}, nil, ReasonBadJWK},
		{"(7) x có padding '='", func() string {
			return proof(owner, func(h, _ map[string]any) {
				h["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": owner.jwk["x"].(string) + "=", "y": owner.jwk["y"]}
			})
		}, nil, ReasonBadJWK},
		{"(12) token đánh cắp + proof ký bằng khoá của kẻ tấn công", func() string { return proof(attacker, nil) }, nil, ReasonKeyMismatch},
		{"(12) token không gắn khoá (cnf.jkt rỗng)", func() string { return proof(owner, nil) }, func(r *Request) { r.BoundJKT = "" }, ReasonKeyMismatch},
		{"(6) chữ ký bị lật 1 bit", func() string {
			p := proof(owner, nil)
			i := strings.LastIndex(p, ".")
			sig, _ := base64.RawURLEncoding.DecodeString(p[i+1:])
			sig[5] ^= 1
			return p[:i+1] + enc(sig)
		}, nil, ReasonBadSignature},
		{"(6) mang jwk của chủ token nhưng ký bằng khoá kẻ tấn công", func() string {
			return proof(signer{alg: "ES256", jwk: owner.jwk, sign: attacker.sign}, nil)
		}, nil, ReasonBadSignature},
		{"(3) thiếu jti", func() string { return proof(owner, func(_, c map[string]any) { delete(c, "jti") }) }, nil, ReasonMissingClaim},
		{"(3) thiếu htm", func() string { return proof(owner, func(_, c map[string]any) { delete(c, "htm") }) }, nil, ReasonMissingClaim},
		{"(3) thiếu htu", func() string { return proof(owner, func(_, c map[string]any) { delete(c, "htu") }) }, nil, ReasonMissingClaim},
		{"(3) thiếu iat", func() string { return proof(owner, func(_, c map[string]any) { delete(c, "iat") }) }, nil, ReasonMissingClaim},
		{"(3) thiếu ath khi có access token", func() string { return proof(owner, func(_, c map[string]any) { delete(c, "ath") }) }, nil, ReasonMissingClaim},
		{"iat là chuỗi", func() string { return proof(owner, func(_, c map[string]any) { c["iat"] = "1793000000" }) }, nil, ReasonMalformed},
		{"jti quá dài", func() string { return proof(owner, func(_, c map[string]any) { c["jti"] = strings.Repeat("j", 300) }) }, nil, ReasonMalformed},
		{"(8) htm POST cho request GET", func() string { return proof(owner, func(_, c map[string]any) { c["htm"] = "POST" }) }, nil, ReasonHTMMismatch},
		{"(8) htm chữ thường", func() string { return proof(owner, func(_, c map[string]any) { c["htm"] = "get" }) }, nil, ReasonHTMMismatch},
		{"(9) htu khác path", func() string {
			return proof(owner, func(_, c map[string]any) { c["htu"] = "https://localhost:8445/profile/whoami" })
		}, nil, ReasonHTUMismatch},
		{"(9) htu khác host", func() string {
			return proof(owner, func(_, c map[string]any) { c["htu"] = "https://evil.example:8445/orders/whoami" })
		}, nil, ReasonHTUMismatch},
		{"(9) htu http thay vì https", func() string {
			return proof(owner, func(_, c map[string]any) { c["htu"] = "http://localhost:8445/orders/whoami" })
		}, nil, ReasonHTUMismatch},
		{"(9) htu khác cổng (proof cho P1 đem sang P2)", func() string {
			return proof(owner, func(_, c map[string]any) { c["htu"] = "https://localhost:8443/orders/whoami" })
		}, nil, ReasonHTUMismatch},
		{"(9) htu tương đối", func() string { return proof(owner, func(_, c map[string]any) { c["htu"] = "/orders/whoami" }) }, nil, ReasonHTUMismatch},
		{"(11) iat cũ 31 s", func() string { return proof(owner, func(_, c map[string]any) { c["iat"] = t0.Unix() - 31 }) }, nil, ReasonIATWindow},
		{"(11) iat tương lai 31 s", func() string { return proof(owner, func(_, c map[string]any) { c["iat"] = t0.Unix() + 31 }) }, nil, ReasonIATWindow},
		{"(12) ath của token khác", func() string { return proof(owner, func(_, c map[string]any) { c["ath"] = ath("token-khac") }) }, nil, ReasonATHMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := req(tc.proof(), jkt)
			if tc.mod != nil {
				tc.mod(&r)
			}
			res, err := newVerifier(t).Verify(r)
			if res != nil {
				t.Fatalf("proof sai mà được chấp nhận: %+v", res)
			}
			wantReason(t, err, tc.want)
		})
	}
}

func TestVerifyRejectsSmallRSAKey(t *testing.T) {
	s := rsaSigner(t, 1024)
	raw, _ := json.Marshal(s.jwk)
	if _, err := Thumbprint(raw, "RS256"); err == nil {
		t.Fatal("RSA 1024 bit phải bị từ chối")
	}
}

// Biên cửa sổ iat: 29 s trước / sau vẫn được (cửa sổ 30 s).
func TestVerifyAcceptsIATInsideWindow(t *testing.T) {
	s := ecSigner(t)
	for _, d := range []int64{-29, 29} {
		p := proof(s, func(_, c map[string]any) { c["iat"] = t0.Unix() + d })
		if _, err := newVerifier(t).Verify(req(p, s.jkt(t))); err != nil {
			t.Fatalf("iat lệch %d s phải được chấp nhận: %v", d, err)
		}
	}
}

// RFC 9449 §4.3 bước 9: so htu bỏ query/fragment và chuẩn hoá scheme/host/cổng mặc định.
func TestVerifyNormalizesHTU(t *testing.T) {
	s := ecSigner(t)
	for _, htu := range []string{"https://LOCALHOST:8445/orders/whoami", "HTTPS://localhost:8445/orders/whoami",
		"https://localhost:8445/orders/whoami?x=1", "https://localhost:8445/orders/whoami#f"} {
		v := newVerifier(t)
		if _, err := v.Verify(req(proof(s, func(_, c map[string]any) { c["htu"] = htu }), s.jkt(t))); err != nil {
			t.Errorf("htu %q phải khớp %s: %v", htu, testURL, err)
		}
	}
	if !sameURI("https://h/a", "https://h:443/a") || !sameURI("http://h:80", "http://h/") || sameURI("https://h/a", "https://h/A") {
		t.Fatal("chuẩn hoá cổng mặc định / path sai")
	}
}

func TestVerifyAcceptsTypCaseInsensitive(t *testing.T) {
	s := ecSigner(t)
	p := proof(s, func(h, _ map[string]any) { h["typ"] = "DPoP+JWT" })
	if _, err := newVerifier(t).Verify(req(p, s.jkt(t))); err != nil {
		t.Fatalf("typ là media type, không phân biệt hoa thường: %v", err)
	}
}

// §11.1: cùng một proof dùng lần hai → replay.
func TestVerifyRejectsReplay(t *testing.T) {
	s := ecSigner(t)
	v := newVerifier(t)
	p := proof(s, nil)
	if _, err := v.Verify(req(p, s.jkt(t))); err != nil {
		t.Fatal(err)
	}
	_, err := v.Verify(req(p, s.jkt(t)))
	wantReason(t, err, ReasonReplay)
}

// jti chỉ được ghi sau khi mọi bước khác qua: proof hỏng không "đốt" jti của proof thật.
func TestVerifyDoesNotStoreJTIOfFailedProof(t *testing.T) {
	s := ecSigner(t)
	v := newVerifier(t)
	bad := proof(s, func(_, c map[string]any) { c["jti"] = "same-jti"; c["htm"] = "DELETE" })
	_, err := v.Verify(req(bad, s.jkt(t)))
	wantReason(t, err, ReasonHTMMismatch)
	if v.cache.Len() != 0 {
		t.Fatal("proof hỏng đã bị ghi vào cache")
	}
	good := proof(s, func(_, c map[string]any) { c["jti"] = "same-jti" })
	if _, err := v.Verify(req(good, s.jkt(t))); err != nil {
		t.Fatalf("proof thật cùng jti phải qua: %v", err)
	}
}

// Hai client khác khoá tình cờ trùng jti không chặn nhầm nhau (khoá cache gộp jkt).
func TestVerifySameJTIDifferentKeys(t *testing.T) {
	a, b := ecSigner(t), ecSigner(t)
	v := newVerifier(t)
	for _, s := range []signer{a, b} {
		p := proof(s, func(_, c map[string]any) { c["jti"] = "shared" })
		if _, err := v.Verify(req(p, s.jkt(t))); err != nil {
			t.Fatal(err)
		}
	}
}

// Sau khi hết cửa sổ, proof cũ bị chặn bởi iat (không cần cache nữa).
func TestVerifyOldProofRejectedByIATAfterWindow(t *testing.T) {
	s := ecSigner(t)
	v := newVerifier(t)
	p := proof(s, nil)
	if _, err := v.Verify(req(p, s.jkt(t))); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(31 * time.Second)
	v.now = func() time.Time { return later }
	v.cache.now = v.now
	_, err := v.Verify(req(p, s.jkt(t)))
	wantReason(t, err, ReasonIATWindow)
}

func TestVerifyCacheFullRejects(t *testing.T) {
	s := ecSigner(t)
	v, _ := New(Config{AllowedAlgs: []string{"ES256"}, IATWindow: 30 * time.Second}, NewReplayCache(2))
	v.now = func() time.Time { return t0 }
	v.cache.now = v.now
	for i := 0; i < 2; i++ {
		if _, err := v.Verify(req(proof(s, nil), s.jkt(t))); err != nil {
			t.Fatal(err)
		}
	}
	_, err := v.Verify(req(proof(s, nil), s.jkt(t)))
	wantReason(t, err, ReasonCacheFull)
}

func TestNewRejectsDangerousConfig(t *testing.T) {
	c := NewReplayCache(10)
	for name, cfg := range map[string]Config{
		"allow-list rỗng":   {IATWindow: time.Second},
		"alg none":          {AllowedAlgs: []string{"none"}, IATWindow: time.Second},
		"alg HS256":         {AllowedAlgs: []string{"HS256"}, IATWindow: time.Second},
		"cửa sổ 0":          {AllowedAlgs: []string{"ES256"}},
		"cửa sổ quá rộng":   {AllowedAlgs: []string{"ES256"}, IATWindow: time.Hour},
		"thiếu cache (nil)": {AllowedAlgs: []string{"ES256"}, IATWindow: time.Second},
	} {
		cache := c
		if name == "thiếu cache (nil)" {
			cache = nil
		}
		if _, err := New(cfg, cache); err == nil {
			t.Errorf("%s: phải bị từ chối khi khởi động", name)
		}
	}
}

// Thumbprint khớp ví dụ chuẩn trong RFC 7638 §3.1.
func TestThumbprintRFC7638Example(t *testing.T) {
	jwk := json.RawMessage(`{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`)
	got, err := Thumbprint(jwk, "RS256")
	if err != nil {
		t.Fatal(err)
	}
	if want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Fatalf("thumbprint = %s, muốn %s (RFC 7638 §3.1)", got, want)
	}
}
