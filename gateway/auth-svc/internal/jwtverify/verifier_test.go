package jwtverify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testIss = "http://localhost:8080/realms/topic09"
	testAud = "topic09-api"
	kidRSA  = "rsa-1" // khoá RSA thật của "realm" trong test
	kidEC   = "ec-1"  // khoá EC cũng có trong JWKS, nhưng ES256 không nằm trong allow-list
)

var fixedNow = time.Unix(1_800_000_000, 0)

// Khoá sinh một lần cho cả gói test (sinh RSA 2048 tốn ~100 ms).
var (
	keysOnce          sync.Once
	realmRSA          *rsa.PrivateKey
	realmEC           *ecdsa.PrivateKey
	attackerRSA       *rsa.PrivateKey
	attackerEC        *ecdsa.PrivateKey
	realmPublicKeyPEM []byte // khoá CÔNG KHAI dạng PEM — thứ kẻ tấn công dùng làm "secret" HS256
)

func testKeys(t *testing.T) {
	t.Helper()
	keysOnce.Do(func() {
		realmRSA, _ = rsa.GenerateKey(rand.Reader, 2048)
		realmEC, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		attackerRSA, _ = rsa.GenerateKey(rand.Reader, 2048)
		attackerEC, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKIXPublicKey(&realmRSA.PublicKey)
		realmPublicKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	})
}

// staticKeys là JWKS cố định trong bộ nhớ (thay cho Keycloak).
type staticKeys map[string]*PublicKey

func (s staticKeys) Key(_ context.Context, kid string) (*PublicKey, error) {
	if k, ok := s[kid]; ok {
		return k, nil
	}
	return nil, ErrUnknownKid
}

type downKeys struct{} // JWKS không tải được

func (downKeys) Key(context.Context, string) (*PublicKey, error) { return nil, ErrJWKSUnavailable }

func realmJWKS() staticKeys {
	return staticKeys{
		kidRSA:       {Kid: kidRSA, Alg: "RS256", Key: &realmRSA.PublicKey},
		kidEC:        {Kid: kidEC, Alg: "ES256", Key: &realmEC.PublicKey},
		"ec-no-alg":  {Kid: "ec-no-alg", Key: &realmEC.PublicKey}, // JWK không ghi alg
		"rsa-no-alg": {Kid: "rsa-no-alg", Key: &realmRSA.PublicKey},
	}
}

func newVerifier(t *testing.T, algs []string, keys KeySource) *Verifier {
	t.Helper()
	v, err := New(Config{
		Issuer: testIss, Audience: testAud, AllowedAlgs: algs,
		TokenType: "Bearer", ClockSkew: 30 * time.Second,
	}, keys)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return fixedNow }
	return v
}

// ---------- công cụ tạo token ----------

type signer func(signingInput []byte) []byte

func rs256(k *rsa.PrivateKey) signer {
	return func(in []byte) []byte {
		d := sha256.Sum256(in)
		s, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		return s
	}
}

func es256(k *ecdsa.PrivateKey) signer {
	return func(in []byte) []byte {
		d := sha256.Sum256(in)
		r, s, _ := ecdsa.Sign(rand.Reader, k, d[:])
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	}
}

func hs256(secret []byte) signer {
	return func(in []byte) []byte {
		m := hmac.New(sha256.New, secret)
		m.Write(in)
		return m.Sum(nil)
	}
}

func fakeSig(in []byte) []byte { return []byte("not-a-real-signature") }

func enc(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func makeToken(hdr, claims map[string]any, sign signer) string {
	in := enc(hdr) + "." + enc(claims)
	return in + "." + base64.RawURLEncoding.EncodeToString(sign([]byte(in)))
}

func hdrRS256() map[string]any { return map[string]any{"alg": "RS256", "typ": "JWT", "kid": kidRSA} }

// goodClaims là payload của một access token Keycloak hợp lệ tại thời điểm fixedNow.
func goodClaims() map[string]any {
	return map[string]any{
		"iss": testIss, "aud": testAud, "sub": "a6dd1608-1da4-43c5-bdcb-e80f368478f6",
		"typ": "Bearer", "azp": "web-app", "jti": "onrtac:1", "preferred_username": "alice",
		"exp": fixedNow.Add(5 * time.Minute).Unix(), "iat": fixedNow.Add(-time.Minute).Unix(),
		"realm_access": map[string]any{"roles": []string{"employee"}},
		"dept":         "sales", "tier": "standard",
	}
}

func with(m map[string]any, k string, v any) map[string]any { m[k] = v; return m }
func without(m map[string]any, k string) map[string]any     { delete(m, k); return m }

// ---------- test ca HỢP LỆ ----------

func TestVerifyAcceptsValidKeycloakAccessToken(t *testing.T) {
	testKeys(t)
	v := newVerifier(t, []string{"RS256"}, realmJWKS())
	c, err := v.Verify(context.Background(), makeToken(hdrRS256(), goodClaims(), rs256(realmRSA)))
	if err != nil {
		t.Fatalf("token hợp lệ bị từ chối: %v", err)
	}
	if c.Subject != "a6dd1608-1da4-43c5-bdcb-e80f368478f6" || c.ClientID != "web-app" ||
		c.Dept != "sales" || c.Tier != "standard" || len(c.Roles) != 1 || c.Roles[0] != "employee" ||
		c.Alg != "RS256" || c.Kid != kidRSA {
		t.Fatalf("claims sai: %+v", c)
	}
}

func TestVerifyAcceptsEdgeCasesWithinRules(t *testing.T) {
	testKeys(t)
	v := newVerifier(t, []string{"RS256"}, realmJWKS())
	cases := map[string]map[string]any{
		"aud là mảng có chứa topic09-api":        with(goodClaims(), "aud", []string{"other", testAud}),
		"exp vừa qua 10 s (trong lệch 30 s)":     with(goodClaims(), "exp", fixedNow.Add(-10*time.Second).Unix()),
		"nbf sớm hơn 10 s nữa (trong lệch 30 s)": with(goodClaims(), "nbf", fixedNow.Add(10*time.Second).Unix()),
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), makeToken(hdrRS256(), claims, rs256(realmRSA))); err != nil {
				t.Fatalf("bị từ chối: %v", err)
			}
		})
	}
}

// Token DPoP của Keycloak: typ = "DPoP" trong payload + cnf.jkt (tuần 6). Bộ kiểm cho P2
// (TokenType "DPoP") đọc được jkt; bộ kiểm cho P1 (TokenType "Bearer") từ chối nó.
func TestVerifyDPoPBoundTokenByProfile(t *testing.T) {
	testKeys(t)
	claims := with(with(goodClaims(), "typ", "DPoP"), "cnf", map[string]any{"jkt": "HqrvtgmxPP60WHHV98ypg5V2l8rNrDMol6TW80JDLXM", "kc-jkt-type": "DPoP"})
	tok := makeToken(hdrRS256(), claims, rs256(realmRSA))

	p2, err := New(Config{Issuer: testIss, Audience: testAud, AllowedAlgs: []string{"RS256"}, TokenType: "DPoP", ClockSkew: 30 * time.Second}, realmJWKS())
	if err != nil {
		t.Fatal(err)
	}
	p2.now = func() time.Time { return fixedNow }
	c, err := p2.Verify(context.Background(), tok)
	if err != nil || c.CnfJKT != "HqrvtgmxPP60WHHV98ypg5V2l8rNrDMol6TW80JDLXM" {
		t.Fatalf("P2 phải đọc được cnf.jkt: claims=%+v err=%v", c, err)
	}

	_, err = newVerifier(t, []string{"RS256"}, realmJWKS()).Verify(context.Background(), tok)
	assertReason(t, err, ReasonWrongType)
}

func TestVerifyBearerTokenHasNoCnf(t *testing.T) {
	testKeys(t)
	c, err := newVerifier(t, []string{"RS256"}, realmJWKS()).Verify(context.Background(), makeToken(hdrRS256(), goodClaims(), rs256(realmRSA)))
	if err != nil || c.CnfJKT != "" {
		t.Fatalf("token bearer không có cnf: %+v %v", c, err)
	}
}

func TestVerifyAcceptsES256WhenAllowListed(t *testing.T) {
	testKeys(t)
	v := newVerifier(t, []string{"ES256"}, realmJWKS())
	tok := makeToken(map[string]any{"alg": "ES256", "kid": kidEC}, goodClaims(), es256(realmEC))
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("ES256 hợp lệ bị từ chối: %v", err)
	}
}

// ---------- test ca SAI (SR-02, T2) — mỗi ca một dòng, kiểm cả mã lý do ----------

func TestVerifyRejectsBadTokens(t *testing.T) {
	testKeys(t)
	good := func() string { return makeToken(hdrRS256(), goodClaims(), rs256(realmRSA)) }

	tests := []struct {
		name  string
		token string
		want  Reason
	}{
		// --- tấn công vào header / alg (RFC 8725 §2.1, §3.1) ---
		{"alg none có chữ ký giả", makeToken(map[string]any{"alg": "none", "kid": kidRSA}, goodClaims(), fakeSig), ReasonAlgNotAllowed},
		{"alg none bỏ hẳn chữ ký", enc(map[string]any{"alg": "none"}) + "." + enc(goodClaims()) + ".", ReasonMalformed},
		{"alg confusion HS256 ký bằng public key PEM của realm", makeToken(map[string]any{"alg": "HS256", "kid": kidRSA}, goodClaims(), hs256(realmPublicKeyPEM)), ReasonAlgNotAllowed},
		{"ES256 chữ ký đúng nhưng ngoài allow-list RS256", makeToken(map[string]any{"alg": "ES256", "kid": kidEC}, goodClaims(), es256(realmEC)), ReasonAlgNotAllowed},
		{"alg viết thường rs256", makeToken(map[string]any{"alg": "rs256", "kid": kidRSA}, goodClaims(), rs256(realmRSA)), ReasonAlgNotAllowed},
		{"header crit không hỗ trợ", makeToken(map[string]any{"alg": "RS256", "kid": kidRSA, "crit": []string{"exp"}}, goodClaims(), rs256(realmRSA)), ReasonCritUnknown},
		{"thiếu kid", makeToken(map[string]any{"alg": "RS256"}, goodClaims(), rs256(realmRSA)), ReasonMissingKid},
		{"kid không có trong JWKS", makeToken(map[string]any{"alg": "RS256", "kid": "nope"}, goodClaims(), rs256(realmRSA)), ReasonUnknownKid},
		{"RS256 nhưng kid trỏ tới khoá EC (JWK có alg ES256)", makeToken(map[string]any{"alg": "RS256", "kid": kidEC}, goodClaims(), rs256(realmRSA)), ReasonKeyMismatch},
		{"RS256 nhưng kid trỏ tới khoá EC (JWK không ghi alg)", makeToken(map[string]any{"alg": "RS256", "kid": "ec-no-alg"}, goodClaims(), rs256(realmRSA)), ReasonKeyMismatch},
		// --- khoá do token tự chỉ định phải bị bỏ qua (jku / jwk injection, RFC 8725 §3.10) ---
		{"jku trỏ tới JWKS của kẻ tấn công bị bỏ qua", makeToken(map[string]any{"alg": "RS256", "kid": "attacker", "jku": "https://evil.example/jwks.json"}, goodClaims(), rs256(attackerRSA)), ReasonUnknownKid},
		{"jwk nhúng trong header bị bỏ qua", makeToken(map[string]any{"alg": "RS256", "kid": kidRSA, "jwk": map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB"}}, goodClaims(), rs256(attackerRSA)), ReasonBadSignature},
		// --- chữ ký ---
		{"ký bằng khoá RSA của kẻ tấn công", makeToken(hdrRS256(), goodClaims(), rs256(attackerRSA)), ReasonBadSignature},
		{"payload bị sửa sau khi ký (tự nâng role)", tamperPayload(good()), ReasonBadSignature},
		{"chữ ký bị lật 1 bit", flipSignatureBit(good()), ReasonBadSignature},
		// --- claim (RFC 8725 §3.8, §3.9, §3.11) ---
		{"sai iss (realm master)", makeToken(hdrRS256(), with(goodClaims(), "iss", "http://localhost:8080/realms/master"), rs256(realmRSA)), ReasonWrongIssuer},
		{"sai aud (account)", makeToken(hdrRS256(), with(goodClaims(), "aud", "account"), rs256(realmRSA)), ReasonWrongAudience},
		{"aud là mảng không có topic09-api", makeToken(hdrRS256(), with(goodClaims(), "aud", []string{"account", "web-app"}), rs256(realmRSA)), ReasonWrongAudience},
		{"thiếu aud", makeToken(hdrRS256(), without(goodClaims(), "aud"), rs256(realmRSA)), ReasonWrongAudience},
		{"hết hạn quá lệch 30 s", makeToken(hdrRS256(), with(goodClaims(), "exp", fixedNow.Add(-31*time.Second).Unix()), rs256(realmRSA)), ReasonExpired},
		{"thiếu exp", makeToken(hdrRS256(), without(goodClaims(), "exp"), rs256(realmRSA)), ReasonMissingExp},
		{"nbf ở tương lai quá lệch 30 s", makeToken(hdrRS256(), with(goodClaims(), "nbf", fixedNow.Add(time.Minute).Unix()), rs256(realmRSA)), ReasonNotYetValid},
		{"iat ở tương lai quá lệch 30 s", makeToken(hdrRS256(), with(goodClaims(), "iat", fixedNow.Add(time.Hour).Unix()), rs256(realmRSA)), ReasonIssuedInFuture},
		{"ID token (typ=ID) thay access token", makeToken(hdrRS256(), with(goodClaims(), "typ", "ID"), rs256(realmRSA)), ReasonWrongType},
		{"refresh token (typ=Refresh) thay access token", makeToken(hdrRS256(), with(goodClaims(), "typ", "Refresh"), rs256(realmRSA)), ReasonWrongType},
		{"thiếu typ", makeToken(hdrRS256(), without(goodClaims(), "typ"), rs256(realmRSA)), ReasonWrongType},
		{"thiếu sub", makeToken(hdrRS256(), without(goodClaims(), "sub"), rs256(realmRSA)), ReasonMissingSubject},
		// --- định dạng và kích thước (T10) ---
		{"chỉ có 2 phần", "aaa.bbb", ReasonMalformed},
		{"header có padding = (không phải base64url chặt)", enc(hdrRS256()) + "=." + enc(goodClaims()) + ".c2ln", ReasonMalformed},
		{"header không phải JSON", base64.RawURLEncoding.EncodeToString([]byte("not json")) + "." + enc(goodClaims()) + ".c2ln", ReasonMalformed},
		{"token dài hơn 8 KiB", makeToken(hdrRS256(), with(goodClaims(), "pad", strings.Repeat("x", 9000)), rs256(realmRSA)), ReasonTooLarge},
	}

	v := newVerifier(t, []string{"RS256"}, realmJWKS())
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), tc.token)
			assertReason(t, err, tc.want)
		})
	}
}

func TestVerifyRejectsES256WithWrongSignatureLength(t *testing.T) {
	testKeys(t)
	v := newVerifier(t, []string{"ES256"}, realmJWKS())
	tok := makeToken(map[string]any{"alg": "ES256", "kid": kidEC}, goodClaims(), fakeSig)
	_, err := v.Verify(context.Background(), tok)
	assertReason(t, err, ReasonBadSignature)
}

func TestVerifyRejectsES256SignedByAttacker(t *testing.T) {
	testKeys(t)
	v := newVerifier(t, []string{"ES256"}, realmJWKS())
	tok := makeToken(map[string]any{"alg": "ES256", "kid": kidEC}, goodClaims(), es256(attackerEC))
	_, err := v.Verify(context.Background(), tok)
	assertReason(t, err, ReasonBadSignature)
}

// SR-11: JWKS không tải được → từ chối, không bao giờ cho qua.
func TestVerifyFailsClosedWhenJWKSUnavailable(t *testing.T) {
	testKeys(t)
	v := newVerifier(t, []string{"RS256"}, downKeys{})
	_, err := v.Verify(context.Background(), makeToken(hdrRS256(), goodClaims(), rs256(realmRSA)))
	assertReason(t, err, ReasonJWKS)
}

func TestNewRejectsDangerousAllowList(t *testing.T) {
	for _, alg := range []string{"none", "HS256", "RS512"} {
		if _, err := New(Config{Issuer: testIss, Audience: testAud, AllowedAlgs: []string{alg}}, staticKeys{}); err == nil {
			t.Errorf("New chấp nhận alg %q trong allow-list", alg)
		}
	}
	if _, err := New(Config{Audience: testAud, AllowedAlgs: []string{"RS256"}}, staticKeys{}); err == nil {
		t.Error("New chấp nhận cấu hình thiếu Issuer")
	}
}

func TestErrorKeepsHeaderValuesShortForLogs(t *testing.T) {
	testKeys(t)
	v := newVerifier(t, []string{"RS256"}, realmJWKS())
	tok := makeToken(map[string]any{"alg": strings.Repeat("A", 500), "kid": strings.Repeat("k", 500)}, goodClaims(), fakeSig)
	_, err := v.Verify(context.Background(), tok)
	var e *Error
	if !errors.As(err, &e) || len(e.Alg) > 16 || len(e.Kid) > 64 {
		t.Fatalf("alg/kid trong lỗi phải bị cắt ngắn, nhận %v", err)
	}
}

// ---------- helper ----------

func assertReason(t *testing.T, err error, want Reason) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("muốn bị từ chối với lý do %q, nhận err = %v", want, err)
	}
	if e.Reason != want {
		t.Fatalf("lý do = %q, muốn %q (%v)", e.Reason, want, err)
	}
}

func tamperPayload(tok string) string {
	p := strings.Split(tok, ".")
	c := goodClaims()
	c["realm_access"] = map[string]any{"roles": []string{"hr", "manager"}}
	return p[0] + "." + enc(c) + "." + p[2]
}

func flipSignatureBit(tok string) string {
	p := strings.Split(tok, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(p[2])
	sig[10] ^= 0x01
	return p[0] + "." + p[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
}
