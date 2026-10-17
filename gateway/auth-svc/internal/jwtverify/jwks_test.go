package jwtverify

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func rsaJWK(kid, use string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kid": kid, "kty": "RSA", "use": use, "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecJWK(kid string) map[string]any {
	return map[string]any{
		"kid": kid, "kty": "EC", "use": "sig", "alg": "ES256", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(realmEC.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(realmEC.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
}

// fakeKeycloak là server JWKS giả; đếm số lần bị gọi, có thể "sập" theo ý test.
type fakeKeycloak struct {
	srv   *httptest.Server
	hits  atomic.Int32
	down  atomic.Bool
	keys  atomic.Value // []map[string]any
	clock time.Time
}

func newFakeKeycloak(t *testing.T, keys ...map[string]any) *fakeKeycloak {
	t.Helper()
	f := &fakeKeycloak{clock: fixedNow}
	f.keys.Store(keys)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if f.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": f.keys.Load()})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeKeycloak) cache() *JWKSCache {
	c := NewJWKSCache(JWKSConfig{URL: f.srv.URL, TTL: 5 * time.Minute, MinRefetch: 10 * time.Second, StaleGrace: 10 * time.Minute})
	c.now = func() time.Time { return f.clock }
	return c
}

func TestParseJWKSKeepsOnlySigningKeys(t *testing.T) {
	testKeys(t)
	// Giống JWKS thật của Keycloak: một khoá RS256 "sig" và một khoá RSA-OAEP "enc".
	data, _ := json.Marshal(map[string]any{"keys": []any{
		rsaJWK("sig-key", "sig", &realmRSA.PublicKey),
		rsaJWK("enc-key", "enc", &attackerRSA.PublicKey),
		ecJWK("ec-key"),
	}})
	keys, err := ParseJWKS(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["enc-key"]; ok {
		t.Fatal("khoá use=enc không được dùng để kiểm chữ ký")
	}
	if _, ok := keys["sig-key"]; !ok {
		t.Fatal("thiếu khoá RSA use=sig")
	}
	if _, ok := keys["ec-key"]; !ok {
		t.Fatal("thiếu khoá EC use=sig")
	}
}

func TestParseJWKSRejectsWeakOrInvalidKeys(t *testing.T) {
	testKeys(t)
	small := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 1023), E: 65537} // 1024 bit
	offCurve := ecJWK("off-curve")
	offCurve["y"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) // điểm (x, 0) không nằm trên P-256
	for name, k := range map[string]map[string]any{
		"RSA 1024 bit":             rsaJWK("small", "sig", small),
		"điểm EC ngoài đường cong": offCurve,
		"không có kid":             rsaJWK("", "sig", &realmRSA.PublicKey),
	} {
		t.Run(name, func(t *testing.T) {
			data, _ := json.Marshal(map[string]any{"keys": []any{k}})
			if _, err := ParseJWKS(data); err == nil {
				t.Fatal("JWKS chỉ có khoá không hợp lệ phải báo lỗi")
			}
		})
	}
}

func TestJWKSCacheServesFromCacheWithinTTL(t *testing.T) {
	testKeys(t)
	f := newFakeKeycloak(t, rsaJWK(kidRSA, "sig", &realmRSA.PublicKey))
	c := f.cache()
	for range 5 {
		if _, err := c.Key(context.Background(), kidRSA); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.hits.Load(); got != 1 {
		t.Fatalf("trong TTL phải chỉ tải JWKS 1 lần, đã tải %d lần", got)
	}
}

func TestJWKSCacheRefetchesAfterTTL(t *testing.T) {
	testKeys(t)
	f := newFakeKeycloak(t, rsaJWK(kidRSA, "sig", &realmRSA.PublicKey))
	c := f.cache()
	_, _ = c.Key(context.Background(), kidRSA)
	f.clock = f.clock.Add(6 * time.Minute) // quá TTL 5 phút
	_, _ = c.Key(context.Background(), kidRSA)
	if got := f.hits.Load(); got != 2 {
		t.Fatalf("quá TTL phải tải lại, số lần tải = %d", got)
	}
}

// Xoay khoá: Keycloak thêm khoá mới; token ký bằng kid mới phải được nhận ngay (tải lại vì kid lạ).
func TestJWKSCacheRefetchesOnUnknownKidForKeyRotation(t *testing.T) {
	testKeys(t)
	f := newFakeKeycloak(t, rsaJWK(kidRSA, "sig", &realmRSA.PublicKey))
	c := f.cache()
	_, _ = c.Key(context.Background(), kidRSA)
	f.clock = f.clock.Add(11 * time.Second)
	f.keys.Store([]map[string]any{rsaJWK(kidRSA, "sig", &realmRSA.PublicKey), rsaJWK("rsa-2", "sig", &attackerRSA.PublicKey)})
	if _, err := c.Key(context.Background(), "rsa-2"); err != nil {
		t.Fatalf("kid mới sau xoay khoá phải được nhận: %v", err)
	}
}

// T10: kid ngẫu nhiên không được biến auth-svc thành công cụ dội request vào Keycloak.
func TestJWKSCacheRateLimitsRefetchForUnknownKids(t *testing.T) {
	testKeys(t)
	f := newFakeKeycloak(t, rsaJWK(kidRSA, "sig", &realmRSA.PublicKey))
	c := f.cache()
	_, _ = c.Key(context.Background(), kidRSA)
	for i := range 50 {
		_, err := c.Key(context.Background(), "random-kid-"+string(rune('a'+i%26)))
		if !errors.Is(err, ErrUnknownKid) {
			t.Fatalf("kid lạ phải trả ErrUnknownKid, nhận %v", err)
		}
	}
	if got := f.hits.Load(); got > 2 {
		t.Fatalf("50 kid lạ trong 10 s chỉ được tải lại tối đa 1 lần, đã tải %d lần", got)
	}
}

// SR-11: chưa từng tải được JWKS → từ chối.
func TestJWKSCacheFailsClosedWhenNeverFetched(t *testing.T) {
	f := newFakeKeycloak(t)
	f.down.Store(true)
	if _, err := f.cache().Key(context.Background(), kidRSA); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("muốn ErrJWKSUnavailable, nhận %v", err)
	}
}

// Keycloak sập sau khi đã có khoá: dùng tiếp khoá cũ trong StaleGrace, quá hạn thì từ chối.
func TestJWKSCacheStaleGraceThenFailsClosed(t *testing.T) {
	testKeys(t)
	f := newFakeKeycloak(t, rsaJWK(kidRSA, "sig", &realmRSA.PublicKey))
	c := f.cache()
	_, _ = c.Key(context.Background(), kidRSA)
	f.down.Store(true)

	f.clock = f.clock.Add(8 * time.Minute) // quá TTL (5') nhưng còn trong TTL + grace (15')
	if _, err := c.Key(context.Background(), kidRSA); err != nil {
		t.Fatalf("trong stale grace phải dùng khoá cũ: %v", err)
	}
	f.clock = f.clock.Add(10 * time.Minute) // 18' > 15'
	if _, err := c.Key(context.Background(), kidRSA); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("quá stale grace phải từ chối, nhận %v", err)
	}
}

// URL JWKS đã ghim: redirect (ví dụ Keycloak bị chiếm) không được dẫn tới JWKS khác.
func TestJWKSCacheDoesNotFollowRedirects(t *testing.T) {
	testKeys(t)
	evil := newFakeKeycloak(t, rsaJWK(kidRSA, "sig", &attackerRSA.PublicKey))
	redirect := httptest.NewServer(http.RedirectHandler(evil.srv.URL, http.StatusFound))
	t.Cleanup(redirect.Close)
	c := NewJWKSCache(JWKSConfig{URL: redirect.URL, TTL: time.Minute, MinRefetch: time.Second})
	if _, err := c.Key(context.Background(), kidRSA); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("redirect phải làm tải JWKS thất bại, nhận %v", err)
	}
	if evil.hits.Load() != 0 {
		t.Fatal("auth-svc đã đi theo redirect tới JWKS khác")
	}
}
