package jwtverify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// Giới hạn khi đọc JWKS — JWKS đến từ mạng nên cũng là dữ liệu không tin cậy (T10).
const (
	maxJWKSBytes   = 64 << 10 // 64 KiB
	maxJWKSKeys    = 20
	minRSAKeyBits  = 2048
	defaultTimeout = 2 * time.Second
)

// PublicKey là một khoá ký đã kiểm tra từ JWKS.
type PublicKey struct {
	Kid string
	Alg string // alg ghi trong JWK (có thể rỗng); nếu có thì phải khớp alg của token
	Key crypto.PublicKey
}

// KeySource trả khoá công khai theo kid. Verifier chỉ phụ thuộc interface này,
// nên unit test dùng được khoá sinh sẵn mà không cần Keycloak.
type KeySource interface {
	Key(ctx context.Context, kid string) (*PublicKey, error)
}

// ErrUnknownKid: JWKS (kể cả sau khi tải lại) không có kid này.
var ErrUnknownKid = errors.New("jwks: unknown kid")

// ErrJWKSUnavailable: không tải được JWKS và không còn khoá cũ trong hạn dùng → fail closed.
var ErrJWKSUnavailable = errors.New("jwks: unavailable")

// JWKSConfig cấu hình cache JWKS.
type JWKSConfig struct {
	URL        string        // ghi cứng trong cấu hình (SR-02), không lấy từ token (jku/x5u)
	TTL        time.Duration // khoá dùng tối đa TTL rồi tải lại
	MinRefetch time.Duration // gặp kid lạ: tải lại, nhưng không quá 1 lần mỗi MinRefetch
	StaleGrace time.Duration // tải lại lỗi: dùng tiếp khoá cũ thêm tối đa StaleGrace, quá thì từ chối
	Client     *http.Client  // nil → client mặc định timeout 2 s, không theo redirect
}

// JWKSCache tải JWKS qua HTTP và giữ trong bộ nhớ. An toàn khi dùng từ nhiều goroutine.
type JWKSCache struct {
	cfg JWKSConfig
	now func() time.Time

	mu          sync.Mutex
	keys        map[string]*PublicKey
	fetchedAt   time.Time // lần tải thành công gần nhất
	lastAttempt time.Time // lần thử tải gần nhất (thành công hay lỗi)
}

// NewJWKSCache tạo cache; chưa tải gì cho tới lần gọi Key đầu tiên (hoặc Refresh).
func NewJWKSCache(cfg JWKSConfig) *JWKSCache {
	if cfg.Client == nil {
		cfg.Client = &http.Client{
			Timeout: defaultTimeout,
			// Không theo redirect: URL JWKS đã ghim, redirect có thể dẫn tới khoá của kẻ tấn công.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &JWKSCache{cfg: cfg, now: time.Now}
}

// Key trả khoá theo kid, tải lại JWKS khi cần.
//
// Thứ tự quyết định (giữ khoá mu suốt quá trình — tải JWKS hiếm và có timeout 2 s):
//  1. Khoá còn trong TTL và có kid → trả ngay.
//  2. Hết TTL hoặc kid lạ → tải lại, trừ khi vừa thử tải trong MinRefetch (chống kid ngẫu nhiên
//     biến auth-svc thành công cụ dội request vào Keycloak — T10).
//  3. Tải lỗi → chỉ dùng khoá cũ nếu chưa quá TTL + StaleGrace; không thì ErrJWKSUnavailable.
func (c *JWKSCache) Key(ctx context.Context, kid string) (*PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	fresh := c.keys != nil && now.Sub(c.fetchedAt) < c.cfg.TTL
	if k, ok := c.keys[kid]; ok && fresh {
		return k, nil
	}

	if now.Sub(c.lastAttempt) >= c.cfg.MinRefetch || c.lastAttempt.IsZero() {
		c.lastAttempt = now
		keys, err := c.fetch(ctx)
		if err == nil {
			c.keys, c.fetchedAt = keys, now
			if k, ok := keys[kid]; ok {
				return k, nil
			}
			return nil, ErrUnknownKid
		}
		// Tải lỗi: rơi xuống nhánh dùng khoá cũ (nếu còn hạn) bên dưới.
	}

	if c.keys == nil || now.Sub(c.fetchedAt) >= c.cfg.TTL+c.cfg.StaleGrace {
		return nil, ErrJWKSUnavailable
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, ErrUnknownKid
}

// Refresh tải JWKS ngay (dùng lúc khởi động để "làm nóng" cache).
func (c *JWKSCache) Refresh(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastAttempt = c.now()
	keys, err := c.fetch(ctx)
	if err != nil {
		return err
	}
	c.keys, c.fetchedAt = keys, c.lastAttempt
	return nil
}

func (c *JWKSCache) fetch(ctx context.Context) (map[string]*PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.cfg.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxJWKSBytes {
		return nil, errors.New("jwks: response too large")
	}
	return ParseJWKS(body)
}

// jwk là các trường JWK (RFC 7517, RFC 7518 §6) mà lab dùng.
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ParseJWKS đọc JWKS, CHỈ giữ khoá ký hợp lệ:
//   - use phải là "sig": JWKS của Keycloak có cả khoá RSA-OAEP (use "enc") để mã hoá —
//     khoá đó không bao giờ được dùng để kiểm chữ ký;
//   - phải có kid (token chọn khoá bằng kid);
//   - RSA ≥ 2048 bit, số mũ e hợp lệ; EC chỉ P-256 và điểm phải nằm trên đường cong.
//
// Khoá không đạt bị bỏ qua (không làm hỏng cả JWKS); không còn khoá nào thì báo lỗi.
func ParseJWKS(data []byte) (map[string]*PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	if len(set.Keys) > maxJWKSKeys {
		return nil, errors.New("jwks: too many keys")
	}
	keys := make(map[string]*PublicKey)
	for _, k := range set.Keys {
		if k.Use != "sig" || k.Kid == "" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			continue
		}
		keys[k.Kid] = &PublicKey{Kid: k.Kid, Alg: k.Alg, Key: pub}
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks: no usable signing keys")
	}
	return keys, nil
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := decodeBigInt(k.N)
		if err != nil {
			return nil, err
		}
		e, err := decodeBigInt(k.E)
		if err != nil {
			return nil, err
		}
		if n.BitLen() < minRSAKeyBits {
			return nil, errors.New("jwks: RSA key too small")
		}
		if !e.IsInt64() || e.Int64() < 3 || e.Int64()%2 == 0 || e.Int64() > 1<<31-1 {
			return nil, errors.New("jwks: bad RSA exponent")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, errors.New("jwks: unsupported curve")
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != 32 {
			return nil, errors.New("jwks: bad EC x")
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil || len(y) != 32 {
			return nil, errors.New("jwks: bad EC y")
		}
		// ParseUncompressedPublicKey kiểm điểm (x, y) nằm trên P-256 — chặn invalid-curve attack.
		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	default:
		return nil, errors.New("jwks: unsupported kty")
	}
}

func decodeBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, errors.New("jwks: bad base64url integer")
	}
	return new(big.Int).SetBytes(b), nil
}
