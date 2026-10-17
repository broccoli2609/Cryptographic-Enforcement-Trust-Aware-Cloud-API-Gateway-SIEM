// Package jwtverify kiểm access token JWT theo cách "chặt" của profile P1 (SR-02, RFC 8725).
//
// Chỉ dùng thư viện chuẩn (crypto/rsa, crypto/ecdsa, crypto/sha256) để mỗi bước kiểm đều
// nhìn thấy được trong code. Thứ tự kiểm đi từ rẻ tới đắt (T10): định dạng → alg → kid →
// chữ ký → claim. Payload chỉ được giải mã SAU KHI chữ ký đúng.
package jwtverify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

// Reason là mã lý do từ chối. Ghi vào log để hunt (H3: alg/kid bất thường),
// KHÔNG trả chi tiết cho client (client chỉ nhận "invalid_token").
type Reason string

const (
	ReasonTooLarge       Reason = "token_too_large"
	ReasonMalformed      Reason = "malformed"
	ReasonAlgNotAllowed  Reason = "alg_not_allowed"
	ReasonCritUnknown    Reason = "crit_not_supported"
	ReasonMissingKid     Reason = "missing_kid"
	ReasonUnknownKid     Reason = "unknown_kid"
	ReasonJWKS           Reason = "jwks_unavailable"
	ReasonKeyMismatch    Reason = "key_alg_mismatch"
	ReasonBadSignature   Reason = "bad_signature"
	ReasonWrongIssuer    Reason = "wrong_iss"
	ReasonWrongAudience  Reason = "wrong_aud"
	ReasonMissingExp     Reason = "missing_exp"
	ReasonExpired        Reason = "expired"
	ReasonNotYetValid    Reason = "nbf_in_future"
	ReasonIssuedInFuture Reason = "iat_in_future"
	ReasonWrongType      Reason = "wrong_typ"
	ReasonMissingSubject Reason = "missing_sub"
)

// Error là lỗi kiểm token. Alg và Kid là giá trị (đã cắt ngắn) đọc từ header — có ích cho
// hunt H3 ngay cả khi token bị từ chối.
type Error struct {
	Reason Reason
	Alg    string
	Kid    string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "jwt: " + string(e.Reason)
	}
	return fmt.Sprintf("jwt: %s: %s", e.Reason, e.Detail)
}

// Config là cấu hình cho MỘT issuer. Mọi giá trị đến từ cấu hình của gateway, không từ token.
type Config struct {
	Issuer      string        // iss phải bằng đúng chuỗi này
	Audience    string        // aud phải chứa giá trị này
	AllowedAlgs []string      // allow-list alg của issuer, ví dụ ["RS256"]
	TokenType   string        // claim typ bắt buộc trong payload; access token Keycloak = "Bearer"
	ClockSkew   time.Duration // lệch đồng hồ cho phép khi kiểm exp / nbf / iat
	MaxTokenLen int           // token dài hơn thì từ chối trước khi xử lý gì thêm
}

// supportedAlgs là các alg mà code này biết kiểm. Allow-list của Config phải là tập con.
var supportedAlgs = []string{"RS256", "ES256"}

// Claims là phần payload đã kiểm, dùng cho bước phân quyền (OPA, tuần 5).
type Claims struct {
	Subject   string
	Issuer    string
	Audience  []string
	ExpiresAt time.Time
	NotBefore time.Time
	IssuedAt  time.Time
	ID        string // jti
	Type      string // typ trong payload
	ClientID  string // azp — client đã xin token
	Username  string // preferred_username
	Roles     []string
	Dept      string
	Tier      string
	Alg       string // alg trong header (đã qua allow-list)
	Kid       string
}

// Verifier kiểm token của một issuer.
type Verifier struct {
	cfg  Config
	keys KeySource
	now  func() time.Time
}

// New tạo Verifier, từ chối cấu hình nguy hiểm ngay khi khởi động (fail fast).
func New(cfg Config, keys KeySource) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" || len(cfg.AllowedAlgs) == 0 {
		return nil, errors.New("jwtverify: Issuer, Audience, AllowedAlgs are required")
	}
	for _, a := range cfg.AllowedAlgs {
		if !slices.Contains(supportedAlgs, a) {
			// Chặn cấu hình nhầm "none", "HS256"… — với issuer dùng khoá bất đối xứng,
			// HS* chính là cửa cho tấn công alg confusion.
			return nil, fmt.Errorf("jwtverify: alg %q not supported (allowed: %v)", a, supportedAlgs)
		}
	}
	if cfg.MaxTokenLen == 0 {
		cfg.MaxTokenLen = 8 << 10
	}
	if keys == nil {
		return nil, errors.New("jwtverify: KeySource is required")
	}
	return &Verifier{cfg: cfg, keys: keys, now: time.Now}, nil
}

// header là phần JOSE header mà ta đọc. Các trường jku, x5u, jwk, x5c CỐ Ý không có ở đây:
// khoá chỉ đến từ JWKS đã ghim, không bao giờ từ token (RFC 8725 §3.10, luật SR-02).
type header struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Crit []string `json:"crit"`
}

// payload: aud có thể là chuỗi hoặc mảng (RFC 7519 §4.1.3); thời gian là NumericDate (giây).
type payload struct {
	Iss         string          `json:"iss"`
	Sub         string          `json:"sub"`
	Aud         json.RawMessage `json:"aud"`
	Exp         *json.Number    `json:"exp"`
	Nbf         *json.Number    `json:"nbf"`
	Iat         *json.Number    `json:"iat"`
	Jti         string          `json:"jti"`
	Typ         string          `json:"typ"`
	Azp         string          `json:"azp"`
	Username    string          `json:"preferred_username"`
	Dept        string          `json:"dept"`
	Tier        string          `json:"tier"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

// Verify kiểm token; trả Claims khi MỌI bước đều qua, ngược lại trả *Error.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	// --- Bước 1: kích thước và định dạng (rẻ nhất) ---
	if len(token) > v.cfg.MaxTokenLen {
		return nil, &Error{Reason: ReasonTooLarge}
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, &Error{Reason: ReasonMalformed, Detail: "need 3 non-empty segments"}
	}
	rawHeader, err := b64(parts[0])
	if err != nil {
		return nil, &Error{Reason: ReasonMalformed, Detail: "header base64url"}
	}
	var h header
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return nil, &Error{Reason: ReasonMalformed, Detail: "header json"}
	}
	fail := func(r Reason, detail string) (*Claims, error) {
		return nil, &Error{Reason: r, Alg: clip(h.Alg, 16), Kid: clip(h.Kid, 64), Detail: detail}
	}

	// --- Bước 2: alg trong allow-list (chặn "none", HS256 alg confusion, alg lạ) ---
	if !slices.Contains(v.cfg.AllowedAlgs, h.Alg) {
		return fail(ReasonAlgNotAllowed, "")
	}
	// crit liệt kê phần mở rộng mà người nhận BẮT BUỘC hiểu; ta không hỗ trợ cái nào (RFC 7515 §4.1.11).
	if len(h.Crit) > 0 {
		return fail(ReasonCritUnknown, "")
	}

	// --- Bước 3: chọn khoá theo kid từ JWKS đã ghim ---
	if h.Kid == "" {
		return fail(ReasonMissingKid, "")
	}
	key, err := v.keys.Key(ctx, h.Kid)
	switch {
	case errors.Is(err, ErrUnknownKid):
		return fail(ReasonUnknownKid, "")
	case err != nil:
		// JWKS không tải được và không còn khoá cũ trong hạn → fail closed (SR-11).
		return fail(ReasonJWKS, err.Error())
	}
	if key.Alg != "" && key.Alg != h.Alg {
		return fail(ReasonKeyMismatch, "jwk alg differs from token alg")
	}

	// --- Bước 4: kiểm chữ ký trên ASCII(header_b64 "." payload_b64) (đắt nhất) ---
	sig, err := b64(parts[2])
	if err != nil {
		return fail(ReasonMalformed, "signature base64url")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := verifySignature(h.Alg, key.Key, digest[:], sig); err != nil {
		if errors.Is(err, errKeyType) {
			return fail(ReasonKeyMismatch, err.Error())
		}
		return fail(ReasonBadSignature, "")
	}

	// --- Bước 5: chữ ký đúng rồi mới giải mã và kiểm claim ---
	rawPayload, err := b64(parts[1])
	if err != nil {
		return fail(ReasonMalformed, "payload base64url")
	}
	var p payload
	dec := json.NewDecoder(bytes.NewReader(rawPayload))
	dec.UseNumber()
	if err := dec.Decode(&p); err != nil {
		return fail(ReasonMalformed, "payload json")
	}

	if p.Iss != v.cfg.Issuer {
		return fail(ReasonWrongIssuer, "")
	}
	aud, err := parseAudience(p.Aud)
	if err != nil || !slices.Contains(aud, v.cfg.Audience) {
		return fail(ReasonWrongAudience, "")
	}

	now := v.now()
	skew := v.cfg.ClockSkew
	if p.Exp == nil {
		return fail(ReasonMissingExp, "")
	}
	exp, err := numericDate(*p.Exp)
	if err != nil {
		return fail(ReasonMalformed, "exp")
	}
	if !now.Before(exp.Add(skew)) {
		return fail(ReasonExpired, "")
	}
	var nbf, iat time.Time
	if p.Nbf != nil {
		if nbf, err = numericDate(*p.Nbf); err != nil {
			return fail(ReasonMalformed, "nbf")
		}
		if now.Add(skew).Before(nbf) {
			return fail(ReasonNotYetValid, "")
		}
	}
	if p.Iat != nil {
		if iat, err = numericDate(*p.Iat); err != nil {
			return fail(ReasonMalformed, "iat")
		}
		if iat.After(now.Add(skew)) {
			return fail(ReasonIssuedInFuture, "")
		}
	}

	// Phân biệt loại token bằng claim typ trong payload: header của mọi token Keycloak đều
	// là "JWT", còn payload ghi "Bearer" (access), "ID" (ID token), "Refresh" (refresh token).
	if v.cfg.TokenType != "" && p.Typ != v.cfg.TokenType {
		return fail(ReasonWrongType, "")
	}
	if p.Sub == "" {
		return fail(ReasonMissingSubject, "")
	}

	return &Claims{
		Subject: p.Sub, Issuer: p.Iss, Audience: aud,
		ExpiresAt: exp, NotBefore: nbf, IssuedAt: iat,
		ID: p.Jti, Type: p.Typ, ClientID: p.Azp, Username: p.Username,
		Roles: p.RealmAccess.Roles, Dept: p.Dept, Tier: p.Tier,
		Alg: h.Alg, Kid: h.Kid,
	}, nil
}

var errKeyType = errors.New("key type does not match alg")

// verifySignature kiểm chữ ký theo alg (RFC 7518 §3.3, §3.4). Loại khoá phải khớp alg:
// token RS256 mà kid trỏ tới khoá EC (hay ngược lại) bị từ chối, không "thử cách khác".
func verifySignature(alg string, key crypto.PublicKey, digest, sig []byte) error {
	switch alg {
	case "RS256": // RSASSA-PKCS1-v1_5 + SHA-256
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errKeyType
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
	case "ES256": // ECDSA P-256 + SHA-256; chữ ký JWS là r ‖ s, mỗi số đúng 32 byte
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errKeyType
		}
		if len(sig) != 64 {
			return errors.New("bad ES256 signature length")
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return errors.New("ecdsa verify failed")
		}
		return nil
	default:
		return errors.New("unsupported alg")
	}
}

// b64 giải mã base64url KHÔNG padding, chặt: từ chối "=" và ký tự lạ (RFC 7515 §2).
func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

func parseAudience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("missing aud")
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, err
	}
	return many, nil
}

// numericDate đổi NumericDate (giây kể từ epoch, có thể có phần thập phân) sang time.Time.
func numericDate(n json.Number) (time.Time, error) {
	f, err := n.Float64()
	if err != nil || f < 0 || f > 1<<40 {
		return time.Time{}, errors.New("bad NumericDate")
	}
	return time.Unix(int64(f), 0), nil
}

// clip cắt chuỗi lấy từ token trước khi ghi log, để token không nhồi được chuỗi dài vào SIEM.
func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
