// Package dpop kiểm DPoP proof (RFC 9449) ở phía resource server — profile P2, tuần 6 (SR-04).
//
// Ý tưởng: access token có claim cnf.jkt = thumbprint khoá công khai của client. Mỗi request
// client gửi kèm một proof (JWT ký bằng khoá riêng) ghi method, URL, thời điểm, mã ngẫu nhiên
// và hash của token. Kẻ trộm được token mà không có khoá riêng thì không tạo được proof hợp lệ;
// chép lại nguyên proof cũ (replay) thì bị chặn vì jti đã dùng, hoặc vì proof chỉ đúng cho
// đúng một method + URL trong một cửa sổ thời gian ngắn.
//
// Chỉ dùng thư viện chuẩn crypto/* để mỗi bước kiểm hiện rõ trong code. Comment "(n)" là số
// bước trong danh sách kiểm của RFC 9449 §4.3.
package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Reason là mã lý do từ chối — ghi vào log để hunt H1 (replay) và H2 (lệch sender-binding).
type Reason string

const (
	ReasonMissing       Reason = "dpop_missing"
	ReasonMultiple      Reason = "dpop_multiple_headers"
	ReasonTooLarge      Reason = "dpop_too_large"
	ReasonMalformed     Reason = "dpop_malformed"
	ReasonBadTyp        Reason = "dpop_bad_typ"
	ReasonAlgNotAllowed Reason = "dpop_alg_not_allowed"
	ReasonCrit          Reason = "dpop_crit_not_supported"
	ReasonBadJWK        Reason = "dpop_bad_jwk"
	ReasonPrivateKey    Reason = "dpop_private_key_in_jwk"
	ReasonKeyMismatch   Reason = "dpop_key_mismatch" // khoá trong proof ≠ khoá token được gắn (cnf.jkt)
	ReasonBadSignature  Reason = "dpop_bad_signature"
	ReasonMissingClaim  Reason = "dpop_missing_claim"
	ReasonHTMMismatch   Reason = "dpop_htm_mismatch"
	ReasonHTUMismatch   Reason = "dpop_htu_mismatch"
	ReasonIATWindow     Reason = "dpop_iat_out_of_window"
	ReasonATHMismatch   Reason = "dpop_ath_mismatch"
	ReasonReplay        Reason = "dpop_replay"
	ReasonCacheFull     Reason = "dpop_replay_cache_full"
)

// Error là lỗi kiểm proof. Alg và ProofJKT (thumbprint khoá CÔNG KHAI, không bí mật) giúp
// hunt H2 thấy "token của khoá A nhưng proof ký bằng khoá B".
type Error struct {
	Reason   Reason
	Alg      string
	ProofJKT string
	Detail   string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "dpop: " + string(e.Reason)
	}
	return fmt.Sprintf("dpop: %s: %s", e.Reason, e.Detail)
}

// supportedAlgs: alg bất đối xứng mà code biết kiểm. Allow-list trong Config phải là tập con.
// Không bao giờ có "none" hay HS* (RFC 9449 §4.3 bước 5: phải là chữ ký bất đối xứng).
var supportedAlgs = []string{"ES256", "EdDSA", "RS256"}

// Config cấu hình bộ kiểm.
type Config struct {
	AllowedAlgs []string      // ví dụ ["ES256"]
	IATWindow   time.Duration // |now − iat| tối đa; quyết định 2026-10-03: 30 s (RFC 9449 §11.1)
	MaxProofLen int           // proof dài hơn thì từ chối trước khi giải mã (T10); mặc định 4096
}

// Request là những gì cần để kiểm một proof. Mọi trường do auth-svc điền từ request và từ token
// ĐÃ KIỂM — không trường nào lấy từ chính proof.
type Request struct {
	Proof       string // giá trị header DPoP như Envoy chuyển tới
	Method      string // method HTTP của request
	URL         string // scheme://host/path của request (query bị bỏ khi so)
	AccessToken string // token trong "Authorization: DPoP <token>"
	BoundJKT    string // cnf.jkt trong access token đã kiểm chữ ký
}

// Result là thông tin của proof hợp lệ.
type Result struct {
	JKT string
	Alg string
}

// Verifier kiểm proof theo RFC 9449 §4.3 và chống replay theo §11.1.
type Verifier struct {
	cfg   Config
	cache *ReplayCache
	now   func() time.Time
}

// New tạo Verifier; cấu hình nguy hiểm bị từ chối ngay khi khởi động.
func New(cfg Config, cache *ReplayCache) (*Verifier, error) {
	if len(cfg.AllowedAlgs) == 0 {
		return nil, errors.New("dpop: AllowedAlgs is required")
	}
	for _, a := range cfg.AllowedAlgs {
		if !slices.Contains(supportedAlgs, a) {
			return nil, fmt.Errorf("dpop: alg %q not supported (allowed: %v)", a, supportedAlgs)
		}
	}
	if cfg.IATWindow <= 0 || cfg.IATWindow > 5*time.Minute {
		return nil, errors.New("dpop: IATWindow must be in (0, 5m]")
	}
	if cfg.MaxProofLen == 0 {
		cfg.MaxProofLen = 4096
	}
	if cache == nil {
		return nil, errors.New("dpop: ReplayCache is required")
	}
	return &Verifier{cfg: cfg, cache: cache, now: time.Now}, nil
}

// AllowedAlgs trả allow-list (để server ghi vào WWW-Authenticate: DPoP algs="...").
func (v *Verifier) AllowedAlgs() []string { return slices.Clone(v.cfg.AllowedAlgs) }

type proofHeader struct {
	Typ  string          `json:"typ"`
	Alg  string          `json:"alg"`
	JWK  json.RawMessage `json:"jwk"`
	Crit []string        `json:"crit"`
}

type proofClaims struct {
	Jti string `json:"jti"`
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	// iat đọc dạng thô: json.Number của Go chấp nhận cả chuỗi "1793000000" (test bắt được),
	// trong khi NumericDate phải là SỐ JSON (RFC 7519 §2).
	Iat json.RawMessage `json:"iat"`
	Ath string          `json:"ath"`
}

// Verify chỉ trả Result khi MỌI bước đều qua; bước đầu tiên hỏng thì dừng và trả *Error.
func (v *Verifier) Verify(req Request) (*Result, error) {
	// --- (1) không quá MỘT header DPoP. Envoy gộp các header trùng tên bằng dấu phẩy, mà JWT
	// compact không bao giờ chứa dấu phẩy → có dấu phẩy nghĩa là client gửi ≥ 2 header.
	if req.Proof == "" {
		return nil, &Error{Reason: ReasonMissing}
	}
	if strings.Contains(req.Proof, ",") {
		return nil, &Error{Reason: ReasonMultiple}
	}
	if len(req.Proof) > v.cfg.MaxProofLen {
		return nil, &Error{Reason: ReasonTooLarge}
	}

	// --- (2) một JWT compact đúng định dạng.
	parts := strings.Split(req.Proof, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return nil, &Error{Reason: ReasonMalformed, Detail: "need header.payload.signature"}
	}
	rawHeader, err := b64(parts[0])
	if err != nil {
		return nil, &Error{Reason: ReasonMalformed, Detail: "header base64url"}
	}
	var h proofHeader
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return nil, &Error{Reason: ReasonMalformed, Detail: "header json"}
	}
	fail := func(r Reason, jkt, detail string) (*Result, error) {
		return nil, &Error{Reason: r, Alg: clip(h.Alg, 16), ProofJKT: jkt, Detail: detail}
	}

	// --- (4) typ = dpop+jwt: phân biệt proof với mọi JWT khác (access token, ID token…), để
	// không ai lấy một JWT loại khác ký bằng cùng khoá ra làm proof. So không phân biệt hoa
	// thường vì giá trị typ là media type (RFC 7515 §4.1.9).
	if !strings.EqualFold(h.Typ, "dpop+jwt") {
		return fail(ReasonBadTyp, "", "")
	}
	// --- (5) alg bất đối xứng, nằm trong allow-list. Chặn "none" và HS256 trước mọi việc khác.
	if !slices.Contains(v.cfg.AllowedAlgs, h.Alg) {
		return fail(ReasonAlgNotAllowed, "", "")
	}
	if len(h.Crit) > 0 { // phần mở rộng bắt buộc hiểu — ta không hỗ trợ cái nào (RFC 7515 §4.1.11)
		return fail(ReasonCrit, "", "")
	}
	if parts[2] == "" {
		return fail(ReasonMalformed, "", "missing signature")
	}

	// --- (7) jwk là khoá CÔNG KHAI hợp lệ, đúng loại với alg.
	pub, jkt, err := parseJWK(h.JWK, h.Alg)
	if errors.Is(err, errPrivate) {
		return fail(ReasonPrivateKey, "", "")
	}
	if err != nil {
		return fail(ReasonBadJWK, "", err.Error())
	}

	// --- (12, phần 2) khoá trong proof phải là khoá mà token được gắn vào (cnf.jkt). Kiểm TRƯỚC
	// chữ ký: chỉ tốn một SHA-256 (đã tính ở trên) mà chặn ngay ca phổ biến nhất của T1 — kẻ trộm
	// token tự ký proof bằng khoá của mình (T10: kiểm rẻ trước). So hằng thời gian cho chắc.
	if req.BoundJKT == "" || subtle.ConstantTimeCompare([]byte(jkt), []byte(req.BoundJKT)) != 1 {
		return fail(ReasonKeyMismatch, jkt, "")
	}

	// --- (6) chữ ký kiểm bằng khoá trong jwk. Chưa qua bước này thì CHƯA đọc payload.
	sig, err := b64(parts[2])
	if err != nil {
		return fail(ReasonMalformed, jkt, "signature base64url")
	}
	if err := verifySignature(h.Alg, pub, parts[0]+"."+parts[1], sig); err != nil {
		return fail(ReasonBadSignature, jkt, "")
	}

	// --- (3) payload có đủ claim bắt buộc (§4.2): jti, htm, htu, iat; ath khi đi kèm access token.
	rawPayload, err := b64(parts[1])
	if err != nil {
		return fail(ReasonMalformed, jkt, "payload base64url")
	}
	var c proofClaims
	if err := json.Unmarshal(rawPayload, &c); err != nil {
		return fail(ReasonMalformed, jkt, "payload json")
	}
	if c.Jti == "" || c.Htm == "" || c.Htu == "" || len(c.Iat) == 0 || string(c.Iat) == "null" ||
		(req.AccessToken != "" && c.Ath == "") {
		return fail(ReasonMissingClaim, jkt, "")
	}
	if len(c.Jti) > 256 {
		return fail(ReasonMalformed, jkt, "jti too long")
	}

	// --- (8) htm = method của request. Method HTTP phân biệt hoa thường (RFC 9110 §9.1).
	if c.Htm != req.Method {
		return fail(ReasonHTMMismatch, jkt, "")
	}
	// --- (9) htu = URI của request, bỏ query và fragment, sau khi chuẩn hoá (RFC 3986 §6.2).
	if !sameURI(c.Htu, req.URL) {
		return fail(ReasonHTUMismatch, jkt, "")
	}
	// --- (10) nonce: gateway không cấp DPoP-Nonce nên không kiểm (ghi trong báo cáo).

	// --- (11) iat nằm trong cửa sổ cho phép (§11.1).
	if c.Iat[0] == '"' {
		return fail(ReasonMalformed, jkt, "iat must be a JSON number")
	}
	iatF, err := strconv.ParseFloat(string(c.Iat), 64)
	if err != nil || iatF < 0 || iatF > 1<<40 {
		return fail(ReasonMalformed, jkt, "iat")
	}
	iat := time.Unix(int64(iatF), 0)
	now := v.now()
	if age := now.Sub(iat); age > v.cfg.IATWindow || age < -v.cfg.IATWindow {
		return fail(ReasonIATWindow, jkt, "")
	}

	// --- (12, phần 1) ath = BASE64URL(SHA-256(access token)): proof chỉ dùng được với ĐÚNG token này.
	if req.AccessToken != "" {
		sum := sha256.Sum256([]byte(req.AccessToken))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(c.Ath), []byte(want)) != 1 {
			return fail(ReasonATHMismatch, jkt, "")
		}
	}

	// --- §11.1 chống replay: ghi jti SAU KHI mọi bước trên đã qua (quyết định 2026-10-03), để
	// một proof hỏng không "đốt" được jti của proof thật. Mục sống tới iat + cửa sổ: sau thời
	// điểm đó proof đã bị bước (11) chặn, không cần nhớ nữa.
	key := sha256.Sum256([]byte(jkt + "\x00" + c.Jti))
	switch err := v.cache.Store(key, iat.Add(v.cfg.IATWindow)); {
	case errors.Is(err, ErrReplay):
		return fail(ReasonReplay, jkt, "")
	case err != nil:
		return fail(ReasonCacheFull, jkt, "")
	}
	return &Result{JKT: jkt, Alg: h.Alg}, nil
}

// verifySignature kiểm chữ ký JWS (RFC 7518 §3.3, §3.4; RFC 8037 §3.1).
func verifySignature(alg string, key crypto.PublicKey, signingInput string, sig []byte) error {
	switch alg {
	case "ES256": // ECDSA P-256 + SHA-256; chữ ký JWS là r ‖ s, mỗi số đúng 32 byte
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return errors.New("bad ES256 key/signature")
		}
		digest := sha256.Sum256([]byte(signingInput))
		if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return errors.New("ecdsa verify failed")
		}
		return nil
	case "EdDSA": // Ed25519 ký trực tiếp trên signing input, không băm trước
		pub, ok := key.(ed25519.PublicKey)
		if !ok || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, []byte(signingInput), sig) {
			return errors.New("ed25519 verify failed")
		}
		return nil
	case "RS256": // RSASSA-PKCS1-v1_5 + SHA-256
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("bad RS256 key")
		}
		digest := sha256.Sum256([]byte(signingInput))
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
	default:
		return errors.New("unsupported alg")
	}
}

// sameURI so htu với URI của request theo RFC 9449 §4.3 bước 9: bỏ query + fragment, chuẩn hoá
// theo RFC 3986 §6.2.2–6.2.3 (scheme và host chữ thường, bỏ cổng mặc định, path rỗng = "/").
func sameURI(htu, requestURI string) bool {
	a, okA := normalizeURI(htu)
	b, okB := normalizeURI(requestURI)
	return okA && okB && a == b
}

func normalizeURI(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", false
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6 không cổng
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, true
}

// b64 giải mã base64url KHÔNG padding, chặt (RFC 7515 §2).
func b64(s string) ([]byte, error) { return base64.RawURLEncoding.Strict().DecodeString(s) }

// clip cắt chuỗi lấy từ proof trước khi ghi log.
func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
