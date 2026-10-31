package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// privateMembers là các trường chỉ có trong khoá RIÊNG (RFC 7518 §6.2.2, §6.3.2, §6.4; RFC 8037).
// Proof mang khoá riêng trong header là lỗi nghiêm trọng của client (lộ tài sản #9) → từ chối
// (RFC 9449 §4.3 bước 7). "k" là khoá đối xứng — DPoP chỉ dùng khoá bất đối xứng.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// errPrivate tách riêng để Verify trả đúng mã lý do.
var errPrivate = errors.New("jwk contains private key material")

// parseJWK đọc khoá công khai trong header jwk, kiểm khoá khớp alg, và tính thumbprint
// RFC 7638 (jkt). Thumbprint chỉ dùng các trường bắt buộc, xếp theo thứ tự chữ cái, không khoảng
// trắng — cùng cách Keycloak tính cnf.jkt, nên hai bên ra cùng một chuỗi cho cùng một khoá.
func parseJWK(raw json.RawMessage, alg string) (crypto.PublicKey, string, error) {
	if len(raw) == 0 {
		return nil, "", errors.New("missing jwk")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, "", errors.New("jwk is not an object")
	}
	for _, m := range privateMembers {
		if _, ok := members[m]; ok {
			return nil, "", errPrivate
		}
	}
	var k struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, "", errors.New("jwk members must be strings")
	}

	var (
		pub   crypto.PublicKey
		thumb string
	)
	switch alg {
	case "ES256":
		if k.Kty != "EC" || k.Crv != "P-256" {
			return nil, "", fmt.Errorf("ES256 needs kty=EC crv=P-256, got %q/%q", clip(k.Kty, 8), clip(k.Crv, 8))
		}
		x, errX := b64(k.X)
		y, errY := b64(k.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return nil, "", errors.New("EC x/y must be 32-byte base64url")
		}
		// ParseUncompressedPublicKey kiểm điểm (x, y) nằm trên đường cong P-256 — chặn tấn công
		// "invalid curve" bằng một điểm giả.
		ec, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, "", errors.New("EC point not on P-256")
		}
		pub = ec
		thumb = `{"crv":"P-256","kty":"EC","x":"` + k.X + `","y":"` + k.Y + `"}`
	case "EdDSA":
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			return nil, "", fmt.Errorf("EdDSA needs kty=OKP crv=Ed25519, got %q/%q", clip(k.Kty, 8), clip(k.Crv, 8))
		}
		x, err := b64(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, "", errors.New("Ed25519 x must be 32-byte base64url")
		}
		pub = ed25519.PublicKey(x)
		thumb = `{"crv":"Ed25519","kty":"OKP","x":"` + k.X + `"}`
	case "RS256":
		if k.Kty != "RSA" {
			return nil, "", fmt.Errorf("RS256 needs kty=RSA, got %q", clip(k.Kty, 8))
		}
		n, errN := b64(k.N)
		e, errE := b64(k.E)
		if errN != nil || errE != nil || len(e) == 0 || len(e) > 4 {
			return nil, "", errors.New("RSA n/e must be base64url, e at most 4 bytes")
		}
		nb := new(big.Int).SetBytes(n)
		eb := new(big.Int).SetBytes(e)
		if nb.BitLen() < 2048 || nb.BitLen() > 8192 {
			return nil, "", fmt.Errorf("RSA modulus %d bits, need 2048..8192", nb.BitLen())
		}
		if eb.Int64() < 3 || eb.Bit(0) == 0 {
			return nil, "", errors.New("RSA exponent must be odd and >= 3")
		}
		pub = &rsa.PublicKey{N: nb, E: int(eb.Int64())}
		thumb = `{"e":"` + k.E + `","kty":"RSA","n":"` + k.N + `"}`
	default:
		return nil, "", fmt.Errorf("alg %q not supported", clip(alg, 16))
	}
	// Các giá trị x, y, n, e đã qua b64() chặt nên chỉ gồm [A-Za-z0-9_-]: ghép thẳng vào
	// chuỗi JSON thumbprint là an toàn, không cần escape.
	sum := sha256.Sum256([]byte(thumb))
	return pub, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// Thumbprint tính jkt của một JWK công khai (dùng trong test và công cụ).
func Thumbprint(jwk json.RawMessage, alg string) (string, error) {
	_, jkt, err := parseJWK(jwk, alg)
	return jkt, err
}
