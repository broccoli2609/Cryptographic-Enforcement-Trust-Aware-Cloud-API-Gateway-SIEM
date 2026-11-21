// Package vault ký digest bằng Vault Transit (khoá siem-digest, Ed25519) qua net/http — không thư
// viện Vault (quyết định 2026-11-13). Token đọc từ file Docker secret MỖI lần ký: đổi token
// (gen-vault-secrets.sh --rotate) không cần khởi động lại digester; token không bao giờ vào log.
//
// Sau khi Vault trả chữ ký, package tự XÁC MINH chữ ký bằng crypto/ed25519 với public key đã
// công bố (kms-public/siem-digest.json do vault-init ghi). Lệch → lỗi, không có digest: bắt được
// trường hợp Vault dev khởi động lại (khoá mới) mà file public key còn là khoá cũ — digest ký như
// vậy sẽ không ai kiểm được về sau.
package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Các lỗi phân loại — trở thành decision_reason của sự kiện digest_failed.
var (
	ErrUnavailable    = errors.New("vault_unavailable")   // không kết nối được / timeout / 5xx
	ErrDenied         = errors.New("vault_denied")        // 401/403: token sai, hết hạn, thiếu quyền
	ErrBadResponse    = errors.New("vault_bad_response")  // 200 nhưng nội dung sai dạng
	ErrPubKeyMismatch = errors.New("pubkey_mismatch")     // chữ ký không khớp public key đã công bố
	ErrNoToken        = errors.New("vault_token_missing") // không đọc được file token
	ErrNoPubKey       = errors.New("pubkey_missing")      // không đọc được file public key
)

var sigRe = regexp.MustCompile(`^vault:v([0-9]{1,9}):([A-Za-z0-9+/]+={0,2})$`)

// Signer gọi POST /v1/transit/sign/<Key>.
type Signer struct {
	Addr       string // http://vault:8200 — ghi cứng trong compose, không lấy từ dữ liệu
	Key        string // siem-digest
	TokenFile  string // /run/secrets/vault_token_digester
	PubKeyFile string // /kms-public/siem-digest.json
	Client     *http.Client
}

// NewClient — http.Client cho Vault: timeout ngắn, không proxy, không theo redirect.
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: nil, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Signature — kết quả một lần ký đã được xác minh.
type Signature struct {
	Value      string // vault:vN:<base64> — nguyên văn từ Vault
	KeyVersion int
	PublicKey  string // base64 của khoá công khai Ed25519 version đó (32 byte)
}

// Sign ký msg; chỉ trả nil error khi chữ ký đã được xác minh bằng public key đã công bố.
func (s *Signer) Sign(ctx context.Context, msg []byte) (Signature, error) {
	tok, err := os.ReadFile(s.TokenFile)
	if err != nil || len(bytes.TrimSpace(tok)) == 0 {
		return Signature{}, ErrNoToken
	}
	body, _ := json.Marshal(map[string]string{"input": base64.StdEncoding.EncodeToString(msg)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.Addr, "/")+"/v1/transit/sign/"+s.Key, bytes.NewReader(body))
	if err != nil {
		return Signature{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	req.Header.Set("X-Vault-Token", string(bytes.TrimSpace(tok)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return Signature{}, ErrUnavailable // không kèm err gốc: URL thì không bí mật, nhưng giữ log gọn
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Signature{}, ErrDenied
	case resp.StatusCode != http.StatusOK:
		return Signature{}, ErrUnavailable
	}
	var out struct {
		Data struct {
			Signature  string `json:"signature"`
			KeyVersion int    `json:"key_version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Signature{}, ErrBadResponse
	}
	m := sigRe.FindStringSubmatch(out.Data.Signature)
	if m == nil {
		return Signature{}, ErrBadResponse
	}
	ver, _ := strconv.Atoi(m[1])
	if out.Data.KeyVersion != 0 && out.Data.KeyVersion != ver {
		return Signature{}, ErrBadResponse
	}
	sig, err := base64.StdEncoding.DecodeString(m[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Signature{}, ErrBadResponse
	}
	pub, err := PublicKey(s.PubKeyFile, ver)
	if err != nil {
		return Signature{}, err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return Signature{}, ErrPubKeyMismatch
	}
	return Signature{Value: out.Data.Signature, KeyVersion: ver, PublicKey: base64.StdEncoding.EncodeToString(pub)}, nil
}

// PublicKey đọc khoá công khai version ver từ file JSON của `vault read -format=json transit/keys/<k>`.
func PublicKey(path string, ver int) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrNoPubKey
	}
	var f struct {
		Data struct {
			Type string `json:"type"`
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &f); err != nil || f.Data.Type != "ed25519" {
		return nil, ErrNoPubKey
	}
	k, ok := f.Data.Keys[strconv.Itoa(ver)]
	if !ok {
		return nil, ErrPubKeyMismatch // Vault ký bằng version mà file chưa có
	}
	b, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrNoPubKey
	}
	return ed25519.PublicKey(b), nil
}
