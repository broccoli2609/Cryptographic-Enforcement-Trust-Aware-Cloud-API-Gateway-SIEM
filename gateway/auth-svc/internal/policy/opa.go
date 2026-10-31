// Package policy hỏi OPA (PDP) xem một request đã xác thực có được phép hay không (tuần 5, SR-06).
//
// auth-svc là PEP: tự kiểm token, rồi gửi cho OPA những gì ĐÃ KIỂM (claim của token, method,
// đường dẫn) và làm theo quyết định. Mọi bất thường khi hỏi OPA — mất kết nối, timeout, mã
// HTTP lạ, JSON hỏng, thiếu "result" — đều trả error, và Server biến error thành TỪ CHỐI
// (SR-11 fail closed). Không có nhánh nào "đoán" là được phép.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Input là toàn bộ dữ liệu OPA nhận — khớp với chú thích đầu file policy/authz.rego.
type Input struct {
	Method  string  `json:"method"`
	Path    string  `json:"path"` // đã bỏ query string
	Subject Subject `json:"subject"`
}

// Subject chỉ chứa claim của access token ĐÃ kiểm chữ ký — không lấy từ header client gửi
// (luật policy.md). Thuộc tính rỗng thì bỏ hẳn khỏi JSON để luật ABAC coi là "thiếu".
type Subject struct {
	Sub      string   `json:"sub"`
	ClientID string   `json:"client_id,omitempty"`
	Roles    []string `json:"roles"`
	Dept     string   `json:"dept,omitempty"`
	Tier     string   `json:"tier,omitempty"`
}

// Decision là kết quả của data.topic09.authz.decision.
type Decision struct {
	Allow         bool
	PolicyID      string
	PolicyVersion string
	Route         string // id route theo mẫu, ví dụ "orders.read" — an toàn để ghi log
	Reason        string
	DecisionID    string // decision_id của OPA, để nối log auth-svc với decision log của OPA
}

// Các lỗi Decide có thể trả. Server ghi tên lỗi vào log làm lý do từ chối.
var (
	ErrUnavailable = errors.New("policy_unavailable")  // không gọi được OPA / timeout / 5xx
	ErrBadResponse = errors.New("policy_bad_response") // OPA trả nội dung không hợp lệ
	ErrUndefined   = errors.New("policy_undefined")    // OPA chưa nạp policy: "result" không có
)

// maxResponse: decision chỉ vài trăm byte. Body lớn hơn là bất thường → không đọc tiếp (T10).
const maxResponse = 64 << 10

// Client gọi REST API của OPA: POST <url> {"input": …}.
type Client struct {
	url  string
	http *http.Client
}

// NewClient kiểm URL ngay lúc khởi động (fail fast). URL ghi cứng trong cấu hình, giống JWKS_URL.
func NewClient(rawURL string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return nil, fmt.Errorf("policy: OPA url %q không hợp lệ", rawURL)
	}
	if timeout <= 0 {
		return nil, errors.New("policy: timeout phải > 0")
	}
	return &Client{
		url: u.String(),
		http: &http.Client{
			Timeout: timeout,
			// Không theo redirect: quyết định phải đến đúng từ OPA đã cấu hình.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				// Proxy: nil — KHÔNG dùng HTTP_PROXY trong biến môi trường. Nếu dùng, ai đặt được
				// biến môi trường sẽ chen được vào giữa auth-svc và OPA để sửa quyết định.
				Proxy:               nil,
				MaxIdleConns:        16,
				MaxIdleConnsPerHost: 16,
				IdleConnTimeout:     60 * time.Second,
				TLSHandshakeTimeout: timeout,
			},
		},
	}, nil
}

// Decide hỏi OPA. Chỉ trả error == nil khi OPA trả 200 và "result" là một object đủ trường.
func (c *Client) Decide(ctx context.Context, in Input) (Decision, error) {
	if in.Subject.Roles == nil {
		in.Subject.Roles = []string{} // gửi [] thay vì null cho rõ ràng; policy coi cả hai là "không có role"
	}
	body, err := json.Marshal(struct {
		Input Input `json:"input"`
	}{in})
	if err != nil {
		return Decision{}, fmt.Errorf("%w: encode input", ErrBadResponse)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return Decision{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Decision{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return Decision{}, fmt.Errorf("%w: read body: %v", ErrUnavailable, err)
	}
	switch {
	case resp.StatusCode >= 500:
		return Decision{}, fmt.Errorf("%w: HTTP %d", ErrUnavailable, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return Decision{}, fmt.Errorf("%w: HTTP %d", ErrBadResponse, resp.StatusCode)
	case len(raw) > maxResponse:
		return Decision{}, fmt.Errorf("%w: body quá lớn", ErrBadResponse)
	}

	// Con trỏ để phân biệt "không có trường" với giá trị rỗng/false.
	var out struct {
		Result *struct {
			Allow         *bool   `json:"allow"`
			PolicyID      *string `json:"policy_id"`
			PolicyVersion *string `json:"policy_version"`
			Route         *string `json:"route"`
			Reason        *string `json:"reason"`
		} `json:"result"`
		DecisionID string `json:"decision_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Decision{}, fmt.Errorf("%w: json: %v", ErrBadResponse, err)
	}
	// OPA trả 200 {} khi đường dẫn policy không tồn tại (chưa nạp policy, gõ sai package).
	// Đây là bẫy fail-open phổ biến: code chỉ đọc result.allow sẽ thấy false/nil và có thể
	// xử lý sai. Ở đây "không có result" là lỗi riêng, và lỗi thì luôn bị từ chối.
	if out.Result == nil {
		return Decision{}, ErrUndefined
	}
	r := out.Result
	if r.Allow == nil || r.PolicyID == nil || *r.PolicyID == "" || r.PolicyVersion == nil ||
		*r.PolicyVersion == "" || r.Reason == nil || *r.Reason == "" || r.Route == nil {
		return Decision{}, fmt.Errorf("%w: thiếu trường trong result", ErrBadResponse)
	}
	return Decision{
		Allow:         *r.Allow,
		PolicyID:      clip(*r.PolicyID, 64),
		PolicyVersion: clip(*r.PolicyVersion, 32),
		Route:         clip(*r.Route, 64),
		Reason:        clip(*r.Reason, 64),
		DecisionID:    clip(out.DecisionID, 64),
	}, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
