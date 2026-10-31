package policy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const okResult = `{"result":{"allow":true,"policy_id":"topic09.authz","policy_version":"1.0.0","route":"orders.read","reason":"ok"},"decision_id":"d-1"}`

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL+"/v1/data/topic09/authz/decision", 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var aliceInput = Input{Method: "GET", Path: "/orders/1", Subject: Subject{Sub: "sub-alice", Roles: []string{"employee"}, Dept: "sales"}}

func TestDecideSendsInputAndParsesAllow(t *testing.T) {
	var got map[string]Input
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("muốn POST application/json, nhận %s %q", r.Method, r.Header.Get("Content-Type"))
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(okResult))
	})
	d, err := c.Decide(context.Background(), aliceInput)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allow || d.PolicyID != "topic09.authz" || d.PolicyVersion != "1.0.0" || d.Route != "orders.read" || d.Reason != "ok" || d.DecisionID != "d-1" {
		t.Fatalf("decision sai: %+v", d)
	}
	if got["input"].Subject.Sub != "sub-alice" || got["input"].Path != "/orders/1" {
		t.Fatalf("OPA nhận input sai: %+v", got)
	}
}

func TestDecideParsesDeny(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":{"allow":false,"policy_id":"topic09.authz","policy_version":"1.0.0","route":"orders.delete","reason":"role_not_allowed"}}`))
	})
	d, err := c.Decide(context.Background(), aliceInput)
	if err != nil || d.Allow || d.Reason != "role_not_allowed" {
		t.Fatalf("muốn deny role_not_allowed, nhận %+v err=%v", d, err)
	}
}

// Thiếu thuộc tính ABAC → bỏ khỏi JSON (để policy coi là "thiếu"), roles nil → [].
func TestDecideOmitsEmptyAttributesAndSendsEmptyRoles(t *testing.T) {
	var raw []byte
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		raw = buf[:n]
		_, _ = w.Write([]byte(okResult))
	})
	_, _ = c.Decide(context.Background(), Input{Method: "GET", Path: "/orders", Subject: Subject{Sub: "s"}})
	s := string(raw)
	if strings.Contains(s, `"dept"`) || strings.Contains(s, `"tier"`) || !strings.Contains(s, `"roles":[]`) {
		t.Fatalf("input gửi OPA = %s", s)
	}
}

// Mọi ca bất thường phải là error (→ Server từ chối). Mỗi ca một test con.
func TestDecideFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		h    http.HandlerFunc
		want error
	}{
		{"OPA trả {} (chưa nạp policy / sai đường dẫn)", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }, ErrUndefined},
		{"result null", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"result":null}`)) }, ErrUndefined},
		{"result thiếu allow", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"result":{"policy_id":"p","policy_version":"1","route":"","reason":"ok"}}`))
		}, ErrBadResponse},
		{"allow là chuỗi \"true\"", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"result":{"allow":"true","policy_id":"p","policy_version":"1","route":"","reason":"ok"}}`))
		}, ErrBadResponse},
		{"result là true trần (policy trả boolean, không có metadata)", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"result":true}`)) }, ErrBadResponse},
		{"thiếu policy_version", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"result":{"allow":true,"policy_id":"p","route":"","reason":"ok"}}`))
		}, ErrBadResponse},
		{"JSON hỏng", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"result":`)) }, ErrBadResponse},
		{"HTTP 500", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }, ErrUnavailable},
		{"HTTP 400 (input bị OPA từ chối)", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(400) }, ErrBadResponse},
		{"redirect sang chỗ khác (không theo)", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://evil.example/allow", http.StatusTemporaryRedirect)
		}, ErrBadResponse},
		{"body quá lớn", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"result":{"allow":true,"policy_id":"` + strings.Repeat("a", maxResponse) + `"}}`))
		}, ErrBadResponse},
		{"OPA treo quá timeout", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
			}
			_, _ = w.Write([]byte(okResult))
		}, ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, tc.h)
			d, err := c.Decide(context.Background(), aliceInput)
			if !errors.Is(err, tc.want) {
				t.Fatalf("muốn %v, nhận err=%v decision=%+v", tc.want, err, d)
			}
			if d.Allow {
				t.Fatal("có lỗi mà decision.Allow = true")
			}
		})
	}
}

func TestDecideFailsClosedWhenOPADown(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // OPA đã dừng: cổng đóng
	c, _ := NewClient(url+"/v1/data/topic09/authz/decision", 200*time.Millisecond)
	if _, err := c.Decide(context.Background(), aliceInput); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("muốn ErrUnavailable, nhận %v", err)
	}
}

func TestNewClientRejectsBadConfig(t *testing.T) {
	for _, u := range []string{"", "opa:8181", "ftp://opa/x", "http://user:pw@opa:8181/v1", "http://opa:8181/v1?x=1", "http:///v1"} {
		if _, err := NewClient(u, time.Second); err == nil {
			t.Errorf("URL %q phải bị từ chối khi khởi động", u)
		}
	}
	if _, err := NewClient("http://opa:8181/v1/data/x", 0); err == nil {
		t.Error("timeout 0 phải bị từ chối")
	}
}

// Biến môi trường HTTP_PROXY không được làm request tới OPA đi vòng qua proxy.
// (Không thử bằng server 127.0.0.1 được: Go vốn không dùng proxy cho loopback, test sẽ luôn xanh.)
func TestClientIgnoresProxyEnv(t *testing.T) {
	c, _ := NewClient("http://opa:8181/v1/data/topic09/authz/decision", time.Second)
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatal("Transport phải đặt Proxy = nil (không đọc HTTP_PROXY)")
	}
}
