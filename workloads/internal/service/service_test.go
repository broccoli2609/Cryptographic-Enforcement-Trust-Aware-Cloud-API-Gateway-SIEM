package service

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestHandler(buf *bytes.Buffer) http.Handler {
	return NewHandler("test-api", "/orders", NewLogger(buf, "test-api"))
}

func TestWhoAmIReturnsGatewayIdentity(t *testing.T) {
	var logs bytes.Buffer
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/orders/whoami", nil)
	req.Header.Set("X-User", "a6dd1608-1da4-43c5-bdcb-e80f368478f6")
	newTestHandler(&logs).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /orders/whoami = %d, muốn 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"user":"a6dd1608-1da4-43c5-bdcb-e80f368478f6"`) {
		t.Fatalf("body phải chứa danh tính từ X-User, nhận được: %s", rr.Body.String())
	}
}

// T5: request không đi qua gateway thì không có X-User — backend không được đoán danh tính.
func TestWhoAmIWithoutIdentityReturns401(t *testing.T) {
	var logs bytes.Buffer
	rr := httptest.NewRecorder()
	newTestHandler(&logs).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/orders/whoami", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("GET /orders/whoami thiếu X-User = %d, muốn 401", rr.Code)
	}
}

func TestWhoAmIRejectsOversizedIdentity(t *testing.T) {
	var logs bytes.Buffer
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/orders/whoami", nil)
	req.Header.Set("X-User", strings.Repeat("a", maxIdentityLen+1))
	newTestHandler(&logs).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("X-User dài %d ký tự = %d, muốn 400", maxIdentityLen+1, rr.Code)
	}
}

func TestHealthzReturns200(t *testing.T) {
	var logs bytes.Buffer
	rr := httptest.NewRecorder()
	newTestHandler(&logs).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, muốn 200", rr.Code)
	}
}

func TestUnknownRouteReturns501(t *testing.T) {
	var logs bytes.Buffer
	rr := httptest.NewRecorder()
	newTestHandler(&logs).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/orders/7", nil))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("GET /orders/7 = %d, muốn 501", rr.Code)
	}
}

func TestHealthzRejectsPost(t *testing.T) {
	var logs bytes.Buffer
	rr := httptest.NewRecorder()
	newTestHandler(&logs).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	// Route "/" bắt mọi thứ còn lại nên POST /healthz rơi vào 501, không phải 200.
	if rr.Code == http.StatusOK {
		t.Fatalf("POST /healthz không được trả 200")
	}
}

// SR-10: token trong header không bao giờ được xuất hiện trong log.
func TestLogsNeverContainTokens(t *testing.T) {
	var logs bytes.Buffer
	req := httptest.NewRequest(http.MethodGet, "/orders/12345", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.secret-payload.sig")
	req.Header.Set("DPoP", "eyJ0eXAiOiJkcG9wK2p3dCJ9.proof.sig")
	req.Header.Set("X-User", "user-identity-must-not-be-logged")
	newTestHandler(&logs).ServeHTTP(httptest.NewRecorder(), req)

	out := logs.String()
	for _, leak := range []string{"eyJ", "secret-payload", "12345", "user-identity-must-not-be-logged"} {
		if strings.Contains(out, leak) {
			t.Fatalf("log chứa %q, không được phép:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, `"route_template":"/"`) {
		t.Fatalf("log phải ghi route theo mẫu, nhận được:\n%s", out)
	}
}

func TestRequestIDIsTruncated(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-Id", strings.Repeat("a", 500))
	if got := len(requestID(req)); got != 64 {
		t.Fatalf("request_id dài %d, muốn tối đa 64", got)
	}
}
