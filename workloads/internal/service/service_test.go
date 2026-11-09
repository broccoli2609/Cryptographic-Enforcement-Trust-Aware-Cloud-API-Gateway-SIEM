package service

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func newTestHandler(buf *bytes.Buffer) http.Handler {
	return NewHandler("test-api", "/orders", NewLogger(buf, "test-api"), nil)
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

// Tuần 7: route không đăng ký trả 404 (trước đây 501 "chưa cài").
func TestUnknownRouteReturns404(t *testing.T) {
	var logs bytes.Buffer
	rr := httptest.NewRecorder()
	newTestHandler(&logs).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/orders/7", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /orders/7 (không có route) = %d, muốn 404", rr.Code)
	}
}

func TestHealthzRejectsPost(t *testing.T) {
	var logs bytes.Buffer
	rr := httptest.NewRecorder()
	newTestHandler(&logs).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	// Route "/" bắt mọi thứ còn lại nên POST /healthz rơi vào 404, không phải 200.
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
	req.Header.Set("X-User-Roles", "manager")
	req.Header.Set("X-User-Dept", "secretdept")
	newTestHandler(&logs).ServeHTTP(httptest.NewRecorder(), req)

	out := logs.String()
	for _, leak := range []string{"eyJ", "secret-payload", "12345", "user-identity-must-not-be-logged", "secretdept"} {
		if strings.Contains(out, leak) {
			t.Fatalf("log chứa %q, không được phép:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, `"route_template":"/"`) {
		t.Fatalf("log phải ghi route theo mẫu, nhận được:\n%s", out)
	}
	// Route không kiểm đối tượng vẫn có trường backend_object_authz (giá trị cố định) — schema ổn định cho SIEM.
	if !strings.Contains(out, `"backend_object_authz":"not_applicable"`) {
		t.Fatalf("log phải có backend_object_authz, nhận được:\n%s", out)
	}
}

func TestRequestIDIsTruncated(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-Id", strings.Repeat("a", 500))
	if got := len(requestID(req)); got != 64 {
		t.Fatalf("request_id dài %d, muốn tối đa 64", got)
	}
}

// Role/dept lạ bị bỏ (không lỗi): người gọi chỉ có thể ít quyền hơn, không bao giờ nhiều hơn.
func TestIdentityFromDropsUnsafeRolesAndDept(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-User", "sub-1")
	req.Header.Set("X-User-Roles", " employee ,MANAGER,hr;admin,,employee,"+strings.Repeat("a", 33)+",batch")
	req.Header.Set("X-User-Dept", "Sales")
	id, err := IdentityFrom(req)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(id.Roles, []string{"employee", "batch"}) {
		t.Fatalf("roles = %v, muốn [employee batch]", id.Roles)
	}
	if id.Dept != "" || id.Has("manager") || id.Has("hr") {
		t.Fatalf("dept/role lạ phải bị bỏ: %+v", id)
	}
}

// P0 chỉ gửi X-User: backend coi như không có role, không có dept.
func TestIdentityFromP0HasNoRoles(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-User", "sub-1")
	id, err := IdentityFrom(req)
	if err != nil || len(id.Roles) != 0 || id.Dept != "" {
		t.Fatalf("P0: muốn danh tính không role/dept, nhận %+v, %v", id, err)
	}
}

func TestReadJSONRejectsUnknownFieldAndHugeBody(t *testing.T) {
	var dst struct {
		Item string `json:"item"`
	}
	cases := map[string]struct {
		body string
		want error
	}{
		"trường lạ (mass assignment)": {`{"item":"pen","owner_id":"bob"}`, ErrUnknownField},
		"hai object liền nhau":        {`{"item":"a"}{"item":"b"}`, errors.New("invalid_body")},
		"không phải JSON":             {`item=pen`, errors.New("invalid_body")},
		"body quá 4 KiB":              {`{"item":"` + strings.Repeat("x", MaxBodyBytes) + `"}`, errors.New("invalid_body")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			err := ReadJSON(rr, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(c.body)), &dst)
			if err == nil || err.Error() != c.want.Error() {
				t.Fatalf("lỗi = %v, muốn %v", err, c.want)
			}
		})
	}
}
