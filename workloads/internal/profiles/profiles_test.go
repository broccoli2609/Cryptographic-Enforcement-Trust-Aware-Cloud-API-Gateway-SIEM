package profiles

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"topic09-lab/workloads/internal/service"
)

type who struct{ sub, roles, dept string }

var (
	alice   = who{"alice-sub", "employee", "sales"}
	bob     = who{"bob-sub", "employee", "engineering"}
	carol   = who{"carol-sub", "employee,hr", "hr"}
	dave    = who{"dave-sub", "employee,manager", "sales"}
	aliceP0 = who{"alice-sub", "", ""}
)

const seed = `[
 {"user_id":"alice-sub","display_name":"Alice","dept":"sales","title":"Sales Executive","salary_band":"B2"},
 {"user_id":"bob-sub","display_name":"Bob","dept":"engineering","title":"Engineer","salary_band":"B3"},
 {"user_id":"carol-sub","display_name":"Carol","dept":"hr","title":"HR Specialist","salary_band":"B3"},
 {"user_id":"dave-sub","display_name":"Dave","dept":"sales","title":"Sales Manager","salary_band":"B4"}
]`

type env struct {
	h    http.Handler
	logs *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	s, err := NewStore([]byte(seed))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	return &env{logs: &logs, h: service.NewHandler("profile-api", "/profile", service.NewLogger(&logs, "profile-api"), s.Register)}
}

func (e *env) do(t *testing.T, u who, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-User", u.sub)
	if u.roles != "" {
		req.Header.Set("X-User-Roles", u.roles)
	}
	if u.dept != "" {
		req.Header.Set("X-User-Dept", u.dept)
	}
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	lines := strings.Split(strings.TrimSpace(e.logs.String()), "\n")
	var log map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &log); err != nil {
		t.Fatal(err)
	}
	return rr, log
}

func fields(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// API3 (đọc): chỉ hr thấy salary_band; người khác nhận đúng allow-list, log ghi trường bị ẩn.
func TestSalaryBandOnlyForHR(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name     string
		u        who
		path     string
		reason   string
		wantBand bool
	}{
		{"hr xem hồ sơ alice", carol, "/profile/alice-sub", "hr", true},
		{"manager cùng phòng xem alice", dave, "/profile/alice-sub", "dept_manager", false},
		{"alice xem /me", alice, "/profile/me", "self", false},
		{"carol (hr) xem /me", carol, "/profile/me", "self", true},
		{"alice xem chính mình qua {id}", alice, "/profile/alice-sub", "self", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr, log := e.do(t, c.u, "GET", c.path, "")
			if rr.Code != 200 {
				t.Fatalf("= %d %s", rr.Code, rr.Body)
			}
			m := fields(t, rr.Body.Bytes())
			_, has := m["salary_band"]
			if has != c.wantBand || len(m) != map[bool]int{true: 5, false: 4}[c.wantBand] {
				t.Fatalf("trường trả về %v, muốn salary_band=%v", m, c.wantBand)
			}
			if log["backend_object_authz"] != "allow" || log["backend_authz_reason"] != c.reason {
				t.Fatalf("log authz = %v/%v", log["backend_object_authz"], log["backend_authz_reason"])
			}
			wantRedacted := map[bool]string{true: "", false: "salary_band"}[c.wantBand]
			if log["backend_redacted_fields"] != wantRedacted {
				t.Fatalf("backend_redacted_fields = %v, muốn %q", log["backend_redacted_fields"], wantRedacted)
			}
			if !c.wantBand && strings.Contains(rr.Body.String(), "B2") {
				t.Fatal("lộ giá trị salary_band trong body")
			}
		})
	}
}

// Mức đối tượng: manager phòng khác — OPA cho qua (manager được GET /profile/{id}), backend chặn.
func TestManagerOtherDeptLooksLikeNotFound(t *testing.T) {
	e := newEnv(t)
	other, log := e.do(t, dave, "GET", "/profile/bob-sub", "")
	missing, _ := e.do(t, dave, "GET", "/profile/nobody", "")
	if other.Code != 404 || other.Body.String() != missing.Body.String() {
		t.Fatalf("hồ sơ phòng khác (%d %s) phải giống hồ sơ không tồn tại (%s)", other.Code, other.Body, missing.Body)
	}
	if log["backend_object_authz"] != "deny" || log["backend_authz_reason"] != "not_allowed" {
		t.Fatalf("log = %v", log)
	}
	if strings.Contains(e.logs.String(), "bob-sub") {
		t.Fatal("log chứa user_id")
	}
}

func TestHRUpdatesTitleAndSalaryBand(t *testing.T) {
	e := newEnv(t)
	rr, log := e.do(t, carol, "PATCH", "/profile/alice-sub", `{"title":"Senior Sales","salary_band":"B3"}`)
	if rr.Code != 200 {
		t.Fatalf("= %d %s", rr.Code, rr.Body)
	}
	if m := fields(t, rr.Body.Bytes()); m["title"] != "Senior Sales" || m["salary_band"] != "B3" {
		t.Fatalf("body = %v", m)
	}
	if log["backend_authz_reason"] != "hr_update" {
		t.Fatalf("log = %v", log)
	}
}

// API3 (ghi): mass assignment, trường cần role, tách nhiệm vụ. Mọi ca bị chặn đều không đổi dữ liệu.
func TestUpdateRejectsForbiddenProperties(t *testing.T) {
	cases := []struct {
		name   string
		u      who
		path   string
		body   string
		code   int
		reason string
	}{
		{"mass assignment: dept", carol, "/profile/alice-sub", `{"dept":"hr"}`, 400, "unknown_field"},
		{"mass assignment: user_id", carol, "/profile/alice-sub", `{"title":"x","user_id":"carol-sub"}`, 400, "unknown_field"},
		{"P0: alice tự nâng salary_band", aliceP0, "/profile/alice-sub", `{"salary_band":"B5"}`, 403, "forbidden_property"},
		{"P0: alice tự đổi title", aliceP0, "/profile/alice-sub", `{"title":"CEO"}`, 403, "forbidden_property"},
		{"hr tự sửa salary_band của mình", carol, "/profile/carol-sub", `{"salary_band":"B5"}`, 403, "self_salary_change"},
		{"manager phòng khác", dave, "/profile/bob-sub", `{"title":"x"}`, 404, "not_allowed"},
		{"không tồn tại", carol, "/profile/nobody", `{"title":"x"}`, 404, "not_found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			rr, log := e.do(t, c.u, "PATCH", c.path, c.body)
			if rr.Code != c.code || log["backend_object_authz"] != "deny" || log["backend_authz_reason"] != c.reason {
				t.Fatalf("= %d %v/%v, muốn %d deny/%s", rr.Code, log["backend_object_authz"], log["backend_authz_reason"], c.code, c.reason)
			}
			// Dữ liệu không đổi.
			rr, _ = e.do(t, carol, "GET", "/profile/alice-sub", "")
			if m := fields(t, rr.Body.Bytes()); m["salary_band"] != "B2" || m["title"] != "Sales Executive" || m["dept"] != "sales" {
				t.Fatalf("hồ sơ alice bị đổi: %v", m)
			}
			rr, _ = e.do(t, carol, "GET", "/profile/carol-sub", "")
			if m := fields(t, rr.Body.Bytes()); m["salary_band"] != "B3" {
				t.Fatalf("hồ sơ carol bị đổi: %v", m)
			}
		})
	}
}

func TestUpdateValidatesValues(t *testing.T) {
	e := newEnv(t)
	for name, body := range map[string]string{
		"rỗng":              `{}`,
		"salary_band lạ":    `{"salary_band":"B9"}`,
		"title xuống dòng":  `{"title":"a\nb"}`,
		"title rỗng":        `{"title":" "}`,
		"không phải object": `["title"]`,
	} {
		t.Run(name, func(t *testing.T) {
			if rr, _ := e.do(t, carol, "PATCH", "/profile/alice-sub", body); rr.Code != 400 {
				t.Fatalf("= %d %s, muốn 400", rr.Code, rr.Body)
			}
		})
	}
}

func TestNewStoreRejectsBadFixture(t *testing.T) {
	for name, s := range map[string]string{
		"band lạ":     `[{"user_id":"a","display_name":"A","dept":"sales","title":"T","salary_band":"X"}]`,
		"trùng":       `[{"user_id":"a","display_name":"A","dept":"sales","title":"T","salary_band":"B1"},{"user_id":"a","display_name":"A","dept":"sales","title":"T","salary_band":"B1"}]`,
		"dept lạ":     `[{"user_id":"a","display_name":"A","dept":"Sales!","title":"T","salary_band":"B1"}]`,
		"thiếu id":    `[{"display_name":"A","dept":"sales","title":"T","salary_band":"B1"}]`,
		"trường thừa": `[{"user_id":"a","display_name":"A","dept":"sales","title":"T","salary_band":"B1","ssn":"1"}]`,
	} {
		if _, err := NewStore([]byte(s)); err == nil {
			t.Errorf("%s: phải báo lỗi", name)
		}
	}
}
