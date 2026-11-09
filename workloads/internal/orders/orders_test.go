package orders

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"topic09-lab/workloads/internal/service"
)

// Danh tính giả như gateway gắn (X-User, X-User-Roles, X-User-Dept).
type who struct{ sub, roles, dept string }

var (
	alice  = who{"alice-sub", "employee", "sales"}
	bob    = who{"bob-sub", "employee", "engineering"}
	carol  = who{"carol-sub", "employee,hr", "hr"}
	dave   = who{"dave-sub", "employee,manager", "sales"}
	batch  = who{"batch-sub", "batch", ""}
	daveP0 = who{"dave-sub", "", ""} // P0 chỉ gửi X-User
)

const seed = `[
 {"id":"o1","owner_id":"alice-sub","dept":"sales","item":"Laptop","quantity":1,"status":"open","created_at":"2026-11-01T00:00:00Z"},
 {"id":"o2","owner_id":"bob-sub","dept":"engineering","item":"Dock","quantity":2,"status":"open","created_at":"2026-11-01T00:00:00Z"},
 {"id":"o3","owner_id":"alice-sub","dept":"sales","item":"Cards","quantity":3,"status":"shipped","created_at":"2026-11-01T00:00:00Z"},
 {"id":"o4","owner_id":"dave-sub","dept":"sales","item":"Venue","quantity":1,"status":"open","created_at":"2026-11-01T00:00:00Z"},
 {"id":"o5","owner_id":"bob-sub","dept":"","item":"Legacy","quantity":1,"status":"open","created_at":"2026-11-01T00:00:00Z"}
]`

type env struct {
	store *Store
	h     http.Handler
	logs  *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	s, err := NewStore([]byte(seed))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	s.newID = func() (string, error) { n++; return fmt.Sprintf("new-%d", n), nil }
	var logs bytes.Buffer
	return &env{store: s, logs: &logs, h: service.NewHandler("orders-api", "/orders", service.NewLogger(&logs, "orders-api"), s.Register)}
}

// do gửi request; trả response và dòng log cuối (đã parse).
func (e *env) do(t *testing.T, u who, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if u.sub != "" {
		req.Header.Set("X-User", u.sub)
	}
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
		t.Fatalf("log không phải JSON: %v", err)
	}
	return rr, log
}

func wantAuthz(t *testing.T, log map[string]any, decision, reason string) {
	t.Helper()
	if log["backend_object_authz"] != decision || log["backend_authz_reason"] != reason {
		t.Fatalf("log: backend_object_authz=%v reason=%v, muốn %s/%s", log["backend_object_authz"], log["backend_authz_reason"], decision, reason)
	}
}

func ids(t *testing.T, body []byte) string {
	t.Helper()
	var out struct {
		Orders []Order `json:"orders"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, o := range out.Orders {
		s = append(s, o.ID)
	}
	return strings.Join(s, ",")
}

// Bảng luật đọc/xoá — kiểm thẳng hàm quyết định.
func TestObjectLevelRules(t *testing.T) {
	ident := func(u who) service.Identity {
		id := service.Identity{Subject: u.sub, Dept: u.dept}
		if u.roles != "" {
			id.Roles = strings.Split(u.roles, ",")
		}
		return id
	}
	o1 := Order{ID: "o1", OwnerID: "alice-sub", Dept: "sales"}
	o2 := Order{ID: "o2", OwnerID: "bob-sub", Dept: "engineering"}
	o5 := Order{ID: "o5", OwnerID: "bob-sub", Dept: ""}
	cases := []struct {
		name       string
		caller     who
		order      Order
		read, del  bool
		readReason string
	}{
		{"chủ đơn đọc đơn của mình", alice, o1, true, false, "owner"},
		{"BOLA: alice đọc đơn của bob", alice, o2, false, false, "not_owner"},
		{"manager cùng phòng", dave, o1, true, true, "dept_manager"},
		{"manager khác phòng", dave, o2, false, false, "not_owner"},
		{"hr không có quyền với đơn", carol, o1, false, false, "not_owner"},
		{"P0: dave không có role/dept", daveP0, o1, false, false, "not_owner"},
		{"dept rỗng không khớp dept rỗng", who{"m", "manager", ""}, o5, false, false, "not_owner"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			read, why := canRead(ident(c.caller), c.order)
			if read != c.read || why != c.readReason || deptManager(ident(c.caller), c.order) != c.del {
				t.Fatalf("đọc=%v(%s) xoá=%v, muốn đọc=%v(%s) xoá=%v", read, why, deptManager(ident(c.caller), c.order), c.read, c.readReason, c.del)
			}
		})
	}
}

func TestOwnerReadsOwnOrder(t *testing.T) {
	e := newEnv(t)
	rr, log := e.do(t, alice, "GET", "/orders/o1", "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"id":"o1"`) {
		t.Fatalf("alice GET o1 = %d %s", rr.Code, rr.Body)
	}
	wantAuthz(t, log, "allow", "owner")
	if log["route_template"] != "GET /orders/{id}" {
		t.Fatalf("route_template = %v", log["route_template"])
	}
}

// API1 BOLA: alice đổi ID sang đơn của bob. Gateway (OPA) cho qua vì employee được GET /orders/{id};
// backend phải chặn, và response KHÔNG được khác ca "đơn không tồn tại".
func TestBOLAOtherUsersOrderLooksLikeNotFound(t *testing.T) {
	e := newEnv(t)
	other, log := e.do(t, alice, "GET", "/orders/o2", "")
	wantAuthz(t, log, "deny", "not_owner")
	missing, log2 := e.do(t, alice, "GET", "/orders/o999", "")
	wantAuthz(t, log2, "deny", "not_found")
	if other.Code != 404 || missing.Code != 404 || other.Body.String() != missing.Body.String() {
		t.Fatalf("đơn người khác (%d %q) phải giống hệt đơn không tồn tại (%d %q)", other.Code, other.Body, missing.Code, missing.Body)
	}
	if strings.Contains(other.Body.String(), "Dock") {
		t.Fatal("lộ dữ liệu đơn của bob")
	}
	// SR-10: log không có ID đơn, không có danh tính.
	for _, leak := range []string{"o2", "o999", "alice-sub", "sales"} {
		if strings.Contains(e.logs.String(), leak) {
			t.Fatalf("log chứa %q:\n%s", leak, e.logs)
		}
	}
}

func TestManagerReadsOnlyOwnDept(t *testing.T) {
	e := newEnv(t)
	rr, log := e.do(t, dave, "GET", "/orders/o1", "")
	if rr.Code != 200 {
		t.Fatalf("dave (manager sales) đọc đơn sales = %d", rr.Code)
	}
	wantAuthz(t, log, "allow", "dept_manager")
	rr, log = e.do(t, dave, "GET", "/orders/o2", "")
	if rr.Code != 404 {
		t.Fatalf("dave đọc đơn engineering = %d, muốn 404", rr.Code)
	}
	wantAuthz(t, log, "deny", "not_owner")
}

func TestDeleteRequiresDeptManager(t *testing.T) {
	e := newEnv(t)
	// alice là chủ o1 nhưng không phải manager: đọc được nên trả 403 (giấu không có ý nghĩa).
	rr, log := e.do(t, alice, "DELETE", "/orders/o1", "")
	if rr.Code != 403 {
		t.Fatalf("alice xoá đơn của mình = %d, muốn 403", rr.Code)
	}
	wantAuthz(t, log, "deny", "not_dept_manager")
	// P0: dave không có role → như người thường. o4 là đơn của dave nên 403, không phải 404.
	rr, log = e.do(t, daveP0, "DELETE", "/orders/o4", "")
	if rr.Code != 403 {
		t.Fatalf("P0 dave xoá đơn của mình = %d, muốn 403", rr.Code)
	}
	wantAuthz(t, log, "deny", "not_dept_manager")
	// Manager khác phòng: không đọc được → 404.
	rr, log = e.do(t, dave, "DELETE", "/orders/o2", "")
	if rr.Code != 404 {
		t.Fatalf("dave xoá đơn engineering = %d, muốn 404", rr.Code)
	}
	wantAuthz(t, log, "deny", "not_owner")
	// Đơn vẫn còn sau các lần bị chặn.
	if rr, _ := e.do(t, alice, "GET", "/orders/o1", ""); rr.Code != 200 {
		t.Fatal("o1 phải còn nguyên")
	}
	// Manager cùng phòng xoá được; sau đó đơn biến mất.
	rr, log = e.do(t, dave, "DELETE", "/orders/o3", "")
	if rr.Code != 204 {
		t.Fatalf("dave xoá đơn sales = %d, muốn 204", rr.Code)
	}
	wantAuthz(t, log, "allow", "dept_manager")
	if rr, log := e.do(t, alice, "GET", "/orders/o3", ""); rr.Code != 404 || log["backend_authz_reason"] != "not_found" {
		t.Fatalf("o3 đã xoá: %d %v", rr.Code, log["backend_authz_reason"])
	}
}

func TestListIsFilteredByServer(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		u      who
		want   string
		reason string
	}{
		{alice, "o1,o3", "filtered"},
		{bob, "o2,o5", "filtered"},
		{dave, "o1,o3,o4", "filtered"}, // đơn của mình + đơn sales (manager)
		{carol, "", "filtered"},
		{batch, "o1,o2,o3,o4,o5", "batch_all"},
		{daveP0, "o4", "filtered"},
	} {
		rr, log := e.do(t, c.u, "GET", "/orders", "")
		if rr.Code != 200 || ids(t, rr.Body.Bytes()) != c.want {
			t.Fatalf("%s GET /orders = %d [%s], muốn [%s]", c.u.sub, rr.Code, ids(t, rr.Body.Bytes()), c.want)
		}
		wantAuthz(t, log, "allow", c.reason)
	}
	// Danh sách rỗng là [] chứ không phải null.
	rr, _ := e.do(t, carol, "GET", "/orders", "")
	if !strings.Contains(rr.Body.String(), `"orders":[]`) {
		t.Fatalf("carol: %s", rr.Body)
	}
}

func TestExportUsesSameFilter(t *testing.T) {
	e := newEnv(t)
	rr, _ := e.do(t, dave, "GET", "/orders/export", "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"count":3`) || !strings.Contains(rr.Body.String(), `"total_quantity":5`) {
		t.Fatalf("dave export = %d %s", rr.Code, rr.Body)
	}
}

// Chủ đơn = người gọi; client không gán được owner_id/dept/status (mass assignment).
func TestCreateTakesOwnerFromIdentity(t *testing.T) {
	e := newEnv(t)
	rr, log := e.do(t, alice, "POST", "/orders", `{"item":"Pen","quantity":2}`)
	if rr.Code != 201 {
		t.Fatalf("tạo đơn = %d %s", rr.Code, rr.Body)
	}
	var o Order
	_ = json.Unmarshal(rr.Body.Bytes(), &o)
	if o.OwnerID != "alice-sub" || o.Dept != "sales" || o.Status != "open" || o.ID != "new-1" {
		t.Fatalf("đơn mới sai: %+v", o)
	}
	wantAuthz(t, log, "allow", "owner_is_caller")

	for name, body := range map[string]string{
		"owner_id":    `{"item":"Pen","quantity":1,"owner_id":"bob-sub"}`,
		"dept":        `{"item":"Pen","quantity":1,"dept":"engineering"}`,
		"status":      `{"item":"Pen","quantity":1,"status":"shipped"}`,
		"OwnerID hoa": `{"item":"Pen","quantity":1,"OWNER_ID":"bob-sub"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rr, log := e.do(t, alice, "POST", "/orders", body)
			if rr.Code != 400 || !strings.Contains(rr.Body.String(), "unknown_field") {
				t.Fatalf("= %d %s, muốn 400 unknown_field", rr.Code, rr.Body)
			}
			wantAuthz(t, log, "deny", "unknown_field")
		})
	}
	for name, body := range map[string]string{
		"quantity 0":      `{"item":"Pen","quantity":0}`,
		"quantity lớn":    `{"item":"Pen","quantity":1001}`,
		"item rỗng":       `{"item":"   ","quantity":1}`,
		"item xuống dòng": `{"item":"Pen\n{\"forged\":1}","quantity":1}`,
		"item quá dài":    `{"item":"` + strings.Repeat("x", 101) + `","quantity":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			if rr, _ := e.do(t, alice, "POST", "/orders", body); rr.Code != 400 {
				t.Fatalf("= %d, muốn 400", rr.Code)
			}
		})
	}
	// Chỉ có đúng 1 đơn mới được tạo.
	if rr, _ := e.do(t, batch, "GET", "/orders", ""); ids(t, rr.Body.Bytes()) != "new-1,o1,o2,o3,o4,o5" {
		t.Fatalf("store: %s", ids(t, rr.Body.Bytes()))
	}
}

func TestCreateStopsAtCapacity(t *testing.T) {
	e := newEnv(t)
	for i := len(e.store.orders); i < maxOrders; i++ {
		e.store.orders[fmt.Sprintf("fill-%d", i)] = Order{ID: "x"}
	}
	if rr, _ := e.do(t, alice, "POST", "/orders", `{"item":"Pen","quantity":1}`); rr.Code != 503 {
		t.Fatalf("store đầy = %d, muốn 503", rr.Code)
	}
}

// T5: không có X-User (gọi vòng qua gateway) → 401, ghi deny vào log.
func TestBusinessRoutesRequireIdentity(t *testing.T) {
	e := newEnv(t)
	for _, c := range [][2]string{{"GET", "/orders"}, {"GET", "/orders/o1"}, {"DELETE", "/orders/o1"}, {"POST", "/orders"}, {"GET", "/orders/export"}} {
		rr, log := e.do(t, who{}, c[0], c[1], `{}`)
		if rr.Code != 401 {
			t.Fatalf("%s %s không X-User = %d, muốn 401", c[0], c[1], rr.Code)
		}
		wantAuthz(t, log, "deny", "missing_identity")
	}
}

func TestNewStoreRejectsBadFixture(t *testing.T) {
	for name, s := range map[string]string{
		"trùng ID":      `[{"id":"a","owner_id":"x","item":"i","quantity":1},{"id":"a","owner_id":"y","item":"i","quantity":1}]`,
		"thiếu owner":   `[{"id":"a","item":"i","quantity":1}]`,
		"ID sai mẫu":    `[{"id":"a/b","owner_id":"x","item":"i","quantity":1}]`,
		"trường lạ":     `[{"id":"a","owner_id":"x","item":"i","quantity":1,"salary":1}]`,
		"quantity âm":   `[{"id":"a","owner_id":"x","item":"i","quantity":-1}]`,
		"không phải []": `{}`,
	} {
		if _, err := NewStore([]byte(s)); err == nil {
			t.Errorf("%s: phải báo lỗi", name)
		}
	}
}
