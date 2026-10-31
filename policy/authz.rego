# Policy phân quyền của gateway Topic 09 — OPA là PDP (Policy Decision Point), tuần 5.
#
# auth-svc (PEP) gọi sau khi đã kiểm JWT (và DPoP ở P2):
#   POST http://opa:8181/v1/data/topic09/authz/decision   body {"input": {...}}
#
# input (chỉ lấy từ claim của token ĐÃ KIỂM, không lấy từ header client gửi):
#   {
#     "method":  "GET",                 # method HTTP (Envoy đưa về chữ hoa)
#     "path":    "/orders/123",         # đường dẫn đã chuẩn hoá, KHÔNG có query string
#     "subject": {
#       "sub": "…", "client_id": "web-app",
#       "roles": ["employee"],          # realm_access.roles
#       "dept": "sales", "tier": "standard"
#     }
#   }
#
# Kết quả luôn là một object có policy_id, policy_version, route, reason (luật policy.md):
#   {"allow": false, "policy_id": "topic09.authz", "policy_version": "1.0.0",
#    "route": "orders.delete", "reason": "role_not_allowed"}
#
# Đổi luật thì tăng policy_version — auth-svc ghi số này vào log của mỗi quyết định,
# nên khi điều tra (hunt H4) biết quyết định nào dùng bản policy nào.
package topic09.authz

policy_id := "topic09.authz"

policy_version := "1.0.0"

# ---------------------------------------------------------------- Bảng route (RBAC)
# Khớp từ trên xuống: route ĐẦU TIÊN khớp cả method lẫn path được dùng (giống bảng route
# của Envoy). Vì vậy route cụ thể (/orders/export) phải đứng trước route có tham số
# (/orders/{id}). Request không khớp route nào → từ chối ("no_matching_route").
#
# roles:   tập role (realm_access.roles) được gọi route này — RBAC.
# require: thuộc tính bắt buộc của người gọi — ABAC. Ví dụ {"dept": {"sales"}} nghĩa là
#          claim dept phải nằm trong tập {"sales"}. Thiếu claim cũng là không đạt.
#
# Gateway chỉ quyết định ở mức "chức năng" (route + method). Kiểm "đối tượng" (đơn hàng
# này có phải của alice không — owner_id) và "thuộc tính" (salary_band chỉ HR xem) là việc
# của backend ở tuần 7 (SR-06): gateway không biết đơn hàng 123 là của ai.
routes := [
	{"id": "orders.whoami", "method": "GET", "path": "/orders/whoami", "roles": {"employee", "manager", "hr", "batch"}},
	# ABAC 2 (tier): xuất báo cáo đơn hàng — tính năng của gói premium.
	{"id": "orders.export", "method": "GET", "path": "/orders/export", "roles": {"employee", "manager"}, "require": {"tier": {"premium"}}},
	{"id": "orders.list", "method": "GET", "path": "/orders", "roles": {"employee", "manager", "batch"}},
	# ABAC 1 (dept): chỉ người thuộc phòng sales được tạo đơn hàng.
	{"id": "orders.create", "method": "POST", "path": "/orders", "roles": {"employee", "manager"}, "require": {"dept": {"sales"}}},
	{"id": "orders.read", "method": "GET", "path": "/orders/{id}", "roles": {"employee", "manager"}},
	# Chức năng quản trị: chỉ manager — mục tiêu của test BFLA (tuần 7).
	{"id": "orders.delete", "method": "DELETE", "path": "/orders/{id}", "roles": {"manager"}},
	{"id": "profile.whoami", "method": "GET", "path": "/profile/whoami", "roles": {"employee", "manager", "hr", "batch"}},
	{"id": "profile.me", "method": "GET", "path": "/profile/me", "roles": {"employee"}},
	{"id": "profile.read", "method": "GET", "path": "/profile/{id}", "roles": {"hr", "manager"}},
	{"id": "profile.update", "method": "PATCH", "path": "/profile/{id}", "roles": {"hr"}},
]

# Giá trị hợp lệ của một tham số {id} trong đường dẫn: chữ, số, "-", "_", tối đa 64 ký tự.
# Chuỗi lạ (dấu chấm, %, rỗng, quá dài) không khớp route nào → bị từ chối.
param_pattern := `^[A-Za-z0-9_-]{1,64}$`

# ---------------------------------------------------------------- Chọn route
# Chỉ số nhỏ nhất trong các route khớp = route đầu tiên khớp.
# Không route nào khớp → tập rỗng → min() không xác định → route không xác định → từ chối.
route_index := min({i |
	some i, r in routes
	r.method == input.method
	path_match(r.path, input.path)
})

route := routes[route_index]

# path_match so từng đoạn giữa hai dấu "/". "/orders/123" → ["", "orders", "123"].
path_match(pattern, path) if {
	is_string(path)
	want := split(pattern, "/")
	got := split(path, "/")
	count(want) == count(got)
	every i, seg in want {
		segment_match(seg, got[i])
	}
}

segment_match(seg, value) if {
	not is_param(seg)
	seg == value
}

segment_match(seg, value) if {
	is_param(seg)
	regex.match(param_pattern, value)
}

is_param(seg) if {
	startswith(seg, "{")
	endswith(seg, "}")
}

# ---------------------------------------------------------------- Luật
# RBAC: người gọi có ít nhất một role nằm trong tập role của route.
role_ok if {
	some role in input.subject.roles
	role in route.roles
}

# ABAC: tên các thuộc tính KHÔNG đạt. object.get(..., {}) — route không có "require" thì
# tập này rỗng. Thiếu claim (input.subject[attr] không xác định) cũng tính là không đạt.
#
# BẪY ĐÃ GẶP (opa test bắt được): viết thẳng `not input.subject[attr] in allowed` thì OPA
# tách thành `x := input.subject[attr]; not x in allowed` — phép gán nằm NGOÀI "not", nên
# thiếu claim làm cả luật không xác định → abac_failed rỗng → CHO QUA (fail open).
# Đưa cả phép so sánh vào hàm attr_ok để "not" bao trọn: thiếu claim → attr_ok không xác
# định → not attr_ok đúng → bị ghi là không đạt.
abac_failed contains attr if {
	some attr, allowed in object.get(route, "require", {})
	not attr_ok(attr, allowed)
}

attr_ok(attr, allowed) if input.subject[attr] in allowed

# Mặc định TỪ CHỐI (luật policy.md). Chỉ cho qua khi có route, đúng role, đủ thuộc tính.
default allow := false

allow if {
	route
	role_ok
	count(abac_failed) == 0
}

# Lý do: thứ tự kiểm giống thứ tự đọc luật — route → role → thuộc tính.
# Chuỗi "else" dừng ở nhánh đầu tiên có thân đúng, nên reason luôn có đúng một giá trị.
reason := "ok" if {
	allow
} else := "no_matching_route" if {
	not route
} else := "role_not_allowed" if {
	not role_ok
} else := concat("_", ["abac", min(abac_failed)]) if {
	count(abac_failed) > 0
} else := "denied"

default route_id := ""

route_id := route.id

# ---------------------------------------------------------------- Kết quả cho auth-svc
# Luôn xác định (allow, reason, route_id đều có giá trị mặc định), nên OPA không bao giờ trả
# "result" rỗng cho đường dẫn này. auth-svc vẫn coi thiếu "result" là lỗi → từ chối (SR-11).
decision := {
	"allow": allow,
	"policy_id": policy_id,
	"policy_version": policy_version,
	"route": route_id,
	"reason": reason,
}
