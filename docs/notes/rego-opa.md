# Ghi chú tuần 5 — OPA và Rego (đọc kèm `policy/authz.rego`)

Nguồn: tài liệu OPA (Policy Language, Policy Testing, Decision Logs, REST API), Styra Academy
"OPA Policy Authoring", OPA Playground. OPA trong lab: 1.21.4 (Rego v1 — `if`, `contains`,
`in`, `every` là cú pháp mặc định, không cần `import rego.v1`).

## 1. OPA làm gì trong lab

```
client ──► Envoy (PEP) ──ext_authz──► auth-svc (PEP) ──POST /v1/data/topic09/authz/decision──► OPA (PDP)
                                          │ kiểm token trước                                    │ đọc policy/*.rego
                                          ◄────────── {"allow": …, "reason": …, "policy_version": …}
```

- **PEP** (Policy Enforcement Point) chặn/cho qua; **PDP** (Policy Decision Point) chỉ trả lời
  "có được không, vì sao". Tách hai vai để đổi luật mà không build lại code (SR-06).
- OPA không biết token là gì: auth-svc kiểm chữ ký xong mới đưa **claim đã kiểm** vào `input`.
  Nếu đưa header client gửi (`X-User-Roles`) vào `input`, ai cũng tự cấp quyền được.
- OPA trả lời qua REST API **không xác thực** → không `ports:`, mạng riêng chỉ có auth-svc.

## 2. Mô hình dữ liệu

| Tên | Là gì | Trong lab |
|---|---|---|
| `input` | dữ liệu của MỘT câu hỏi, gửi kèm request | method, path, subject (sub, roles, dept, tier) |
| `data` | mọi thứ OPA đã nạp: policy (`data.topic09.authz.*`) + file dữ liệu | `data.topic09.authz.decision`, `data.system.log.mask` |
| package | "thư mục" chứa luật; `package topic09.authz` ⇒ đường dẫn REST `/v1/data/topic09/authz/...` | |

## 3. Năm kiểu luật dùng trong `authz.rego`

| Kiểu | Ví dụ trong file | Ý nghĩa |
|---|---|---|
| Hằng | `policy_version := "1.0.0"` | luôn có giá trị |
| Luật đúng/sai có `default` | `default allow := false` + `allow if { … }` | thân đúng → `true`; không thân nào đúng → giá trị `default` |
| Luật giá trị có `else` | `reason := "ok" if {…} else := "no_matching_route" if {…} else := …` | lấy nhánh **đầu tiên** có thân đúng, như if/else if |
| Tập (partial set) | `abac_failed contains attr if { … }` | mỗi lần thân đúng thêm một phần tử vào tập |
| Hàm | `path_match(pattern, path) if { … }` | có tham số; nhiều định nghĩa cùng tên = "hoặc" |

Trong **thân** luật, các dòng nối với nhau bằng **VÀ**. Muốn **HOẶC** thì viết nhiều luật cùng
tên (xem hai định nghĩa `segment_match`).

## 4. Khái niệm quan trọng nhất: "không xác định" (undefined) ≠ `false`

- Một biểu thức tham chiếu thứ không tồn tại (`input.subject.dept` khi không có `dept`) thì
  **không xác định**, và cả thân luật dừng lại — luật không được tạo ra.
- `not X` đúng khi `X` sai **hoặc** không xác định.
- Vì vậy luật cho phép phải viết theo kiểu "chỉ đúng khi chứng minh được" và có
  `default allow := false`. Thiếu dữ liệu → không chứng minh được → từ chối (fail closed).

### Bẫy 1 (gặp thật khi viết lab) — `not` không bao trọn phép gán

```rego
# SAI: OPA tách thành  x := input.subject[attr];  not x in allowed
abac_failed contains attr if {
    some attr, allowed in object.get(route, "require", {})
    not input.subject[attr] in allowed
}
```

Thiếu claim `tier` → dòng `x := input.subject["tier"]` không xác định → cả thân dừng →
`abac_failed` rỗng → `allow` = **true**. User không có `tier` lại xuất được báo cáo premium.
`opa test` bắt được (ca `test_missing_tier_claim_is_denied`). Sửa: đưa phép so vào hàm để
`not` bao cả hàm:

```rego
abac_failed contains attr if {
    some attr, allowed in object.get(route, "require", {})
    not attr_ok(attr, allowed)
}
attr_ok(attr, allowed) if input.subject[attr] in allowed
```

Bài học: luật **từ chối** viết bằng `not` phải có test cho ca **thiếu dữ liệu**.

### Bẫy 2 — OPA trả `200 {}` khi đường dẫn không tồn tại

Gõ sai package hoặc OPA chưa nạp policy: `POST /v1/data/topic09/authz/decison` → `200 {}`
(không có `result`). PEP nào chỉ đọc `result.allow` mà coi `nil` như "không chặn" là fail open.
`internal/policy/opa.go` coi thiếu `result`, thiếu trường, sai kiểu đều là lỗi → 503.

## 5. Các cú pháp khác trong file

| Cú pháp | Ví dụ | Đọc là |
|---|---|---|
| `some i, r in routes` | trong `route_index` | duyệt mảng, `i` là chỉ số, `r` là phần tử |
| Comprehension tập | `{i \| some i, r in routes; …}` | tập các `i` thoả điều kiện |
| `min(tập)` | `route_index := min({…})` | tập rỗng → không xác định → không có route → từ chối |
| `every` | `every i, seg in want { segment_match(seg, got[i]) }` | đúng khi MỌI phần tử thoả |
| `object.get(o, k, mặc_định)` | `object.get(route, "require", {})` | lấy khoá, thiếu thì dùng mặc định thay vì không xác định |
| `regex.match` | `regex.match(param_pattern, value)` | `{id}` chỉ nhận `[A-Za-z0-9_-]{1,64}` |
| `with` (chỉ trong test) | `authz.decision with input as {...}` | chạy luật với `input` giả; phải nằm trong **thân** luật, không ở phần đầu |
| `default` | `default route_id := ""` | giá trị mặc định phải là **hằng**, không được tham chiếu biến (lỗi `illegal default rule` đã gặp) |

## 6. Kiểm thử và vận hành

- `opa test policy/ -v`: chạy mọi luật tên `test_*`. `--coverage` cho biết dòng nào chưa chạy
  (lab: 98,6 %, dòng còn lại là nhánh `else := "denied"` không thể xảy ra).
- `opa check --strict`: bắt biến không dùng, import thừa…; `opa fmt --list`: như `gofmt -l`.
- Decision log (`--set=decision_logs.console=true`): mỗi quyết định một dòng JSON có
  `decision_id`, `input`, `result`. `package system.log` + `mask contains "/input/path"` xoá
  đường dẫn thật trước khi ghi (SR-10). auth-svc ghi `opa_decision_id` để nối hai log.
- `policy_version` trong kết quả: đổi luật thì tăng số, mỗi dòng log biết bản policy nào quyết định.

## 7. Bài tập cho Playground (play.openpolicyagent.org) — tự làm

Dán `policy/authz.rego` vào ô policy, mỗi bài đổi `input` hoặc luật rồi đoán kết quả TRƯỚC khi bấm Evaluate.

1. `input = {"method":"GET","path":"/orders/export","subject":{"roles":["employee"],"tier":"premium"}}`
   → `allow`? `reason`? Đổi `tier` thành `"Premium"` thì sao? Vì sao so sánh phân biệt hoa thường là đúng?
2. Đổi thứ tự hai dòng `orders.export` và `orders.read` trong `routes`. Request ở bài 1 giờ
   khớp route nào? Kết luận về luật "khớp đầu tiên".
3. Viết lại `abac_failed` theo kiểu SAI ở Bẫy 1, bỏ `tier` khỏi input bài 1. Quan sát `allow`.
4. Thêm luật ABAC thứ ba: `DELETE /orders/{id}` chỉ cho manager **cùng dept với** … — vì sao
   gateway KHÔNG viết được luật "chỉ xoá đơn của phòng mình"? (Gợi ý: OPA không biết đơn 123
   thuộc phòng nào → đó là việc của backend, tuần 7, object-level authz.)
5. Viết 2 unit test mới cho bài 4 theo mẫu `authz_test.rego` (một ca allow, một ca deny).

## 8. Liên hệ threat model

| Threat | Policy giúp gì | Còn hở |
|---|---|---|
| T4 broken authorization | RBAC route+method, ABAC dept/tier, mặc định từ chối | lỗi object-level (BOLA) — gateway không biết chủ đơn hàng |
| T8 policy compromise | mount chỉ đọc, `policy_version` trong log, OPA không lộ API | ai sửa được git + restart OPA (T11) |
| SR-11 fail closed | auth-svc: OPA lỗi/timeout/`{}` → 503 | — |
