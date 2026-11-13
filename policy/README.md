# policy/ — OPA (PDP) của gateway (tuần 5)

`auth-svc` (PEP) kiểm token xong thì hỏi OPA:
`POST http://opa:8181/v1/data/topic09/authz/decision` với `input` gồm method, đường dẫn
(không có query) và claim **đã kiểm** của token (`sub`, `client_id`, `roles`, `dept`, `tier`).
Header client tự gửi (`X-User-Roles`…) không bao giờ vào `input`.

| File | Nội dung |
|---|---|
| `authz.rego` | `package topic09.authz` — bảng route (RBAC) + luật ABAC, `default allow := false` |
| `authz_test.rego` | 33 unit test (`opa test`), mỗi luật có ca cho phép và ca từ chối |
| `log_mask.rego` | `package system.log` — xoá `input.path` khỏi decision log (SR-10) |

## Bảng route (khớp từ trên xuống, route đầu tiên khớp thắng)

| id | Method | Đường dẫn | Role | ABAC |
|---|---|---|---|---|
| `orders.whoami` | GET | `/orders/whoami` | employee, manager, hr, batch | — |
| `orders.export` | GET | `/orders/export` | employee, manager | `tier` = premium |
| `orders.list` | GET | `/orders` | employee, manager, batch | — |
| `orders.create` | POST | `/orders` | employee, manager | `dept` = sales |
| `orders.read` | GET | `/orders/{id}` | employee, manager | — (owner_id kiểm ở backend, tuần 7) |
| `orders.delete` | DELETE | `/orders/{id}` | manager | — |
| `profile.whoami` | GET | `/profile/whoami` | employee, manager, hr, batch | — |
| `profile.me` | GET | `/profile/me` | employee | — |
| `profile.read` | GET | `/profile/{id}` | hr, manager | — (salary_band chỉ HR, backend, tuần 7) |
| `profile.update` | PATCH | `/profile/{id}` | hr | — |

`{id}` khớp `^[A-Za-z0-9_-]{1,64}$`. Request không khớp route nào → từ chối (`no_matching_route`).

Kết quả luôn có dạng
`{"allow": bool, "policy_id": "topic09.authz", "policy_version": "1.1.0", "route": "<id>", "route_template": "<đường dẫn mẫu>", "reason": "<mã>"}`;
`reason` ∈ `ok`, `no_matching_route`, `role_not_allowed`, `abac_dept`, `abac_tier`.
`route_template` (tuần 8) là cột "Đường dẫn" của route đã khớp, ví dụ `/orders/{id}` — rỗng nếu
không khớp route nào. auth-svc ghi nó vào log thay cho đường dẫn thật (SR-10).
**Đổi luật thì tăng `policy_version`** — số này nằm trong log của mỗi quyết định ở auth-svc.

| `policy_version` | Thay đổi |
|---|---|
| 1.0.0 (tuần 5) | RBAC route + method, ABAC `dept` / `tier` |
| 1.1.0 (tuần 8) | Kết quả thêm `route_template` cho telemetry; luật không đổi |

## Decision log → SIEM (tuần 8)

OPA ghi mỗi quyết định một dòng JSON ra stdout; Vector đọc và đổi sang `telemetry/schema.json`:

| Trong decision log | Trường trong SIEM |
|---|---|
| `timestamp` | `event_time` |
| `decision_id` | `opa_decision_id` (auth-svc cũng ghi mã này → nối PEP ↔ PDP) |
| `result.allow` / `result.reason` | `decision` / `decision_reason` |
| `result.policy_id`, `result.policy_version` | `policy_id`, `policy_version` |
| `result.route`, `result.route_template` | `policy_route`, `route_template` |
| `input.method` | `method` |
| `input.subject.sub` | `principal_hash` (HMAC, giá trị thô bị xoá) |
| `input.subject.client_id`, `.roles`, `.dept`, `.tier` | `client_id`, `subject_roles`, `subject_dept`, `subject_tier` |
| `metrics.timer_rego_query_eval_ns` | `policy_eval_us` |
| `input.path` | đã bị `log_mask.rego` xoá — không tới được Vector |

## Kiểm

```bash
make policy-test      # opa fmt --list, opa check --strict, opa test -v (chạy bằng image OPA, không cần cài)
make authz-test       # đầu-cuối bằng token thật: RBAC, ABAC dept/tier, header giả, so sánh P0
make failclosed       # dừng / treo OPA → P1 phải 503, không bao giờ 200 (SR-11)
```

## Bảo vệ OPA

- REST API của OPA không xác thực → OPA **không có `ports:`**, chỉ ở mạng `topic09-policy`
  (internal) chung với `auth-svc` (smoke test kiểm danh sách thành viên mạng).
- Policy mount **chỉ đọc**; đổi policy = sửa file trong git + restart OPA (T8).
- `auth-svc` coi mọi bất thường khi hỏi OPA là từ chối: mất kết nối, quá `OPA_TIMEOUT` (250 ms),
  HTTP ≠ 200, JSON hỏng, thiếu trường, và cả `{}` — OPA trả `200 {}` khi đường dẫn policy không
  tồn tại, đây là bẫy fail-open hay gặp.
