# Ghi chú tuần 7 — OWASP API Security Top 10 (2023) và phân quyền ở backend

Nguồn: OWASP API Security Top 10 — bản 2023 (owasp.org/API-Security), mục API1, API3, API5;
RFC 9110 §15.5.4 (403 Forbidden) và §15.5.5 (404 Not Found). Đọc kèm code:
`workloads/internal/orders/orders.go`, `workloads/internal/profiles/profiles.go`,
`policy/authz.rego`, test đầu-cuối `scripts/object-authz-test.sh`.

## 1. Mười mục 2023 và vị trí trong lab

| Mục | Tên | Lab xử lý ở đâu |
|---|---|---|
| API1 | Broken Object Level Authorization (BOLA) | **backend** — `owner_id`, manager cùng phòng (tuần 7) |
| API2 | Broken Authentication | Keycloak (PKCE, brute-force), gateway kiểm JWT chặt, DPoP (tuần 3–6) |
| API3 | Broken Object Property Level Authorization | **backend** — `salary_band` chỉ hr, chặn mass assignment (tuần 7) |
| API4 | Unrestricted Resource Consumption | giới hạn header/token/proof/body, cache `jti` có trần, trần số đơn (T10) |
| API5 | Broken Function Level Authorization (BFLA) | **gateway** — OPA theo route + method (tuần 5) |
| API6 | Unrestricted Access to Sensitive Business Flows | ngoài phạm vi (không có luồng mua/đặt chỗ) |
| API7 | Server Side Request Forgery | auth-svc chỉ gọi URL ghi cứng (JWKS, OPA), không theo redirect |
| API8 | Security Misconfiguration | TLS 1.3 only, image ghim, không admin port, `read_only`, `cap_drop` |
| API9 | Improper Inventory Management | bảng route duy nhất trong `authz.rego`; route lạ → 404 ở Envoy/OPA/backend |
| API10 | Unsafe Consumption of APIs | không gọi API bên thứ ba (chỉ Keycloak nội bộ) |

Bản 2023 gộp hai mục cũ của bản 2019 — *Excessive Data Exposure* và *Mass Assignment* — thành
API3, vì gốc của cả hai là một: **không kiểm quyền ở mức từng thuộc tính** (đọc hay ghi).

## 2. Ba câu hỏi phân quyền — mỗi câu một lớp

| Câu hỏi | OWASP | Ai trả lời được | Vì sao lớp đó |
|---|---|---|---|
| Người này có được gọi **chức năng** này (route + method)? | API5 BFLA | gateway (OPA) | chỉ cần role + route, không cần dữ liệu nghiệp vụ |
| Người này có được đụng **đối tượng** này (đơn ord-1002)? | API1 BOLA | backend | chỉ backend biết ord-1002 thuộc ai, phòng nào |
| Người này có được xem/sửa **thuộc tính** này (`salary_band`)? | API3 | backend | gateway thấy URL, không thấy trường nào trong body/response |

Đây là lý do SR-06 ghi "gateway là PEP … **backend vẫn kiểm object/property**": OPA trả lời đúng
câu 1, nhưng với câu 2 thì `GET /orders/{id}` của employee luôn **hợp lệ** — dù `{id}` là của ai.

## 3. API1 — BOLA

**Bản chất:** API nhận ID đối tượng từ client (URL, body, header) và trả/sửa đối tượng đó mà không
kiểm người gọi có quan hệ gì với nó. Kẻ tấn công không cần kỹ thuật cao: đổi `ord-1001` → `ord-1002`.
OWASP xếp BOLA đứng đầu vì phổ biến nhất và dễ khai thác nhất.

**Trong lab:**

- Luật nằm ở một chỗ (`canRead`, `deptManager` trong `orders.go`), mọi handler nhận ID đều gọi:
  đọc = chủ đơn **hoặc** manager cùng phòng; xoá = manager cùng phòng; liệt kê = lọc ở server.
- `owner_id` của đơn mới **luôn** lấy từ `X-User` (sub đã kiểm), không bao giờ từ body.
- ID fixture tăng dần và xen kẽ chủ (1001 alice, 1002 bob…) — cố ý để thấy dò ID là chuyện dễ.
  ID đơn mới là ngẫu nhiên (`ord-` + 12 hex), nhưng OWASP nói rõ: ID khó đoán **không thay** được
  kiểm quyền — ID vẫn lộ qua log, link chia sẻ, lịch sử trình duyệt.

**404 thay vì 403** (quyết định 2026-11-09): đơn của người khác và đơn không tồn tại trả **cùng**
`404 {"error":"not_found"}`. Nếu trả 403 cho đơn có thật, kẻ dò ID biết đơn nào tồn tại. RFC 9110
§15.5.4 cho phép server dùng 404 để giấu sự tồn tại của tài nguyên bị cấm. Lý do thật
(`not_owner` / `not_found`) chỉ nằm trong log — cho hunt H5. Ngoại lệ: alice xoá đơn **của mình**
→ 403, vì alice đọc được đơn đó nên giấu không có ý nghĩa.

## 4. API3 — Broken Object Property Level Authorization

Hai mặt:

1. **Đọc — lộ dữ liệu thừa.** Lỗi kinh điển: backend trả cả object, "tin" client tự ẩn trường
   nhạy cảm. Trong lab, manager được xem hồ sơ nhân viên phòng mình nhưng **không** thấy
   `salary_band`. Cách làm: hai struct đầu ra (`publicView`, `hrView`) — `publicView` **không có**
   trường `salary_band`, nên không thể vô tình serialize ra. An toàn hơn "lấy struct đầy đủ rồi xoá
   trường" (quên xoá một trường là lộ). Log ghi `backend_redacted_fields: "salary_band"`.
2. **Ghi — mass assignment.** Lỗi kinh điển: bind thẳng body JSON vào object trong DB, client gửi
   thêm `"owner_id"`, `"role"`, `"salary_band"` là sửa được. Trong lab: struct đầu vào chỉ có các
   trường được phép + `DisallowUnknownFields` → trường lạ = `400 unknown_field`; quyền ghi từng
   trường (`writableBy`): `salary_band` chỉ hr; hr **không** tự sửa `salary_band` của mình
   (tách nhiệm vụ — gateway không thấy được vì OPA không so `{id}` trong URL với `sub`).

## 5. API5 — BFLA

**Bản chất:** người dùng thường gọi được chức năng quản trị (DELETE, PATCH, `/admin/...`) vì API chỉ
kiểm "đã đăng nhập". Trong lab, bảng route của OPA khai role cho từng route + method, mặc định từ
chối: alice (employee) `DELETE /orders/{id}` → 403 ở gateway, request không tới backend.

Ở **P0** (chỉ `jwt_authn`), BFLA lọt gateway — đúng định nghĩa baseline. Lớp backend vẫn chặn được
một phần vì luật xoá là "manager cùng phòng" và P0 không gửi role (E2 trong test). Nhưng đó là
phòng thủ nhiều lớp, không phải chỗ chính để chặn BFLA.

## 6. Header danh tính gateway → backend (TB3)

| Header | Giá trị | P0 | P1/P2 |
|---|---|---|---|
| `X-User` | `sub` | có (`claim_to_headers`) | có (auth-svc) |
| `X-User-Roles` | role nối "," (chỉ `[a-z][a-z0-9_-]*`, bỏ giá trị lạ) | **không** | có |
| `X-User-Dept` | `dept` (cùng luật) | **không** | có |

Thiếu role/dept → backend coi người gọi **ít quyền nhất** (fail-safe): ở P0 không ai là "manager
cùng phòng", không ai thấy `salary_band`. Trên cả ba listener, Envoy xoá `X-User`, `X-User-Roles`,
`X-User-Dept`, `X-User-Tier` do client gửi **trước** mọi filter khác — test E5: alice gửi
`X-User-Roles: hr` qua P0 vẫn không tự sửa được `salary_band`.

## 7. Rủi ro còn lại (đưa vào báo cáo)

- **TB3 tin bằng vị trí mạng:** container bị chiếm trong mạng `topic09-backend` gửi được
  `X-User-Roles: hr`. Nâng cấp: JWT nội bộ ngắn hạn do gateway ký, hoặc mTLS (§8.2 bản phân tích).
- **Lỗi logic backend** (cột "Còn hở" của T4): luật đúng hay sai chỉ chứng minh bằng test. Đã gom
  luật về một hàm/đối tượng và có bảng test riêng (`TestObjectLevelRules`).
- **Thuộc tính cũ trong token:** đổi `dept` của user trong Keycloak thì token cũ vẫn mang `dept` cũ
  tới khi hết hạn (300 s).
- **Kênh phụ thời gian:** 404 "không tồn tại" và 404 "của người khác" đi hai nhánh code khác nhau;
  chênh lệch cỡ micro giây, nhỏ hơn nhiều so với độ dao động mạng — chấp nhận.
- **Dữ liệu trong bộ nhớ:** restart là mất thay đổi. Đủ cho lab; DB thật thì luật giữ nguyên, có
  thêm lựa chọn lọc ngay trong câu truy vấn (`WHERE owner_id = $sub`).

## 8. Tự kiểm

1. Vì sao OPA không chặn được A2 (alice `GET /orders/ord-1002`)?
   → OPA chỉ thấy `employee` + `GET /orders/{id}` — hợp lệ; nó không có dữ liệu "ord-1002 của bob".
2. Có nên đưa bảng chủ đơn vào `data` của OPA để OPA quyết luôn object-level?
   → Làm được với dữ liệu nhỏ, nhưng phải đồng bộ DB → OPA liên tục; lệch dữ liệu = lỗ hổng. Cách
   phổ biến: OPA quyết chức năng, backend quyết đối tượng (hoặc backend hỏi OPA kèm thuộc tính đối tượng).
3. Vì sao không trả 403 cho đơn của người khác?
   → 403 phân biệt được "có nhưng cấm" với "không có" → dò ID biết đơn nào tồn tại.
4. Manager phòng sales có xoá được đơn của bob (engineering) không? Lớp nào chặn?
   → Không. Gateway cho qua (manager được DELETE), backend chặn (`not_owner`, 404) — test B3.
5. Vì sao chặn `{"owner_id": ...}` bằng 400 thay vì lặng lẽ bỏ qua trường đó?
   → Bỏ qua lặng lẽ thì client lỗi không biết; báo 400 + log `unknown_field` cho SIEM thấy có người
   thử gán thuộc tính không được phép.
