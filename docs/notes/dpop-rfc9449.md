# Ghi chú tuần 6 — DPoP (RFC 9449) và cách lab cài đặt

Nguồn: RFC 9449 (OAuth 2.0 Demonstrating Proof of Possession, 09/2023), RFC 7638 (JWK
Thumbprint), RFC 9700 §2.2 (sender-constrained token), tài liệu Keycloak 26 về DPoP.
Số mục RFC: đối chiếu lại bản gốc trước khi trích vào báo cáo.

## 1. Vấn đề DPoP giải quyết (T1 — token theft/replay)

Bearer token giống tiền mặt: **ai cầm cũng tiêu được**. Token lộ qua log, proxy, XSS, máy client
bị chiếm… là kẻ tấn công gọi API được tới khi token hết hạn (lab: 5 phút). TLS chỉ bảo vệ trên
đường truyền, không bảo vệ token đã nằm ở đầu kia.

DPoP biến token thành "tiền có chữ ký": token gắn với một **cặp khoá của client**. Mỗi request
client phải chứng minh đang giữ khoá riêng bằng một **DPoP proof** mới. Có token mà không có khoá
riêng thì vô dụng.

## 2. Ba mảnh ghép

| Mảnh | Nằm ở đâu | Nội dung |
|---|---|---|
| Khoá DPoP (tài sản #9) | chỉ ở client | EC P-256 trong lab (`dpop_keygen`); khoá riêng không bao giờ gửi đi |
| `cnf.jkt` trong access token | Keycloak ghi khi cấp token | `jkt` = BASE64URL(SHA-256(JWK công khai dạng chuẩn RFC 7638)) — "vân tay" của khoá |
| DPoP proof | header `DPoP:` của MỖI request | JWT ký bằng khoá riêng: header `{typ: dpop+jwt, alg, jwk}`, payload `{jti, htm, htu, iat, ath}` |

Payload của proof:

| Claim | Ý nghĩa | Chống gì |
|---|---|---|
| `htm`, `htu` | method + URL (bỏ query) của đúng request này | đem proof sang request khác |
| `iat` | thời điểm tạo | dùng proof cũ (lab: cửa sổ ±30 s) |
| `jti` | mã ngẫu nhiên | phát lại proof trong cửa sổ (server nhớ `jti` đã thấy) |
| `ath` | BASE64URL(SHA-256(access token)) | ghép proof với token khác |

Token trong request dùng scheme mới: `Authorization: DPoP <token>` (không phải `Bearer`).

## 3. Luồng trong lab (trace: `docs/traces/dpop-token-2026-10-31.txt`)

1. Client sinh khoá, tính `jkt`.
2. Auth Code + PKCE như tuần 3 với client `web-app-dpop` (`dpop.bound.access.tokens: true`).
3. Đổi code lấy token **kèm proof** (`htm=POST`, `htu`=token endpoint, không có `ath`).
4. Keycloak kiểm proof → cấp token `token_type: DPoP`, payload có `typ: "DPoP"` và
   `cnf: {jkt: …}`. Refresh token cũng gắn khoá (client public, RFC 9449 §5): refresh bằng
   khoá khác → `invalid_grant (DPoP confirmation doesn't match DPoP proof)`.
5. Gọi API ở P2 `:8445`: `Authorization: DPoP <token>` + `DPoP: <proof mới>`
   (`htm`/`htu` của request, `ath` của token).

## 4. 12 bước kiểm của RFC 9449 §4.3 → code → test

Code: `gateway/auth-svc/internal/dpop/dpop.go` (comment "(n)" là số bước). Test đơn vị:
`internal/dpop/dpop_test.go`; test đầu-cuối: `scripts/dpop-test.sh` (mã ca A–E).

| # | Kiểm | Lý do từ chối trong log | Test đầu-cuối |
|---|---|---|---|
| 1 | không quá một header DPoP (Envoy gộp header trùng bằng dấu phẩy) | `dpop_multiple_headers` | C13 |
| 2 | là một JWT đúng định dạng | `dpop_malformed` | — (unit) |
| 3 | đủ `jti`, `htm`, `htu`, `iat` (+ `ath` khi có token) | `dpop_missing_claim` | C6, C7 |
| 4 | `typ` = `dpop+jwt` | `dpop_bad_typ` | C1 |
| 5 | `alg` bất đối xứng, trong allow-list (lab: ES256) | `dpop_alg_not_allowed` | C2 (none), C3 (HS256) |
| 6 | chữ ký đúng với khoá trong `jwk` | `dpop_bad_signature` | C5 |
| 7 | `jwk` không chứa khoá riêng | `dpop_private_key_in_jwk` | C4 |
| 8 | `htm` = method của request | `dpop_htm_mismatch` | B6 |
| 9 | `htu` = URI của request (bỏ query/fragment, chuẩn hoá) | `dpop_htu_mismatch` | B5, C9, C10 |
| 10 | `nonce` (nếu server cấp) | — | không dùng (xem §6) |
| 11 | `iat` trong cửa sổ (±30 s) | `dpop_iat_out_of_window` | C11, C12 |
| 12a | `ath` = hash của access token đi kèm | `dpop_ath_mismatch` | C8 |
| 12b | khoá trong proof = khoá token được gắn (`jkt` = `cnf.jkt`) | `dpop_key_mismatch` | B4 |
| §11.1 | `jti` chưa dùng trong cửa sổ | `dpop_replay` | B1, B7 |

**Thứ tự trong code khác thứ tự đánh số** (RFC không bắt buộc thứ tự): rẻ trước, đắt sau (T10).
Bước 12b (một SHA-256) đặt **trước** bước 6 (kiểm chữ ký): chặn ngay kẻ trộm token tự ký proof
bằng khoá của mình mà không tốn phép kiểm chữ ký. Payload chỉ được đọc **sau** khi chữ ký đúng.

**`jti` ghi vào cache sau cùng** (quyết định 2026-10-03): proof hỏng ở bất kỳ bước nào không
"đốt" được `jti`. Kiểm-và-ghi nằm trong một khoá mutex: B7 gửi 10 request song song cùng một
proof → đúng 1 lần 200. Cache đầy → từ chối (503), không xoá mục còn hạn.

## 5. Chống hạ cấp (RFC 9449 §7.2) và vì sao chỉ được mở P2

Server nhận cả Bearer lẫn DPoP **phải** từ chối token đã gắn khoá gửi như bearer — nếu không,
kẻ trộm chỉ cần đổi `Authorization: DPoP` thành `Bearer`.

| Profile | Token DPoP bị trộm, gửi `Bearer`, không proof | Vì sao |
|---|---|---|
| P0 `:8444` | **200 — lọt** (ca D2) | `jwt_authn` của Envoy không biết `cnf`/`typ`; baseline có chủ đích |
| P1 `:8443` | 401 `wrong_typ` (D1) | auth-svc chỉ nhận `typ=Bearer`; có thêm kiểm `cnf.jkt` → `dpop_bound_token_as_bearer` (không phụ thuộc chi tiết riêng của Keycloak) |
| P2 `:8445` | 401 (B2, B3, B4) | bắt buộc scheme DPoP + proof |

Kết luận cho báo cáo: P0/P1 chỉ giữ để **đo so sánh** (tuần 11). Triển khai thật chỉ mở P2,
nếu không thì DPoP bị vượt qua P0.

## 6. Giới hạn còn lại (ghi vào residual risk)

- **Không dùng `DPoP-Nonce`** (§8–9): cửa sổ `iat` ±30 s + cache `jti` đủ cho lab. Nonce do
  server cấp chống được proof **tạo trước** cho thời điểm tương lai (§11.2); thiếu nonce thì
  mã độc chạy trên máy client (XSS) có thể ký sẵn proof — nhưng nó cũng ký được proof mới bất kỳ
  lúc nào nếu dùng được khoá, nên khoá cần lưu không xuất được (WebCrypto `extractable: false`).
- Cache `jti` trong bộ nhớ một tiến trình: restart auth-svc mất cache → proof < 30 s tuổi dùng
  lại được một lần ngay sau restart; nhiều bản auth-svc cần cache chung (Redis).
- Kẻ tấn công **có** khoá riêng của client (máy bị chiếm) thì DPoP không giúp gì.
- Cache có trần (100 000 mục): một client hợp lệ gửi > ~3 300 request/s có thể làm đầy cache
  trong 30 s → mọi request P2 bị từ chối (DoS, T10). Lab chấp nhận; thật thì giới hạn theo `jkt`.
- Keycloak kiểm proof ở token endpoint, auth-svc kiểm ở resource server: hai bên **độc lập**,
  khớp nhau nhờ cùng tính `jkt` theo RFC 7638 (unit test so với ví dụ chuẩn RFC 7638 §3.1).

## 7. Con số tuần 6 (2026-10-31)

| Mục | Kết quả | File |
|---|---|---|
| Token DPoP + 7 ca ở token endpoint | 9 dòng PASS | `docs/traces/dpop-token-2026-10-31.txt` |
| P2 đầu-cuối | 31/31 PASS | `docs/evidence/dpop-p2-2026-10-31.txt` |
| Unit test auth-svc (cả JWT, OPA, DPoP) | 173 PASS | `docs/evidence/auth-svc-unit-tests-2026-10-31.txt` |
| Thời gian quyết định P2 ở auth-svc (JWT + proof + OPA) | trung vị ~1,9 ms (n = 6) | log auth-svc — chưa phải benchmark (tuần 11) |
