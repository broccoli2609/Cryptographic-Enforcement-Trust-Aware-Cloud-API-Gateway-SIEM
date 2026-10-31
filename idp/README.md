# idp/ — realm Keycloak `topic09` (tuần 3)

`realm-topic09.json` là realm viết dưới dạng code. Keycloak import file này khi khởi động
(`start-dev --import-realm`, thư mục `idp/` mount chỉ đọc vào `/opt/keycloak/data/import`).

- Realm đã có trong volume `keycloak-data` thì Keycloak **bỏ qua** file (chiến lược `IGNORE_EXISTING`).
  Sửa file xong muốn áp dụng: xoá realm `topic09` trong admin console (hoặc
  `DELETE /admin/realms/topic09`) rồi `docker compose restart keycloak`.
  Chỉ thêm **một client** thì không cần xoá realm: `./scripts/kc-apply-client.sh <clientId>` đọc
  client + scope mapping từ file này và tạo qua Admin REST API (không ghi đè client đã có).
- Mật khẩu user không nằm trong file: `${LAB_USER_PASSWORD}` được Keycloak thay bằng biến
  môi trường lấy từ `.env`.
- Khoá công khai của `batch-worker` không nằm trong file (khoá sinh trên từng máy):
  `./scripts/batch-worker-key.sh` sinh khoá và đăng ký chứng chỉ qua Admin REST API.
- Kiểm cấu hình đang chạy: `./scripts/check-realm.sh`.

## Client

| Client | Loại | Luồng | Xác thực client | Ghi chú bảo mật |
|---|---|---|---|---|
| `web-app` | public | Authorization Code + PKCE | không có (public) | PKCE bắt buộc `S256`; `redirect_uri` đúng một giá trị `http://localhost:3000/callback`; tắt implicit và ROPC |
| `web-app-dpop` (tuần 6) | public | Authorization Code + PKCE + **DPoP** | không có (public) | như `web-app` + `dpop.bound.access.tokens: true`: thiếu DPoP proof ở token endpoint → `400 DPoP proof is missing`. Token có `typ: "DPoP"` và `cnf.jkt`; refresh token cũng gắn khoá (RFC 9449 §5). Dùng cho profile P2 (`:8445`) |
| `batch-worker` | confidential | Client Credentials | `private_key_jwt` (`client-jwt`), chữ ký bắt buộc ES256 | không có secret dùng chung; Keycloak chỉ giữ chứng chỉ (khoá công khai) |

`web-app-dpop` là client riêng (không bật DPoP trên `web-app`) để token bearer của P0/P1 vẫn
dùng được cho bài so sánh profile ở tuần 11.

Mọi client có `fullScopeAllowed: false`, chỉ được cấp các role ghi trong `scopeMappings`
(`web-app`, `web-app-dpop`: employee/manager/hr; `batch-worker`: batch). Hệ quả: token không mang role thừa,
`aud` không có `account`. Đây là nguyên tắc giới hạn đặc quyền của token (RFC 9700 §2.3).
Mapper `audience-topic09-api` đặt `aud = topic09-api`; gateway sẽ chỉ nhận token có `aud` này.

## User (mật khẩu chung `LAB_USER_PASSWORD` trong `.env`)

| User | Role | `dept` | `tier` | Dùng cho |
|---|---|---|---|---|
| alice | employee | sales | standard | user thường; nạn nhân/kẻ tấn công trong test BOLA (tuần 7) |
| bob | employee | engineering | premium | user thường khác phòng ban |
| carol | employee, hr | hr | standard | được xem `salary_band` (property-level, tuần 7) |
| dave | employee, manager | sales | premium | luật ABAC theo `dept` (tuần 5) |
| service-account-batch-worker | batch | — | — | token máy-với-máy |

`dept` và `tier` được khai báo trong User Profile: **user xem được nhưng chỉ admin sửa được**.
Nếu để user tự sửa qua Account Console, alice có thể tự đổi `tier` thành `premium` hoặc `dept`
thành `hr`, rồi dùng chính token hợp lệ đó để vượt luật ABAC (T4, leo quyền).

## Thiết lập realm và lý do

| Thiết lập | Giá trị | Lý do |
|---|---|---|
| `accessTokenLifespan` | 300 s | token bị lộ chỉ dùng được trong thời gian ngắn (T1) |
| `accessCodeLifespan` | 60 s | mã uỷ quyền chỉ dùng một lần và sống ngắn (RFC 9700 §4.5) |
| `revokeRefreshToken`, `refreshTokenMaxReuse: 0` | bật, 0 | refresh token xoay vòng; dùng lại token cũ bị phát hiện (RFC 9700 §4.14) |
| `bruteForceProtected` | 5 lần sai → khoá tăng dần 60 s…900 s | chống đoán mật khẩu (T3); mặc định Keycloak tắt |
| `passwordPolicy` | `length(12) and notUsername` | chặn mật khẩu yếu khi tạo user mới |
| `registrationAllowed`, `resetPasswordAllowed` | tắt | lab không có SMTP; không cho ai tự tạo tài khoản |
| `defaultSignatureAlgorithm` | RS256 | khoá ký phần mềm do Keycloak sinh (rủi ro còn lại T7) |
| `eventsEnabled`, `adminEventsEnabled` | bật (listener `jboss-logging` → stdout) | sự kiện đăng nhập/quản trị sẽ đưa về SIEM ở tuần 8 (T11) |
| `sslRequired` | `external` | lab chạy HTTP trên localhost; địa chỉ ngoài bắt buộc HTTPS |

JWKS của realm có hai khoá: `RS256` (`use: sig`, dùng để ký token) và `RSA-OAEP` (`use: enc`,
dùng để mã hoá). Bộ kiểm JWT ở gateway chỉ được dùng khoá có `use: sig`.
