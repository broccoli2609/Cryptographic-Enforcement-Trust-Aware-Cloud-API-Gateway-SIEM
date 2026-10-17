# Ghi chú đọc tuần 3 — Authorization Code + PKCE, RFC 9700

Nguồn: oauth.com (OAuth 2.0 Simplified, các trang Authorization Code và PKCE), RFC 7636 (PKCE),
RFC 9700 (OAuth 2.0 Security Best Current Practice, 01/2025). Ghi chú bằng lời của mình, kèm cột
"trong lab" để dùng lại cho báo cáo. Số mục RFC: đối chiếu lại bản gốc trước khi trích.

## 1. Authorization Code + PKCE từng bước

| # | Ai → ai | Gửi gì | Vì sao |
|---|---|---|---|
| 1 | client tự sinh | `code_verifier` = 32 byte ngẫu nhiên → base64url (43 ký tự) | bí mật chỉ client biết; RFC 7636 §4.1 cho 43–128 ký tự `[A-Za-z0-9-._~]` |
| 2 | client tự tính | `code_challenge = BASE64URL(SHA-256(code_verifier))` | dùng được ở kênh trước (trình duyệt) vì không suy ngược được verifier |
| 3 | trình duyệt → AS `/auth` | `response_type=code`, `client_id`, `redirect_uri`, `scope=openid`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256` | AS lưu challenge cùng phiên đăng nhập |
| 4 | user ↔ AS | đăng nhập | mật khẩu chỉ đi tới AS, client không thấy |
| 5 | AS → trình duyệt → `redirect_uri` | `302 Location: …?code=…&state=…&iss=…` | `code` sống ngắn (lab: 60 s), dùng một lần |
| 6 | client kiểm | `state` khớp giá trị đã gửi; `iss` đúng AS mong đợi | chống CSRF (§4.7) và mix-up (§4.4, RFC 9207) |
| 7 | client → AS `/token` (kênh sau) | `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier` | AS tính lại SHA-256(verifier) và so với challenge đã lưu |
| 8 | AS → client | `access_token`, `id_token`, `refresh_token` | chỉ client giữ verifier mới đổi được code ra token |

Ý nghĩa mật mã: SHA-256 là hàm một chiều. Kẻ tấn công thấy `code_challenge` ở bước 3, hoặc chặn
được `code` ở bước 5 (log proxy, lịch sử trình duyệt, app độc chiếm custom scheme), vẫn không
đổi được code vì không có `code_verifier`. Phương thức `plain` (challenge = verifier) mất tính
chất này nên lab chỉ cho `S256`.

## 2. RFC 9700 — điểm áp dụng vào lab

| Mục | Khuyến nghị (tóm tắt) | Trong lab | Test/bằng chứng |
|---|---|---|---|
| §2.1 | So `redirect_uri` bằng **so khớp chuỗi chính xác** | `web-app` chỉ có `http://localhost:3000/callback` | `pkce-negative.sh`: sai `redirect_uri` bị từ chối |
| §2.1.1 | Client public **phải** dùng PKCE; nên dùng `S256` | `pkce.code.challenge.method = S256` | thiếu challenge, `plain`, sai verifier đều bị từ chối |
| §2.1.2 | Không dùng implicit grant | `implicitFlowEnabled: false` | `check-realm.sh` |
| §2.2.1 | Access token nên bị ràng buộc với người gửi (mTLS hoặc DPoP) | tuần 6: DPoP (`cnf.jkt`) = P2 | S3, S4 |
| §2.2.2 | Refresh token của client public: ràng buộc người gửi hoặc xoay vòng | `revokeRefreshToken: true`, dùng lại 0 lần | — |
| §2.3 | Giới hạn đặc quyền của token, nhất là audience | `aud = topic09-api`, `fullScopeAllowed: false` | gateway kiểm `aud` (tuần 4) |
| §2.4 | **Không được** dùng Resource Owner Password Credentials | `directAccessGrantsEnabled: false` cho cả hai client | `check-realm.sh` |
| §2.5 | Ưu tiên xác thực client bất đối xứng (mTLS, `private_key_jwt`) | `batch-worker` dùng `private_key_jwt` ES256 | `client-credentials.sh` |
| §4.4 | Mix-up: client kiểm `iss` trong response | Keycloak gửi `iss` (RFC 9207); script so `iss` với issuer | trace PKCE |
| §4.5 | Chặn tiêm mã uỷ quyền: PKCE (hoặc `nonce`) | PKCE + `nonce` | dùng lại `code` bị từ chối |
| §4.7 | CSRF: PKCE hoặc `state` một lần | script sinh `state` ngẫu nhiên và so khi nhận | trace PKCE |
| §4.8 | PKCE downgrade: auth request không có challenge thì token request có verifier phải bị từ chối | Keycloak bắt buộc challenge với `web-app` → không có đường downgrade | `pkce-negative.sh` |
| §4.13 | Reverse proxy kết thúc TLS phải xoá header nội bộ client tự gửi | Envoy xoá `X-User` trước khi đặt lại (tuần 4) | S8 |

## 3. Client Credentials + `private_key_jwt` (RFC 7523, OIDC Core §9)

Client không gửi secret dùng chung. Nó tự ký một JWT ngắn hạn (client assertion) gồm
`iss = sub = client_id`, `aud` = issuer của AS, `jti` ngẫu nhiên, `iat`, và `exp` (lab: 60 s).
AS kiểm chữ ký bằng khoá công khai đã đăng ký và nhớ `jti` để chặn dùng lại. Lợi ích so với
`client_secret`: AS chỉ giữ khoá công khai, nên lộ DB của AS không lộ được cách mạo danh client
(tài sản #3 chỉ nằm ở máy client).

## 4. Câu hỏi tự kiểm

1. Vì sao `state` vẫn cần khi đã có PKCE? (Gợi ý: PKCE chặn tiêm code; client chưa dùng
   PKCE hoặc phiên trình duyệt vẫn cần chống CSRF; RFC 9700 cho phép PKCE thay `state` nếu AS hỗ trợ.)
2. `code_verifier` 43 ký tự base64url có bao nhiêu bit entropy? (32 byte = 256 bit.)
3. Nếu `redirect_uri` cho phép wildcard `http://localhost:3000/*`, kẻ tấn công làm được gì?
