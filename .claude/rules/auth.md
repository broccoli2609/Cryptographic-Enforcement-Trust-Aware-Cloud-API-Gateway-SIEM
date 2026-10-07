---
paths:
  - "gateway/**"
  - "idp/**"
---
# Luật cho auth-svc, Envoy, Keycloak

JWT (SR-02, RFC 8725):
- Allow-list `alg` cấu hình sẵn theo issuer; token tự chọn `alg` khác → từ chối. Không bao giờ chấp nhận `none` hay HS* khi issuer dùng khoá bất đối xứng.
- `iss` và URL JWKS ghi cứng trong cấu hình; bỏ qua `jku`, `x5u`, `jwk` trong header token.
- Kiểm `aud`, `exp`, `nbf` (lệch đồng hồ cho phép nhỏ, ghi rõ con số), và loại token bằng claim `typ` trong payload ("Bearer" với access token của Keycloak) — không nhận ID token.
- JWKS cache có TTL; `kid` lạ thì refetch nhưng giới hạn tần suất.

DPoP (SR-04, RFC 9449 §4.3, §11.1):
- Đủ 12 bước kiểm của §4.3: một header DPoP, `typ` = `dpop+jwt`, `alg` bất đối xứng, `jwk` không chứa khoá riêng, `htm`, `htu` (bỏ query/fragment), `iat` trong cửa sổ 30 giây, `ath` = hash của access token, khoá trong proof khớp `cnf.jkt`.
- Chỉ ghi `jti` vào cache **sau khi** mọi bước khác đã qua. Cache đầy thì từ chối request, không xoá mục chưa hết cửa sổ `iat`.

Gateway:
- Kiểm rẻ trước, đắt sau: định dạng, `alg`, `kid` trước khi kiểm chữ ký (T10).
- auth-svc lỗi → Envoy trả 403 (`failure_mode_allow: false`). OPA lỗi/timeout → auth-svc chặn.
- Envoy xoá mọi header danh tính client gửi (`X-User`, ...) rồi mới đặt lại.
- Keycloak: client public dùng PKCE method S256; `redirect_uri` khớp chính xác; batch-worker dùng `private_key_jwt`.
