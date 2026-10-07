# Mô hình bảo mật — tóm tắt để tra cứu

Nguồn đầy đủ: các doc tuần 1–2 (tài sản, trust boundary, data flow, threat model) và đề bài Topic 09 mục 4–7, 11.2, 13.2. Phạm vi: track A + C + E. **Ngoài phạm vi:** track B (F3, T6, SR-05), D (SR-07), F.

## Profile (theo kế hoạch, khác mục 12.2 đề bài — báo cáo phải ghi rõ)

- **P0:** TLS 1.3 + bearer JWT, Envoy `jwt_authn`.
- **P1:** P0 + auth-svc kiểm JWT chặt + OPA.
- **P2:** P1 + DPoP (`cnf.jkt`, proof mỗi request, cache `jti`) + hash chain + digest ký bằng Vault.

## Tài sản (#n dùng trong threat model)

| # | Tài sản | Phân loại |
|---|---|---|
| 1 | Khoá riêng ký token (Keycloak realm) | Tối mật |
| 2 | Tài khoản, mật khẩu, role, `dept`, `tier` | Tối mật |
| 3 | Khoá riêng của batch-worker (`private_key_jwt`) | Tối mật |
| 4 | Tài khoản quản trị (Keycloak admin, Vault root token, OpenSearch admin) | Tối mật |
| 5 | Mã uỷ quyền + `code_verifier` | Mật |
| 6 | Access token | Mật |
| 7 | ID token | Mật |
| 8 | Refresh token | Mật |
| 9 | Khoá riêng DPoP của client | Mật |
| 10 | Khoá riêng CA nội bộ + root cert | Tối mật / Công khai |
| 11 | Khoá riêng TLS của Envoy | Tối mật |
| 12 | JWKS | Công khai (cần toàn vẹn) |
| 13 | Khoá ký digest `siem-digest` (Vault) | Tối mật |
| 14 | Khoá HMAC giả danh định danh (Vector) | Mật |
| 15 | Policy Rego | Nội bộ |
| 16 | File cấu hình (alg allow-list, issuer, aud, envoy.yaml, compose) | Nội bộ |
| 17 | Dữ liệu đơn hàng, `owner_id` | Nội bộ |
| 18 | Hồ sơ nhân viên, `salary_band` | Mật |
| 19 | Log bảo mật + hash chain + digest | Mật |

## Trust boundary

| TB | Từ → tới | Bằng chứng để tin | Yếu? |
|---|---|---|---|
| TB1a | Client → Envoy | TLS 1.3, chữ ký JWT, DPoP proof (P2) | |
| TB1b | Client ↔ Keycloak | Mật khẩu, PKCE S256, `redirect_uri` cố định, TLS | |
| TB2a | Keycloak → auth-svc (JWKS) | URL JWKS + `iss` ghi cứng | |
| TB2b | auth-svc → OPA | Chỉ vị trí mạng | **Yếu** |
| TB3 | Envoy → backend | Chỉ vị trí mạng; Envoy đặt `X-User` | **Yếu** |
| TB4 | digester → Vault | Vault token quyền hẹp | |
| TB5 | service → Vector → OpenSearch | Hash chain + digest sau Vector; trước Vector chỉ mạng | **Yếu** |
| TB6 | Control/Admin → mọi container | Quyền trên máy WSL, Docker, git | **Yếu** (giả định máy dev tin cậy) |

## Data flow

| F | Đường đi trong lab | Qua TB | SR chính |
|---|---|---|---|
| F0 | CA → Envoy; Keycloak → JWKS → auth-svc; Vault → `siem-digest`; `.env` → khoá HMAC | TB6, TB2a | SR-08 |
| F1 | Client ↔ Keycloak (Auth Code + PKCE; batch-worker: Client Credentials + `private_key_jwt`) | TB1b | SR-03, SR-01, SR-10 |
| F2 | Client → Envoy → auth-svc → orders/profile | TB1a, TB3 | SR-01, 02, 04, 06, 11 |
| F3 | service ↔ service — **ngoài phạm vi** | — | SR-05 |
| F4 | auth-svc ↔ OPA | TB2b | SR-06, SR-11 |
| F5 | mọi service + Vault audit → Vector → OpenSearch; digester → Vault | TB5, TB4 | SR-09, SR-10 |
| F6 | Người vận hành → Keycloak / OPA / Envoy (làm tay theo runbook) | TB6 | SR-12 |

## Threat → yêu cầu → cơ chế → kiểm chứng (bản nháp traceability matrix)

| Threat | SR | Cơ chế | Test | Hunt | Còn hở |
|---|---|---|---|---|---|
| T1 Token theft/replay | 04, 10 | P2: DPoP + cache `jti`, `iat` 30 s; refresh token xoay vòng/gắn DPoP | S3, S4 | H1, H2 | P0/P1 (có chủ đích); XSS tạo proof mới |
| T2 JWT validation failure | 02, 08 | Allow-list alg, pin iss + JWKS, aud/exp/nbf/typ, JWKS cache TTL | 8 unit test (T4), S1, S2, xoay khoá | H3 | Khoá realm lộ (T7) |
| T3 Broken authentication | 03 | PKCE S256, redirect_uri chính xác, brute-force detection (mặc định tắt), `private_key_jwt` | Test PKCE sai/thiếu | — | Không MFA; credential stuffing |
| T4 Broken authorization | 06 | OPA RBAC + ABAC; backend kiểm `owner_id`, `salary_band` | S6, S7 | H4, H5 | Lỗi logic backend |
| T5 Gateway bypass | 01, 06 | Backend không `ports:`; Envoy xoá header danh tính; backend tự kiểm quyền | S8 | — | Container bị chiếm trong mạng |
| T7 KMS/key compromise | 08 | Vault token chỉ `transit/sign/siem-digest`; không export; audit device | S9 | — | Khoá Keycloak là khoá phần mềm |
| T8 Policy compromise | 06, 11 | `default allow := false`; mount ro + git; OPA chỉ chung network auth-svc; fail-closed 2 lớp | `docker stop opa` → 403/503; failure injection | H4 | Ai sửa được git + restart (T11) |
| T9 Telemetry tampering | 09, 10 | Hash chain, digest có seq + prev sig, `verify-chain`, scanner | S10 | H9 | Log giả trước Vector; sự kiện sau digest gần nhất |
| T10 Resource abuse | 11 | Kiểm rẻ trước; giới hạn header; cache `jti` có trần, đầy thì từ chối | S11 (k6) | — | DoS cỡ lớn |
| T11 Cloud-account abuse | 12 | Không mật khẩu mặc định; console chỉ 127.0.0.1; admin events → SIEM | Kiểm tay | — | Ai có Docker là có tất cả |

T6 (service identity abuse) bỏ vì không có F3/workload identity ở mức Đại học; phần còn lại nằm ở T5.

## Security requirements (đề bài mục 7)

SR-01 TLS 1.3, chặn gọi thẳng backend · SR-02 JWT allow-list + iss/aud/exp/nbf/typ · SR-03 Auth Code + PKCE S256 · SR-04 sender-constrained (DPoP) · SR-05 workload identity (ngoài phạm vi) · SR-06 gateway là PEP, quyết định có policy version + lý do, backend vẫn kiểm object/property · SR-07 HTTP Message Signatures (ngoài phạm vi) · SR-08 vòng đời khoá: kid/version, xoay chồng, audit · SR-09 telemetry có toàn vẹn/nguồn gốc · SR-10 SIEM không có secret/token, có giả danh · SR-11 fail closed · SR-12 thay đổi có người được uỷ quyền + dấu vết.

## Kịch bản (đề bài 13.2) và hunt dùng trong đồ án

S0 bình thường · S1 hết hạn/sai iss/aud · S2 alg cấm · S3 bearer replay · S4 DPoP sai/replay · S6 leo quyền policy · S7 BOLA/BFLA · S8 gateway bypass · S9 dùng KMS bất thường · S10 sửa/xoá log · S11 tải cao chữ ký sai. (S5 mTLS ngoài phạm vi.)
Hunt: H1 token replay · H2 sender-binding mismatch · H3 alg/kid bất thường · H4 leo quyền authz · H5 dò BOLA/BFLA · H9 telemetry bị sửa.
