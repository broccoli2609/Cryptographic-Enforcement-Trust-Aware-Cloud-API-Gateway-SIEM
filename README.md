# Topic 09 — Cryptographic Enforcement & Trust-Aware Cloud API Gateway + SIEM

Lab đồ án môn Mật mã học. Phạm vi: track A (north–south API access), C (fine-grained authorization), E (SIEM cryptographic evidence).

## Trạng thái hiện tại — tuần 4 (mốc M1)

| Thành phần | Trạng thái |
|---|---|
| Keycloak 26.8.0 (`start-dev`) | realm `topic09` import từ `idp/realm-topic09.json`: client `web-app` (public, PKCE S256), `batch-worker` (`private_key_jwt` ES256), 4 user có role + `dept` + `tier`; chỉ mở ở `127.0.0.1:8080` |
| Envoy 1.39.4 (distroless) | TLS 1.3 only; `:8443` = **P1** (`jwt_authn` + ext_authz auth-svc), `:8444` = **P0** (chỉ `jwt_authn`); chỉ mở ở `127.0.0.1` |
| `auth-svc` (Go, gRPC ext_authz) | kiểm JWT chặt: allow-list `alg`, `iss`/`aud`/`exp`/`nbf`/`iat`/`typ`, JWKS cache có TTL; fail closed |
| `orders-api`, `profile-api` (Go) | `GET /healthz`, `GET /{orders,profile}/whoami` (trả danh tính gateway đặt); route khác = 501; không mở port ra host |
| OPA | tuần 5 |
| Vector, OpenSearch, Vault, digester | tuần 8–9 |

## Chạy lần đầu

```bash
./scripts/check-env.sh          # Docker, Go, perf đã đủ chưa
cp .env.example .env            # rồi đặt KC_ADMIN_PASSWORD, LAB_USER_PASSWORD (ngẫu nhiên)
./scripts/gen-certs.sh          # CA nội bộ + cert TLS cho Envoy → secrets/tls/ (không commit)
docker compose up -d --build
./scripts/batch-worker-key.sh   # khoá batch-worker → secrets/batch-worker/, đăng ký cert vào Keycloak
./scripts/smoke-test.sh         # 16 mục PASS là đạt
```

Gọi API qua gateway (token của alice qua Auth Code + PKCE):

```bash
TOKEN=$(./scripts/pkce-login.sh alice --token)
curl --cacert secrets/tls/ca.crt -H "Authorization: Bearer $TOKEN" https://localhost:8443/orders/whoami
```

Keycloak admin console: http://localhost:8080 (user/mật khẩu trong `.env`).

## Lệnh hay dùng

| Lệnh | Làm gì |
|---|---|
| `make up` / `make down` | bật / tắt lab (dữ liệu Keycloak giữ trong volume) |
| `make ps`, `make logs` | trạng thái, log |
| `make test` | unit test của backend và auth-svc |
| `make pkce`, `make pkce-negative` | Auth Code + PKCE (trace) / 7 ca PKCE sai |
| `make cc` | Client Credentials + `private_key_jwt` + 5 ca sai |
| `make tls` | gateway chỉ nói TLS 1.3 |
| `make gateway-test` | kiểm đầu-cuối P1 và P0 (token đúng 200, token hỏng 401) |
| `make failclosed` | dừng auth-svc → P1 phải trả 403 |
| `make evidence` | chạy lại mọi kiểm tra tuần 3–4, lưu vào `docs/evidence/`, `docs/traces/` |
| `make perf-check` | kiểm `perf` đếm được cycles không, lưu vào `docs/evidence/` |

## Cấu trúc thư mục (theo mục 21 đề bài)

```
architecture/   sơ đồ 4 plane, trust boundary, data flow (.drawio + .png)
workloads/      orders-api, profile-api (Go)
idp/            realm Keycloak dạng code (tuần 3)
gateway/        envoy.yaml (P0/P1) + auth-svc/ (Go, ext_authz) — tuần 4
policy/ kms/ telemetry/ detections/ dataset/ benchmarks/ tests/   — các tuần sau
docs/notes/     ghi chú đọc (OAuth, PKCE, RFC 9700)
docs/evidence/  bằng chứng (kết quả kiểm, đo, ảnh chụp)
docs/traces/    HTTP trace (đã che token và mã uỷ quyền)
scripts/        cài đặt, kiểm tra, client OAuth bằng curl (scripts/lib/common.sh)
```

Thư mục `identity/` (SPIFFE/SPIRE) không có vì track B nằm ngoài phạm vi.

## Quy tắc

- Không commit `.env`, `secrets/` (khoá riêng, cert), token (xem `.gitignore`).
- Bằng chứng trong `docs/` không chứa token thô hay mã uỷ quyền: script che bằng độ dài + tiền tố SHA-256.
- Ghim phiên bản image, không dùng `:latest`.
- Backend và auth-svc không bao giờ có mục `ports:` — chỉ gateway (và Keycloak ở localhost) được mở ra ngoài.
