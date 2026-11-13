# Topic 09 — Cryptographic Enforcement & Trust-Aware Cloud API Gateway + SIEM

Lab đồ án môn Mật mã học. Phạm vi: track A (north–south API access), C (fine-grained authorization), E (SIEM cryptographic evidence).

## Trạng thái hiện tại — tuần 8

Phân tích kiến trúc (mốc M1): [`docs/architecture-analysis.md`](docs/architecture-analysis.md).
Telemetry và SIEM: [`telemetry/README.md`](telemetry/README.md).

| Thành phần | Trạng thái |
|---|---|
| Keycloak 26.8.0 (`start-dev`) | realm `topic09` import từ `idp/realm-topic09.json`: client `web-app` (public, PKCE S256), `web-app-dpop` (PKCE + DPoP bắt buộc), `batch-worker` (`private_key_jwt` ES256), 4 user có role + `dept` + `tier`; chỉ mở ở `127.0.0.1:8080` |
| Envoy 1.39.4 (distroless) | TLS 1.3 only; `:8443` = **P1**, `:8444` = **P0** (chỉ `jwt_authn`), `:8445` = **P2** (P1 + DPoP); chỉ mở ở `127.0.0.1` |
| `auth-svc` (Go, gRPC ext_authz) | JWT chặt (allow-list `alg`, `iss`/`aud`/`exp`/`nbf`/`iat`/`typ`, JWKS cache TTL); hỏi OPA; P2: kiểm DPoP proof đủ 12 bước RFC 9449 §4.3 + cache `jti` chống replay; fail closed |
| OPA 1.21.4 (PDP) | `policy/authz.rego`: RBAC theo route + method, ABAC `dept`/`tier`, mặc định từ chối; 33 `opa test`; không mở port, mạng riêng chỉ chung với auth-svc |
| `orders-api`, `profile-api` (Go) | kiểm quyền mức đối tượng (`owner_id`, manager cùng phòng) và mức thuộc tính (`salary_band` chỉ HR, chặn mass assignment); ghi `backend_object_authz` vào log; không mở port ra host |
| Vector 0.60.0 | đọc log của 6 container (5 nguồn), đổi về `telemetry/schema.json` (27 trường mục 13.1 đề bài), băm HMAC định danh, chỉ giữ trường trong schema, che giá trị dạng token; không mở port |
| OpenSearch 3.8.0 (SIEM) | index `topic09-events`, mapping `dynamic: strict` sinh từ schema; không mở port, mạng riêng chỉ chung với Vector |
| Vault, digester, hash chain | tuần 9 |

## Chạy lần đầu

```bash
./scripts/check-env.sh          # Docker, Go, perf đã đủ chưa
cp .env.example .env            # rồi đặt KC_ADMIN_PASSWORD, LAB_USER_PASSWORD (ngẫu nhiên), SIEM_HMAC_KEY (openssl rand -hex 32)
./scripts/gen-certs.sh          # CA nội bộ + cert TLS cho Envoy → secrets/tls/ (không commit)
docker compose up -d --build
./scripts/batch-worker-key.sh   # khoá batch-worker → secrets/batch-worker/, đăng ký cert vào Keycloak
./scripts/smoke-test.sh         # 26 mục PASS là đạt (tuần 8)
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
| `make failclosed` | dừng auth-svc → P1/P2 403; dừng hoặc treo OPA → P1 503 |
| `make policy-test` | `opa fmt` + `opa check --strict` + `opa test` (chạy bằng image OPA) |
| `make authz-test` | RBAC/ABAC đầu-cuối qua P1 bằng token thật |
| `make dpop-login` | Auth Code + PKCE + DPoP (trace, token có `cnf.jkt`) |
| `make dpop-test` | P2: replay, token bị trộm, proof sai, hạ cấp sang Bearer |
| `make object-authz-test` | BOLA/BFLA/property-level đầu-cuối, log 2 tầng gateway ↔ backend |
| `make vector-validate` | cú pháp `vector.yaml` + 21 unit test đường ống + schema ↔ Vector ↔ mapping (không cần lab chạy) |
| `make schema-test` | log thô của 5 nguồn ↔ `telemetry/schema.json` |
| `make siem-test` | đường ống đầu-cuối: 5 nguồn → SIEM, HMAC đúng khoá, chèn token, scanner, mapping strict |
| `make siem-scan` | scanner SR-10: token / khoá / mã uỷ quyền / bí mật / định danh thô trong SIEM và `dataset/` |
| `make siem-search` | 20 sự kiện mới nhất trong SIEM |
| `make evidence` | chạy lại mọi kiểm tra tuần 3–8, lưu vào `docs/evidence/`, `docs/traces/` |
| `make perf-check` | kiểm `perf` đếm được cycles không, lưu vào `docs/evidence/` |

## Cấu trúc thư mục (theo mục 21 đề bài)

```
architecture/   sơ đồ 4 plane, trust boundary, data flow (.drawio + .png)
workloads/      orders-api, profile-api (Go)
idp/            realm Keycloak dạng code (tuần 3)
gateway/        envoy.yaml (P0/P1/P2) + auth-svc/ (Go, ext_authz: JWT, OPA, DPoP) — tuần 4–6
policy/         OPA/Rego + opa test (tuần 5)
telemetry/      schema.json (27 trường mục 13.1), Vector, mapping OpenSearch, scanner — tuần 8
kms/ detections/ dataset/ benchmarks/ tests/   — các tuần sau
docs/architecture-analysis.md   phân tích kiến trúc (M1)
docs/notes/     ghi chú đọc (OAuth/PKCE/RFC 9700, Rego/OPA, DPoP/RFC 9449)
docs/evidence/  bằng chứng (kết quả kiểm, đo, ảnh chụp)
docs/traces/    HTTP trace (đã che token và mã uỷ quyền)
scripts/        cài đặt, kiểm tra, client OAuth bằng curl (scripts/lib/common.sh)
```

Thư mục `identity/` (SPIFFE/SPIRE) không có vì track B nằm ngoài phạm vi.

## Quy tắc

- Không commit `.env`, `secrets/` (khoá riêng, cert), token (xem `.gitignore`).
- Bằng chứng trong `docs/` không chứa token thô hay mã uỷ quyền: script che bằng độ dài + tiền tố SHA-256.
- Ghim phiên bản image, không dùng `:latest`.
- Backend, auth-svc, OPA, Vector và OpenSearch không bao giờ có mục `ports:` — chỉ gateway (và Keycloak ở localhost) được mở ra ngoài.
- SIEM và `dataset/` không chứa token, khoá, mã uỷ quyền hay định danh thô: định danh được băm HMAC ở Vector, `make siem-scan` kiểm tự động.
