# Topic 09 — Cryptographic Enforcement & Trust-Aware Cloud API Gateway + SIEM

Lab đồ án môn Mật mã học. Phạm vi: track A (north–south API access), C (fine-grained authorization), E (SIEM cryptographic evidence).

## Trạng thái hiện tại — tuần 2

| Thành phần | Trạng thái |
|---|---|
| Keycloak 26.8.0 (`start-dev`) | chạy, chỉ mở ở `127.0.0.1:8080` |
| `orders-api`, `profile-api` (Go) | rỗng: `GET /healthz` = 200, route khác = 501; không mở port ra host |
| Envoy, auth-svc, OPA | tuần 4–5 |
| Vector, OpenSearch, Vault, digester | tuần 8–9 |

## Chạy lần đầu

```bash
./scripts/check-env.sh          # Docker, Go, perf đã đủ chưa
cp .env.example .env            # rồi sửa KC_ADMIN_PASSWORD
docker compose up -d --build
./scripts/smoke-test.sh         # 9 mục PASS là đạt
```

Keycloak admin console: http://localhost:8080 (user/mật khẩu trong `.env`).

## Lệnh hay dùng

| Lệnh | Làm gì |
|---|---|
| `make up` / `make down` | bật / tắt lab (dữ liệu Keycloak giữ trong volume) |
| `make ps`, `make logs` | trạng thái, log |
| `make test` | unit test của backend |
| `make perf-check` | kiểm `perf` đếm được cycles không, lưu vào `docs/evidence/` |

## Cấu trúc thư mục (theo mục 21 đề bài)

```
architecture/   sơ đồ 4 plane, trust boundary, data flow (.drawio + .png)
workloads/      orders-api, profile-api (Go)
idp/ gateway/ policy/ kms/ telemetry/ detections/ dataset/ benchmarks/ tests/   — các tuần sau
docs/evidence/  bằng chứng (kết quả perf, ảnh chụp)
docs/traces/    HTTP trace (tuần 3)
scripts/        cài đặt và kiểm tra
```

Thư mục `identity/` (SPIFFE/SPIRE) không có vì track B nằm ngoài phạm vi.

## Quy tắc

- Không commit `.env`, khoá riêng, token (xem `.gitignore`).
- Ghim phiên bản image, không dùng `:latest`.
- Backend không bao giờ có mục `ports:` — chỉ gateway được mở ra ngoài.
