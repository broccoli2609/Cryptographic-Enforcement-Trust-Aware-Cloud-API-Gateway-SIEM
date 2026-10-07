# Topic 09 — Cloud API Gateway + SIEM (đồ án Mật mã học)

Lab Docker Compose trong WSL2 mô phỏng một API gateway có mật mã (JWT chặt, DPoP, OPA) và SIEM có bằng chứng toàn vẹn (hash chain + digest ký bằng Vault). Mức Đại học, làm một mình, track A + C + E, 12 tuần (24/09 → 11/12/2026), làm thứ 5 và thứ 6.

## Cách làm việc với tôi

- Trả lời tiếng Việt, xưng "tôi", gọi tôi là "bạn". Tên biến, hàm, commit message bằng tiếng Anh; comment trong code được viết tiếng Việt.
- Tôi là sinh viên đang học: trước mỗi bước, nói ngắn gọn **làm gì và vì sao**; sau khi xong, chỉ cách tôi tự kiểm.
- Lệnh cần `sudo`, cài gói hệ thống hay sửa file ngoài repo: đưa lệnh cho tôi tự chạy, không tự chạy.
- Không tự `git commit` / `git push`; cuối việc thì đề xuất commit message.
- Hỏi trước khi thêm dependency Go mới hoặc image Docker mới.
- Mỗi phiên làm **một** việc trong kế hoạch. Việc khác thì ghi vào `docs/context/progress.md`, để phiên sau.

## Đầu phiên và cuối phiên

- **Đầu phiên:** đọc `docs/context/progress.md` (ngắn). Chỉ đọc thêm khi việc cần:
  - `docs/context/plan.md` — lịch 12 tuần, mốc, thứ tự cắt khi trễ
  - `docs/context/security-model.md` — F0–F6, TB, T1–T11, SR, test S*, hunt H*
  - `docs/context/decisions.md` — các quyết định đã chốt và lý do
- **Cuối phiên:** cập nhật `progress.md` (Đang làm / Tiếp theo / 1–3 dòng nhật ký); quyết định mới thì thêm vào `decisions.md`; đề xuất commit message.

## Stack (ghim phiên bản)

| Thành phần | Phiên bản | Ghi chú |
|---|---|---|
| WSL2 Ubuntu + Docker Engine | — | Docker cài trong Ubuntu, không dùng Docker Desktop |
| Go | 1.27.x (`go.mod`: `go 1.26`) | image build `golang:1.27-alpine`, chạy `gcr.io/distroless/static-debian12:nonroot` |
| Keycloak | 26.8.0, `start-dev` | `127.0.0.1:8080`, `KC_HOSTNAME=http://localhost:8080` |
| Envoy + `auth-svc` (Go, ext_authz gRPC) | tuần 4–6 | PEP |
| OPA | tuần 5 | PDP |
| Vector → OpenSearch, Vault (dev, Transit), `digester` | tuần 8–9 | SIEM |

Profile so sánh (theo kế hoạch, **khác** mục 12.2 đề bài): P0 = bearer + Envoy `jwt_authn`; P1 = JWT chặt trong auth-svc + OPA; P2 = P1 + DPoP + hash chain + digest ký bằng Vault.

## Cấu trúc repo (theo mục 21 đề bài)

```
workloads/   orders-api, profile-api (Go) + internal/service dùng chung
gateway/     envoy.yaml (T4); auth-svc/ (Go, T4–T6)
idp/         realm export Keycloak (T3)
policy/      Rego + opa test (T5)
telemetry/   schema.json, Vector, digester/, verify-chain/ (T8–T10)
kms/         Vault policy (T9)          detections/  6 hunt query (T9)
tests/ dataset/ benchmarks/  (T10–T11)  scripts/  cài đặt, kiểm tra
architecture/  sơ đồ .drawio            docs/evidence/, docs/traces/  bằng chứng
```

## Lệnh

```bash
make up | down | ps | logs        # docker compose
make smoke                        # ./scripts/smoke-test.sh — 9 PASS là đạt
make test                         # go test ./... trong workloads/
make env-check | perf-check       # kiểm Docker/Go/perf, lưu bằng chứng perf
docker compose config             # kiểm cú pháp compose
cd workloads && go vet ./... && go test ./...
```

## Luật bảo mật không được phá (chi tiết: docs/context/security-model.md)

1. Không bao giờ log header, token, mã uỷ quyền, cookie, khoá riêng. Log route theo mẫu (`r.Pattern`), không log đường dẫn thật (SR-10).
2. Backend, OPA, Vault, Vector, OpenSearch **không** có `ports:`. Chỉ Envoy và Keycloak mở ra host, và Keycloak chỉ ở `127.0.0.1` (T5).
3. Fail-closed ở hai lớp: Envoy `failure_mode_allow: false`; auth-svc lỗi/timeout khi gọi OPA thì chặn (SR-11).
4. JWT: allow-list `alg`, pin `iss` + URL JWKS, kiểm `aud`/`exp`/`nbf`, phân biệt loại token bằng claim `typ` trong payload; bỏ qua `jku`/`x5u`/`jwk` (SR-02).
5. Envoy xoá header danh tính client gửi lên trước khi đặt `X-User` (RFC 9700 §4.13).
6. Ghim phiên bản image, không `:latest`. Không commit `.env` hay khoá.
7. Không sửa test cho "xanh" bằng cách nới điều kiện bảo mật; báo tôi nếu test bảo mật fail.

## Ghi chú

- Code đặt trong `~/topic09-lab` (ổ Linux của WSL), không đặt dưới `/mnt/c`.
- Kết quả đo và ảnh chụp lưu vào `docs/evidence/`, HTTP trace vào `docs/traces/` — đây là bằng chứng cho traceability matrix tuần 12.
