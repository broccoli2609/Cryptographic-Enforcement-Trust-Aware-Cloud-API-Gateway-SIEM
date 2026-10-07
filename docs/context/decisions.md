# Quyết định đã chốt

Mỗi dòng: ngày — quyết định — lý do. Thêm dòng mới ở cuối; đổi ý thì thêm dòng mới ghi "thay cho ...", không xoá dòng cũ.

- 2026-09-18 — Mức Đại học, làm một mình, track A + C + E; cắt B, D, F — vừa sức 12 tuần × 2 buổi; phần cắt viết thành residual risk.
- 2026-09-18 — Lab chạy Docker Compose trong WSL2, không Kubernetes — đủ cho phạm vi Đại học (mục 18 đề bài), nhẹ máy.
- 2026-09 — auth-svc, backend, digester, verify-chain viết bằng Go — hệ sinh thái Envoy ext_authz/gRPC, thư viện crypto chuẩn, `go test -bench` cho benchmark.
- 2026-09-25 — Thêm Vault dev + Transit chỉ để ký digest SIEM; khoá ký token của Keycloak vẫn là khoá phần mềm — giữ phạm vi, ghi là rủi ro còn lại của T7.
- 2026-10-03 — Profile P0/P1/P2 định nghĩa theo kế hoạch, khác mục 12.2 đề bài — so sánh từng lớp một; báo cáo phải nêu.
- 2026-10-03 — Fail-closed ở hai lớp: Envoy `failure_mode_allow: false`, auth-svc chặn khi OPA lỗi/timeout.
- 2026-10-03 — DPoP: cửa sổ `iat` 30 giây; cache `jti` là map có TTL (chưa cần Redis), chỉ ghi sau khi mọi bước kiểm qua, đầy thì từ chối.
- 2026-10-03 — OPA không mở port, chỉ chung network với auth-svc (REST API của OPA mặc định không xác thực).
- 2026-10-03 — Digester lấy đầu chuỗi từ Vector, không từ OpenSearch; digest có số thứ tự, thời điểm, chữ ký digest trước; lưu public key + version kèm digest.
- 2026-10-03 — Bật audit device của Vault và đưa về SIEM (mục 11.1 đề bài).
- 2026-10-06 — Docker Engine cài trong Ubuntu, không Docker Desktop — nhẹ, đúng hướng dẫn chính thức.
- 2026-10-06 — Ghim image: `quay.io/keycloak/keycloak:26.8.0`, `golang:1.27-alpine`, `gcr.io/distroless/static-debian12:nonroot`, `busybox:1.37` (chỉ dùng trong smoke test).
- 2026-10-06 — Keycloak `start-dev` + DB H2 trong volume; `KC_HOSTNAME=http://localhost:8080` để `iss` cố định; chỉ bind `127.0.0.1:8080`.
- 2026-10-06 — Mạng: `topic09-identity` (Keycloak), `topic09-backend` (`internal: true`, 2 backend). Backend không có `ports:`.
- 2026-10-06 — Backend log JSON qua `slog`, không log header, route theo `r.Pattern`, `request_id` tối đa 64 ký tự; image distroless, healthcheck bằng `/app -healthcheck`.
- (chờ kết quả) — Đo cycles bằng perf hay chuyển sang `go test -bench` (`ns/op`) + `benchstat`: quyết sau khi chạy `scripts/check-perf.sh`.
- 2026-10-07 — Đo cycles bằng perf (`cycles:u`, `perf_event_paranoid` = 2), vẫn chạy kèm `go test -bench` (`ns/op`) + `benchstat`; thay cho dòng "(chờ kết quả)" ở trên — `check-perf.sh` đếm được cycles trên i7-7500U trong WSL2 (`docs/evidence/perf-check-2026-10-07.txt`); verify JWT/DPoP chạy ở user-space nên `:u` đủ.
