---
paths:
  - "docker-compose*.yml"
  - "**/Dockerfile"
  - "**/.env.example"
---
# Luật cho docker-compose và Dockerfile

- Ghim tag image cụ thể, không `:latest`. Đổi phiên bản thì ghi vào docs/context/decisions.md.
- Chỉ Envoy và Keycloak có `ports:`; Keycloak và OpenSearch Dashboards chỉ bind `127.0.0.1`.
- Mỗi vùng tin cậy một network: backend `internal: true`; OPA chỉ chung network với auth-svc.
- Container của mình: `read_only: true`, `cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true"]`, có `healthcheck`.
- Bí mật lấy từ `.env` bằng `${VAR:?thông báo}` để thiếu là dừng; `.env` không commit, chỉ commit `.env.example`.
- Image chạy dùng distroless/nonroot khi có thể.
- Sau khi sửa: `docker compose config` hợp lệ, rồi `./scripts/smoke-test.sh` (cập nhật script nếu thêm service).
