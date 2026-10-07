# Tiến độ

Cập nhật lần cuối: 2026-10-07

## Đang làm

**Tuần 3 T5 (08/10):** đọc oauth.com (Authorization Code + PKCE) và RFC 9700; tạo realm Keycloak, 2 client, 4 user có role và claim `dept`, `tier`. Export realm vào `idp/`.

## Tiếp theo

**Tuần 3 T6 (09/10):** script curl chạy Auth Code + PKCE tự sinh `code_verifier`/`code_challenge`; trace vào `docs/traces/`; Client Credentials + `private_key_jwt`.

## Đã xong

- [x] Tuần 1: bảng 19 tài sản, sơ đồ 4 plane, trust boundary TB1a–TB6 (sơ đồ trong `architecture/`)
- [x] Tuần 2 T5: data flow F0–F6, threat model T1–T11 (bỏ T6), ghi chú RFC 9846 §2 + §7 — tóm tắt trong `security-model.md`
- [x] Tuần 2 T6 (phần code): scaffold repo, `docker-compose.yml`, 2 backend Go rỗng (5 unit test qua)
- [x] Tuần 2 T6 (phần máy, làm bù 07/10): repo ở `~/topic09-lab` + remote GitHub; Docker Engine, Go 1.27.1, linux-tools; `.env` (mật khẩu admin ngẫu nhiên, quyền 600); `check-env` exit 0; perf đếm được cycles; lab lên, smoke test 9/9 PASS

## Kết quả cần ghi lại

| Mục | Kết quả | Ghi ở đâu |
|---|---|---|
| Máy | i7-7500U (2 nhân/4 luồng); WSL2 kernel 6.18.40.1, Ubuntu 24.04.5; WSL 7.7 GiB RAM (host 15.9 GB), không có `.wslconfig` | — |
| `check-env.sh` (07/10) | exit 0 — Docker 29.8.2, Compose v5.6.0, Go 1.27.1, perf 6.8.12 (`linux-tools-6.8.0-146`), `perf_event_paranoid` = 2 | nhật ký phiên |
| perf đếm được cycles? | **Có** — `perf stat -- ls`: 795145 `cycles:u`, 579106 `instructions:u` (chỉ user-space vì paranoid = 2) | `docs/evidence/perf-check-2026-10-07.txt` |
| unit test backend | 5/5 PASS; `gofmt -l` rỗng; `go vet` sạch | nhật ký phiên |
| `docker compose up -d --build` lần đầu | ~2 phút (gồm tải image) | — |
| smoke test | **9/9 PASS**, exit 0 | `docs/evidence/smoke-test-2026-10-07.txt` (ảnh chụp: chưa) |
| Soát bảo mật (phần D) | đạt: chỉ Keycloak `127.0.0.1:8080` mở ra host; image ghim; `.env` không bị theo dõi, mật khẩu không lọt vào file nào khác; 2 backend `read_only` + `cap_drop: ALL` + `no-new-privileges` + healthcheck; `topic09-backend` internal | nhật ký phiên |

## Vướng mắc / câu hỏi mở

- Docker Desktop 4.87 vẫn cài trên Windows (đang tắt). Đừng bật WSL integration cho Ubuntu — sẽ có hai lệnh `docker` trỏ hai daemon. Có thể gỡ nếu không dùng.
- Doc checklist "Dựng môi trường lab — Tuần 2 (T6)" không có trong repo, chỉ được nhắc tên.
- WSL chưa có `claude` CLI; `cach-mo-phien.md` hướng dẫn chạy `claude` trong Ubuntu, hiện đang dùng desktop app trên Windows (skill `/topic09` ở `C:\Users\games\.claude\skills\topic09`).
- `create-github-issues.sh` (thư mục D:) cần `tasks-github.csv` — chưa thấy file này.
- Giờ trong WSL là UTC (`perf-check` ghi `+00:00`), lệch giờ Việt Nam 7 tiếng — lưu ý khi đối chiếu timestamp bằng chứng và log SIEM sau này.

## Nhật ký phiên

- 2026-10-07 — tạo context pack cho Claude Code (CLAUDE.md, .claude/rules, docs/context).
- 2026-10-07 — đưa repo vào `~/topic09-lab`, giải nén context pack, tạo `.env`; giữ Docker Engine theo quyết định 06/10 — người dùng cài Docker/Go/linux-tools.
- 2026-10-07 — Tuần 2 T6 làm bù: `check-env` exit 0, perf đếm được `cycles:u`, `make test` 5/5, smoke test 9/9 PASS, soát bảo mật đạt — xong tuần 2.
- 2026-10-07 — đặt git identity + `gh auth login` trong WSL; push, PR #1 squash-merge vào `main` (`1a4ea5f`) — repo GitHub đang PUBLIC.
