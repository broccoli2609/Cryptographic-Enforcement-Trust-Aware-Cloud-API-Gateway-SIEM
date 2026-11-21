# kms/ — Vault Transit của lab (tuần 9)

Vault 2.1.2 chế độ **dev** (dữ liệu trong RAM, tự unseal) chỉ ở mạng `topic09-kms` (internal), không
có cổng ra host. Giữ 2 khoá Transit **không export**, mỗi khoá một việc (CR, "một khoá một mục đích"):

| Khoá | Kiểu | Dùng cho | Ai được dùng | Policy |
|---|---|---|---|---|
| `siem-digest` (tài sản #13) | ed25519 | ký digest của hash chain SIEM (M7, SR-09) | digester | `policies/digester.hcl` — chỉ `transit/sign/siem-digest` |
| `pii-enc` (tài sản #20) | aes256-gcm96 | mã hoá `salary_band` (M9, SR-13) — **tuần 10** | profile-api | `policies/profile-api.hcl` — chỉ `transit/encrypt/pii-enc` + `transit/decrypt/pii-enc` |

Cả hai khoá: `exportable=false`, `allow_plaintext_backup=false`, `deletion_allowed=false` (kể cả root
cũng không xoá được qua API). Token của app tạo với `no_default_policy=true` — không có cả
`lookup-self`/`renew-self`.

## File

| File | Việc |
|---|---|
| `vault-dev.sh` | lệnh khởi động container `vault`: đọc root token từ Docker secret rồi `exec vault server -dev` |
| `setup.sh` | container `vault-init` (chạy một lần mỗi `make up`, idempotent): audit device → Transit + 2 khoá → public key → 2 policy → 2 token |
| `policies/*.hcl` | 2 policy quyền tối thiểu |

## Secret (không bao giờ commit)

`./scripts/gen-vault-secrets.sh` (hoặc `make vault-secrets`) sinh 3 token ngẫu nhiên 192 bit vào
`secrets/vault/` (thư mục 700, file 644 — giống `envoy.key`, vì container chạy uid khác chủ file):
`root.token` (vault, vault-init), `digester.token` (digester), `profile-api.token` (profile-api, tuần 10).
Container đọc chúng ở `/run/secrets/…` (Docker secrets) — **không** qua biến môi trường (luật 8, ST4).

Vì Vault dev mất mọi thứ khi khởi động lại, `vault-init` tạo lại token với **đúng ID trong file**
(`auth/token/create-orphan id=@file`) — app không phải đổi cấu hình. Đánh đổi: Vault cảnh báo token có
ID tự đặt được băm bằng SHA-1 (thay cho HMAC-SHA256) khi làm khoá tra cứu nội bộ — chấp nhận cho lab
(băm có salt, nằm trong RAM; SHA-1 yếu ở va chạm, không yếu ở tìm ngược) — `decisions.md` 2026-11-21.

## Public key của `siem-digest`

`setup.sh` ghi `kms-public/siem-digest.json` (đầu ra `vault read transit/keys/siem-digest`) và **ghi
thêm** mọi public key mới vào `kms-public/siem-digest.history.jsonl`. Vault dev khởi động lại = khoá
MỚI nhưng vẫn là `v1`; người kiểm (`telemetry/chain_check.py`, `verify-chain` tuần 10) tin một public
key nếu nó từng được `vault-init` công bố — digest của "đời Vault" trước vẫn kiểm được.

## Audit device

`file` → `/vault/logs/audit.log` (volume `vault-audit`, mode 0644), Vector đọc bằng source `file`
(`norm_vault`). Vault HMAC mọi chuỗi bí mật trước khi ghi (token, input, plaintext, ciphertext,
signature); Vector còn bỏ hẳn các khối đó, chỉ giữ ai / làm gì / kết quả:

| Trường SIEM | Lấy từ audit | Ghi chú |
|---|---|---|
| `kms_path` | `request.path` | ví dụ `transit/sign/siem-digest` |
| `kms_operation` | `request.operation` | `update`, `read`, `list`… |
| `kms_client` | `auth.display_name` | `token-digester`, `token-profile-api`; root token của Vault dev mang tên `token` → nhận ra root bằng `kms_policies=root` |
| `kms_policies` | `auth.token_policies` | nối bằng dấu phẩy |
| `decision` / `decision_reason` | `error` | `ok`, `permission_denied`, `invalid_token`, `vault_error` |
| `kms_calls` | — | 1 với `transit/…`, 0 với `sys/…`, `auth/…` |
| `kms_key_version` | `response.data.key_version` | chỉ khi có |

**Không** đưa stdout của Vault dev vào SIEM: banner khởi động in `Root Token: …` (luật telemetry).
`docker logs` của container `vault` vì vậy có root token — ai đọc được `docker logs` đã có quyền điều
khiển Docker (TB6, T11), cùng mức với file `secrets/vault/root.token`.

## Kiểm

```bash
make kms-test       # 2 khoá đúng thuộc tính; token digester/profile-api chỉ làm được đúng việc của mình
                    # (10 + 8 thao tác bị từ chối); openssl xác minh chữ ký bằng public key đã công bố;
                    # audit có dấu vết lần bị từ chối, không chứa token/plaintext thô; token không ở env
```

## Giới hạn (residual risk)

- Vault dev: khởi động lại là mất khoá → `pii-enc` mất thì mọi `salary_band` đã mã hoá không giải mã
  được nữa. **Phải quyết trước tuần 10** (Vault server mode + storage `file` trong volume + unseal key
  trong `secrets/`, hay chấp nhận seed lại dữ liệu) — ghi ở `docs/context/progress.md`.
- `vault-init` chỉ chạy khi `docker compose up`; Vault tự khởi động lại (crash) thì phải
  `docker compose up -d vault-init` — trong lúc đó digester báo `digest_failed` (fail-closed, H9 thấy).
- Ai có `secrets/vault/digester.token` ký được digest giả tới khi token bị thay (`--rotate`).
