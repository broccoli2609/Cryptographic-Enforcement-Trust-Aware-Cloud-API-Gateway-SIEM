#!/bin/sh
# Lệnh khởi động container vault (tuần 9 T5): Vault ở chế độ dev — dữ liệu trong RAM, tự unseal.
# Chỉ dùng cho lab (decisions 2026-09-25, 2026-11-13). Mỗi lần khởi động lại là một Vault TRỐNG;
# vault-init (kms/setup.sh) dựng lại khoá, policy, token, audit device.
#
# Root token lấy từ Docker secret (secrets/vault/root.token), không qua biến môi trường (luật 8):
# biến shell ROOT không được export nên không vào môi trường của tiến trình vault. Giá trị vẫn nằm
# trong tham số dòng lệnh của PID 1 — chỉ thấy được từ BÊN TRONG container này.
#
# Lưu ý (luật telemetry): Vault dev in "Root Token: …" ra stdout lúc khởi động → `docker logs vault`
# có root token. Vì vậy stdout của Vault KHÔNG được đưa vào SIEM; audit device ghi ra FILE riêng
# (/vault/logs/audit.log) và Vector đọc file đó.
set -eu
ROOT=$(cat /run/secrets/vault_root_token)
[ -n "$ROOT" ] || { echo "thiếu /run/secrets/vault_root_token — chạy ./scripts/gen-vault-secrets.sh" >&2; exit 1; }
exec vault server -dev \
  -dev-listen-address=0.0.0.0:8200 \
  -dev-root-token-id="$ROOT" \
  -dev-no-store-token
