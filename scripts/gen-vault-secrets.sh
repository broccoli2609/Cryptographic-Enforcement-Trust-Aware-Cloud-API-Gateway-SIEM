#!/usr/bin/env bash
# Tuần 9 T5 — sinh 3 token Vault ngẫu nhiên vào secrets/vault/ (tài sản #4, TB4). Chạy trước `make up`.
#   root.token         root token của Vault dev (chỉ vault + vault-init đọc) — tài sản #4
#   digester.token     token của digester: CHỈ transit/sign/siem-digest      (kms/policies/digester.hcl)
#   profile-api.token  token của profile-api: CHỈ encrypt/decrypt pii-enc    (kms/policies/profile-api.hcl, dùng từ tuần 10)
#
# Vault dev giữ mọi thứ trong RAM: mỗi lần container vault khởi động lại là một Vault trống.
# vault-init (kms/setup.sh) tạo lại khoá, policy và token với ĐÚNG các giá trị trong các file này,
# nên app không phải đổi cấu hình. Các file đi vào container bằng Docker secrets (/run/secrets/…),
# không qua biến môi trường (luật 8, ST4).
#
# Quyền 644 trong thư mục 700 — giống secrets/tls/envoy.key (quyết định 2026-10-17): Docker
# secrets của compose (không swarm) là bind mount giữ nguyên quyền file, mà container chạy uid khác
# chủ file (vault = 100, digester = 65532). Thư mục 700 chặn user khác trên máy.
#
#   ./scripts/gen-vault-secrets.sh            # tạo file còn thiếu, không ghi đè file đã có
#   ./scripts/gen-vault-secrets.sh --rotate   # cấp lại cả 3 token (sau đó: docker compose up -d --force-recreate vault)
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

DIR="$ROOT/secrets/vault"
mkdir -p "$DIR"
chmod 700 "$ROOT/secrets" "$DIR"

for name in root digester profile-api; do
  f="$DIR/$name.token"
  if [ -f "$f" ] && [ "${1:-}" != --rotate ]; then
    echo "  giữ nguyên  secrets/vault/$name.token"
    continue
  fi
  # 24 byte ngẫu nhiên từ CSPRNG của OpenSSL = 192 bit, in hex. Tiền tố "t09-" để nhận ra token
  # của lab trong log và để không trùng tiền tố "hvs." mà Vault dành cho token tự sinh.
  # Ghi qua file tạm rồi mv: không bao giờ có file token viết dở.
  tmp=$(mktemp "$DIR/.$name.XXXXXX")
  printf 't09-%s' "$(openssl rand -hex 24)" > "$tmp"
  chmod 644 "$tmp"
  mv -f "$tmp" "$f"
  echo "  đã tạo      secrets/vault/$name.token ($(redact "$name" "$(cat "$f")"))"
done
ls -l "$DIR" | sed 1d | awk '{print "  " $1, $NF}'
