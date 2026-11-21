#!/bin/sh
# vault-init (tuần 9 T5): dựng cấu hình Vault cho lab. Chạy MỘT LẦN mỗi lần `docker compose up`,
# sau khi vault healthy và trước digester. Chạy lại bao nhiêu lần cũng được (idempotent): bước nào
# đã có thì bỏ qua — nên dùng được cả khi Vault đang chạy lẫn khi Vault dev vừa khởi động lại (trống).
#
#   1. audit device  → file /vault/logs/audit.log (volume vault-audit, Vector đọc) — làm ĐẦU TIÊN để
#                      mọi thao tác sau (kể cả của chính script này) đều có dấu vết (SR-08, SR-12)
#   2. Transit       → khoá siem-digest (ed25519, ký digest SIEM, tài sản #13)
#                      khoá pii-enc     (aes256-gcm96, mã hoá salary_band từ tuần 10, tài sản #20)
#                      cả hai: không export, không cho backup dạng rõ, không cho xoá
#   3. public key    → /vault/file/siem-digest.json (volume kms-public, digester đọc để ghi kèm
#                      digest — Vault dev mất khoá khi restart, luật telemetry)
#   4. policy        → kms/policies/{digester,profile-api}.hcl
#   5. token         → ID lấy từ Docker secret; orphan, không policy "default", hạn 720 giờ
#
# Root token chỉ dùng ở đây và trong test quản trị; app không bao giờ có root token (luật telemetry).
# Giá trị token đi vào Vault bằng cú pháp key=@file của CLI — không nằm trên dòng lệnh.
set -eu
export VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN=$(cat /run/secrets/vault_root_token)
export VAULT_TOKEN
TTL=720h   # < 768h (max_lease_ttl mặc định); Vault dev hiếm khi chạy liền 30 ngày

say() { echo "vault-init: $*"; }

# --- 1. audit device. mode=0644: Vector đọc được (Vector bỏ mọi capability nên root trong Vector
#        cũng không vượt được quyền file). Vault mặc định HMAC mọi chuỗi bí mật trong audit log
#        (token, input/plaintext/ciphertext/signature) — không có giá trị thô nào trong file.
if vault audit list 2>/dev/null | grep -q '^file/'; then
  say "audit device file/ đã bật"
else
  vault audit enable -path=file file file_path=/vault/logs/audit.log mode=0644 >/dev/null
  say "bật audit device file/ → /vault/logs/audit.log"
fi

# --- 2. Transit + 2 khoá
if vault secrets list 2>/dev/null | grep -q '^transit/'; then
  say "secrets engine transit/ đã bật"
else
  vault secrets enable transit >/dev/null
  say "bật secrets engine transit/"
fi

mkkey() { # mkkey TÊN KIỂU
  if vault read transit/keys/"$1" >/dev/null 2>&1; then
    say "khoá $1 đã có"
  else
    vault write -f transit/keys/"$1" type="$2" exportable=false allow_plaintext_backup=false >/dev/null
    say "tạo khoá $1 ($2, không export)"
  fi
  # deletion_allowed mặc định false; đặt lại cho chắc (T7: không ai xoá được khoá qua API).
  vault write transit/keys/"$1"/config deletion_allowed=false >/dev/null
}
mkkey siem-digest ed25519
mkkey pii-enc aes256-gcm96

# --- 3. public key của siem-digest (mọi version). Ghi file tạm rồi mv để digester không đọc phải file dở.
vault read -format=json transit/keys/siem-digest > /vault/file/.siem-digest.json.tmp
mv -f /vault/file/.siem-digest.json.tmp /vault/file/siem-digest.json
say "ghi public key siem-digest → kms-public/siem-digest.json"
#     Lịch sử (chỉ ghi thêm): Vault dev khởi động lại = khoá MỚI nhưng vẫn là "v1". Người kiểm
#     (chain_check, verify-chain) tin một public key nếu nó từng được vault-init công bố ở đây —
#     digest ký bằng khoá của "đời Vault" trước vẫn kiểm được.
H=/vault/file/siem-digest.history.jsonl
touch "$H"
for pk in $(grep -o '"public_key": *"[^"]*"' /vault/file/siem-digest.json | sed 's/.*: *"\(.*\)"/\1/'); do
  if ! grep -qF "\"$pk\"" "$H"; then
    printf '{"public_key":"%s","published":"%s"}\n' "$pk" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$H"
    say "thêm public key mới vào lịch sử siem-digest.history.jsonl"
  fi
done

# --- 4. policy
for p in digester profile-api; do
  vault policy write "$p" /kms/policies/"$p".hcl >/dev/null
  say "policy $p ← kms/policies/$p.hcl"
done

# --- 5. token với ID cố định (đọc từ Docker secret)
mktoken() { # mktoken TÊN POLICY FILE_SECRET
  if vault write auth/token/lookup token=@"$3" >/dev/null 2>&1; then
    say "token $1 đã có"
  else
    vault write auth/token/create-orphan id=@"$3" policies="$2" no_default_policy=true \
      display_name="$1" ttl="$TTL" explicit_max_ttl="$TTL" renewable=false >/dev/null
    say "tạo token $1 (policy $2, hạn $TTL)"
  fi
}
mktoken digester digester /run/secrets/vault_token_digester
mktoken profile-api profile-api /run/secrets/vault_token_profile

say "xong"
