#!/usr/bin/env bash
# Tuần 9 T5 — kiểm Vault Transit + policy tách biệt (TB4, T7, S9, RC6, RS2, CR-06/CR-08, M7/M9).
# Cần lab chạy (ít nhất vault + vault-init). Mã thoát = số mục FAIL.
#   A. hạ tầng: vault healthy, không port, mạng kms internal, vault-init xong
#   B. 2 khoá đúng kiểu, không export, không backup dạng rõ, không xoá được
#   C. token digester: CHỈ ký siem-digest — mọi việc khác bị từ chối
#   D. token profile-api: CHỈ encrypt/decrypt pii-enc — mọi việc khác bị từ chối
#   E. chữ ký kiểm được NGOÀI Vault bằng public key đã công bố (openssl, Ed25519)
#   F. audit log: có dấu vết cả lần bị từ chối; không chứa token/plaintext thô
#   G. token không nằm trong biến môi trường của container nào, không bị git theo dõi (ST4)
#
# Lệnh chạy với token của app đi qua `docker compose run vault-init` (container có sẵn 3 secret,
# ở mạng kms). Giá trị token không bao giờ được in ra.
set -u
cd "$(dirname "$0")/.." || exit 1
FAIL=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

echo "== A. Hạ tầng"
s=$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q vault)" 2>/dev/null)
[ "$s" = healthy ] && pass "vault: healthy" || fail "vault: ${s:-không chạy}"
c=$(docker inspect -f '{{.State.ExitCode}}' "$(docker compose ps -aq vault-init)" 2>/dev/null)
[ "$c" = 0 ] && pass "vault-init thoát mã 0" || fail "vault-init thoát mã ${c:-?}"
# `docker compose port` in ":0" cho cổng chỉ EXPOSE trong image (Vault có EXPOSE 8200) — dùng
# `docker port`, lệnh chỉ liệt kê cổng đã publish ra host.
p=$(docker port "$(docker compose ps -q vault)" 2>/dev/null)
[ -z "$p" ] && pass "vault không publish cổng nào ra host" || fail "vault publish cổng ra host: $p"
if [ "$(docker network inspect -f '{{.Internal}}' topic09-kms 2>/dev/null)" = true ]; then
  pass "mạng topic09-kms là internal"
else
  fail "mạng topic09-kms không internal hoặc không có"
fi
members=$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' topic09-kms | tr ' ' '\n' | sed -E 's/^topic09-lab-//; s/-[0-9]+$//' | grep -v '^$' | sort -u | tr '\n' ' ')
case " $members" in
  *" vault "*) bad=$(echo "$members" | tr ' ' '\n' | grep -vxE 'vault|vault-init|digester|profile-api|' || true)
               [ -z "$bad" ] && pass "thành viên mạng kms: $members" || fail "mạng kms có service lạ: $bad" ;;
  *) fail "vault không ở mạng kms ($members)" ;;
esac

# Chạy một đoạn shell trong container vault-init (mạng kms, có 3 secret).
in_kms() { docker compose run --rm --no-deps -T --entrypoint sh vault-init -s; }

# Đầu ra của khối dưới: mỗi dòng "<mã> <kết quả>", kết quả = ok | denied | err:<mã lỗi>.
in_kms > "$TMP/probe" 2>"$TMP/probe.err" <<'EOF'
export VAULT_ADDR=http://vault:8200
R=/run/secrets/vault_root_token D=/run/secrets/vault_token_digester P=/run/secrets/vault_token_profile
MSG=$(printf 'topic09 digest test' | base64)
SECRET_PT=$(printf 'kms-test-plaintext-7f3a' | base64)
# try MÃ FILE_TOKEN lệnh… → in "MÃ ok" hoặc "MÃ denied"/"MÃ err:<dòng lỗi của Vault>".
# Đầu ra khi thành công giữ trong biến LAST (container chỉ đọc, không ghi được file tạm).
try() {
  id=$1; tf=$2; shift 2; LAST=
  if out=$(VAULT_TOKEN=$(cat "$tf") "$@" 2>&1); then echo "$id ok"; LAST=$out
  elif printf '%s' "$out" | grep -q 'permission denied'; then echo "$id denied"
  else echo "$id err:$(printf '%s\n' "$out" | sed -n 's/^\* //p' | head -1 | cut -c1-80)"; fi
}
# --- B (root): thuộc tính khoá
for k in siem-digest pii-enc; do
  for f in type exportable deletion_allowed allow_plaintext_backup latest_version; do
    echo "keyattr_${k}_$f $(VAULT_TOKEN=$(cat $R) vault read -field=$f transit/keys/$k 2>/dev/null)"
  done
done
echo "policy_digester $(VAULT_TOKEN=$(cat $R) vault policy read digester | grep -v '^ *#' | tr -d ' \n')"
echo "policy_profile $(VAULT_TOKEN=$(cat $R) vault policy read profile-api | grep -v '^ *#' | tr -d ' \n')"
echo "tokpol_digester $(VAULT_TOKEN=$(cat $R) vault write -field=policies auth/token/lookup token=@$D 2>/dev/null | tr -d '[] ')"
echo "tokpol_profile $(VAULT_TOKEN=$(cat $R) vault write -field=policies auth/token/lookup token=@$P 2>/dev/null | tr -d '[] ')"
# --- C: digester
try d_sign      $D vault write -field=signature transit/sign/siem-digest input="$MSG"
[ -n "$LAST" ] && echo "sig $LAST"
try d_encrypt   $D vault write transit/encrypt/pii-enc plaintext="$SECRET_PT"
try d_decrypt   $D vault write transit/decrypt/pii-enc ciphertext=vault:v1:AAAA
try d_verify    $D vault write transit/verify/siem-digest input="$MSG" signature=vault:v1:AAAA
try d_readkey   $D vault read transit/keys/siem-digest
try d_rotate    $D vault write -f transit/keys/siem-digest/rotate
try d_export    $D vault read transit/export/signing-key/siem-digest
try d_hashpath  $D vault write transit/sign/siem-digest/sha2-256 input="$MSG"
try d_policies  $D vault policy list
try d_lookself  $D vault token lookup
try d_mktoken   $D vault token create -policy=digester
# --- D: profile-api
try p_encrypt   $P vault write -field=ciphertext transit/encrypt/pii-enc plaintext="$SECRET_PT"
if [ -n "$LAST" ]; then
  CT=$LAST; echo "ct_prefix $(printf '%s' "$CT" | cut -d: -f1-2)"
  try p_decrypt $P vault write -field=plaintext transit/decrypt/pii-enc ciphertext="$CT"
  [ "$LAST" = "$SECRET_PT" ] && echo "roundtrip ok" || echo "roundtrip err:mismatch"
fi
try p_sign      $P vault write transit/sign/siem-digest input="$MSG"
try p_rewrap    $P vault write transit/rewrap/pii-enc ciphertext=vault:v1:AAAA
try p_rotate    $P vault write -f transit/keys/pii-enc/rotate
try p_readkey   $P vault read transit/keys/pii-enc
try p_datakey   $P vault write -f transit/datakey/plaintext/pii-enc
try p_export    $P vault read transit/export/encryption-key/pii-enc
try p_otherkey  $P vault write transit/encrypt/siem-digest plaintext="$SECRET_PT"
try p_sys       $P vault secrets list
# --- root không xoá được khoá (deletion_allowed=false)
try r_delete    $R vault delete transit/keys/pii-enc
EOF
grep -q . "$TMP/probe" || { fail "không chạy được khối kiểm trong mạng kms: $(head -3 "$TMP/probe.err")"; echo "Kết quả: $FAIL FAIL"; exit "$FAIL"; }
get() { awk -v k="$1" '$1==k {sub(/^[^ ]+ /,""); print; exit}' "$TMP/probe"; }
expect() { # expect MÃ MONG_ĐỢI MÔ_TẢ
  v=$(get "$1")
  if [ "$v" = "$2" ]; then pass "$3 → $v"; else fail "$3 → '${v:-không có}' (muốn $2)"; fi
}

echo "== B. Khoá Transit"
expect keyattr_siem-digest_type ed25519 "siem-digest: kiểu"
expect keyattr_pii-enc_type aes256-gcm96 "pii-enc: kiểu"
for k in siem-digest pii-enc; do
  expect "keyattr_${k}_exportable" false "$k: exportable"
  expect "keyattr_${k}_allow_plaintext_backup" false "$k: allow_plaintext_backup"
  expect "keyattr_${k}_deletion_allowed" false "$k: deletion_allowed"
done
case "$(get r_delete)" in
  err:*eletion*) pass "kể cả root cũng không xoá được pii-enc (deletion_allowed=false)" ;;
  *) fail "root xoá pii-enc → '$(get r_delete)' (muốn lỗi deletion not allowed)" ;;
esac
expect policy_digester 'path"transit/sign/siem-digest"{capabilities=["update"]}' "policy digester chỉ 1 đường dẫn"
expect policy_profile 'path"transit/encrypt/pii-enc"{capabilities=["update"]}path"transit/decrypt/pii-enc"{capabilities=["update"]}' "policy profile-api chỉ encrypt + decrypt"
expect tokpol_digester digester "token digester chỉ mang policy digester (không có default)"
expect tokpol_profile profile-api "token profile-api chỉ mang policy profile-api (không có default)"

echo "== C. Token digester"
expect d_sign ok "ký bằng siem-digest"
for x in d_encrypt:"encrypt pii-enc" d_decrypt:"decrypt pii-enc" d_verify:"verify siem-digest" d_readkey:"đọc cấu hình khoá" \
         d_rotate:"xoay khoá siem-digest" d_export:"export khoá ký" d_hashpath:"ký qua đường dẫn /sha2-256" \
         d_policies:"liệt kê policy" d_lookself:"lookup-self" d_mktoken:"tạo token con"; do
  expect "${x%%:*}" denied "${x#*:} bị từ chối"
done

echo "== D. Token profile-api"
expect p_encrypt ok "encrypt pii-enc"
expect ct_prefix vault:v1 "ciphertext có version khoá (vault:v1:…)"
expect p_decrypt ok "decrypt pii-enc"
expect roundtrip ok "giải mã ra đúng plaintext ban đầu"
for x in p_sign:"ký siem-digest" p_rewrap:"rewrap" p_rotate:"xoay pii-enc" p_readkey:"đọc cấu hình khoá" \
         p_datakey:"xin data key dạng rõ" p_export:"export khoá" p_otherkey:"encrypt bằng khoá khác" p_sys:"liệt kê secrets engine"; do
  expect "${x%%:*}" denied "${x#*:} bị từ chối"
done

echo "== E. Kiểm chữ ký ngoài Vault bằng public key đã công bố (kms-public/siem-digest.json)"
docker compose run --rm --no-deps -T --entrypoint cat vault-init /vault/file/siem-digest.json > "$TMP/pub.json" 2>/dev/null
pub=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["data"]; print(d["keys"][str(d["latest_version"])]["public_key"])' "$TMP/pub.json" 2>/dev/null)
sig=$(get sig)
if [ -n "$pub" ] && [ -n "$sig" ]; then
  # SubjectPublicKeyInfo của Ed25519 = tiền tố DER cố định 12 byte (RFC 8410 §4) + 32 byte khoá.
  { printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; printf '%s' "$pub" | base64 -d; } > "$TMP/pub.der"
  printf '%s' "${sig#vault:v*:}" | base64 -d > "$TMP/sig.bin"
  printf 'topic09 digest test' > "$TMP/msg"
  if openssl pkeyutl -verify -pubin -inkey "$TMP/pub.der" -keyform DER -rawin -in "$TMP/msg" -sigfile "$TMP/sig.bin" >/dev/null 2>&1; then
    pass "openssl xác minh chữ ký Ed25519 của Vault bằng public key đã công bố"
  else
    fail "openssl KHÔNG xác minh được chữ ký"
  fi
  printf 'topic09 digest tesT' > "$TMP/msg2"
  if openssl pkeyutl -verify -pubin -inkey "$TMP/pub.der" -keyform DER -rawin -in "$TMP/msg2" -sigfile "$TMP/sig.bin" >/dev/null 2>&1; then
    fail "đổi 1 ký tự của thông điệp mà chữ ký vẫn đúng"
  else
    pass "đổi 1 ký tự của thông điệp → chữ ký sai"
  fi
else
  fail "thiếu public key hoặc chữ ký để kiểm"
fi

echo "== F. Audit device"
docker compose exec -T vault cat /vault/logs/audit.log > "$TMP/audit.log" 2>/dev/null
n=$(wc -l < "$TMP/audit.log")
[ "$n" -gt 0 ] && pass "audit log có $n dòng" || fail "audit log rỗng"
den=$(python3 - "$TMP/audit.log" <<'PY'
import json, sys
n = 0
for line in open(sys.argv[1]):
    try: e = json.loads(line)
    except ValueError: continue
    if e.get("type") == "response" and "permission denied" in (e.get("error") or "") \
       and (e.get("auth") or {}).get("display_name") == "token-digester":
        n += 1
print(n)
PY
)
[ "${den:-0}" -ge 5 ] && pass "audit ghi $den lần token-digester bị từ chối (S9 nhìn thấy được)" || fail "audit chỉ ghi ${den:-0} lần digester bị từ chối"
leak=0
for f in root digester profile-api; do
  grep -qF -- "$(cat "secrets/vault/$f.token")" "$TMP/audit.log" && { fail "audit log chứa token $f dạng thô"; leak=1; }
done
[ $leak = 0 ] && pass "audit log không chứa token thô nào (Vault HMAC giá trị)"
pt64=$(printf 'kms-test-plaintext-7f3a' | base64)
if grep -qF -e "kms-test-plaintext-7f3a" -e "$pt64" "$TMP/audit.log"; then
  fail "audit log chứa plaintext của phép encrypt"
else
  pass "audit log không chứa plaintext (dạng rõ lẫn base64)"
fi

echo "== G. Token không lọt ra ngoài (ST4)"
envleak=0
for cid in $(docker compose ps -aq); do
  envs=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid")
  for f in root digester profile-api; do
    printf '%s' "$envs" | grep -qF -- "$(cat "secrets/vault/$f.token")" && { fail "token $f nằm trong env của $(docker inspect -f '{{.Name}}' "$cid")"; envleak=1; }
  done
done
[ $envleak = 0 ] && pass "không container nào có token Vault trong biến môi trường"
if git ls-files --error-unmatch secrets/vault >/dev/null 2>&1 || git ls-files secrets | grep -q .; then
  fail "secrets/ đang bị git theo dõi"
else
  pass "secrets/vault/ không bị git theo dõi"
fi

echo
echo "Kết quả: $FAIL FAIL"
exit "$FAIL"
