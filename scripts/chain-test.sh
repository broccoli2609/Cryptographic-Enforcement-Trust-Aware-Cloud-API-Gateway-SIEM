#!/usr/bin/env bash
# Tuần 9 T5 — hash chain + digest ký bằng Vault, đầu-cuối (SR-09, SR-11, T9, M6/M7, RP6, RS3,
# CR-06, S10/H9, FI-4). Cần lab chạy đủ. Mã thoát = số mục FAIL. Mất ~1 phút.
#   A. hạ tầng digester: healthy, không port, đúng 2 mạng, mount đúng quyền, token không ở env
#   B. sinh lưu lượng qua gateway (mọi nguồn) rồi ký digest ngay (SIGUSR1)
#   C. kiểm độc lập bằng telemetry/chain_check.py: event_hash, seq liền mạch, file chuỗi của Vector
#      ↔ SIEM, chữ ký Ed25519 (khoá ghim), mắt xích digest, head = H tính lại; Vault transit/verify
#   D. sổ digest cục bộ = digest trong OpenSearch; sự kiện mới khớp schema 1.1.0
#   E. selftest: 6 kiểu sửa/xoá trên bản sao đều bị phát hiện
#   F. FI-4: Vault treo → digest_failed, KHÔNG có digest nào; Vault chạy lại → digest kế tiếp nối liền
set -u
cd "$(dirname "$0")/.." || exit 1
FAIL=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
TMP=$(mktemp -d); trap 'docker compose unpause vault >/dev/null 2>&1; rm -rf "$TMP"' EXIT
OSQ() { docker compose exec -T opensearch curl -s -H 'Content-Type: application/json' "http://127.0.0.1:9200/$1" ${2:+-d "$2"}; }
ledger() { docker run --rm --network none -v topic09-lab_digester-state:/s:ro busybox:1.37 cat /s/digests.jsonl 2>/dev/null; }
nlines() { ledger | grep -c . ; }
# usr1_wait MSG — gửi SIGUSR1 cho digester rồi chờ (tối đa 20 s) một dòng log MSG mới.
usr1_wait() {
  local before; before=$(docker compose logs --no-log-prefix digester 2>/dev/null | grep -c "\"msg\":\"$1\"")
  docker compose kill -s USR1 digester >/dev/null 2>&1
  for _ in $(seq 1 20); do
    sleep 1
    [ "$(docker compose logs --no-log-prefix digester 2>/dev/null | grep -c "\"msg\":\"$1\"")" -gt "$before" ] && return 0
  done
  return 1
}

echo "== A. Hạ tầng digester"
cid=$(docker compose ps -q digester)
s=$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null)
[ "$s" = healthy ] && pass "digester: healthy" || fail "digester: ${s:-không chạy}"
[ -z "$(docker port "$cid" 2>/dev/null)" ] && pass "digester không publish cổng nào" || fail "digester có cổng ra host"
nets=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$cid" | xargs -n1 | sort | xargs)
[ "$nets" = "topic09-kms topic09-telemetry" ] && pass "digester chỉ ở mạng: $nets" || fail "mạng của digester: $nets"
mounts=$(docker inspect -f '{{range .Mounts}}{{.Destination}}={{.RW}} {{end}}' "$cid" | xargs -n1 | sort | xargs)
case "$mounts" in
  "/chain=false /kms-public=false /run/secrets/vault_token_digester=false /state=true") pass "mount: file chuỗi + public key chỉ đọc, chỉ /state ghi được ($mounts)" ;;
  *) fail "mount của digester: $mounts" ;;
esac
if docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" | grep -qF -- "$(cat secrets/vault/digester.token)"; then
  fail "token digester nằm trong biến môi trường"
else
  pass "token digester không nằm trong biến môi trường (đọc từ /run/secrets)"
fi
vmounts=$(docker inspect -f '{{range .Mounts}}{{.Destination}}={{.RW}} {{end}}' "$(docker compose ps -q vector)")
case " $vmounts " in *" /var/lib/vector-chain=true "*"/vault-audit=false"*|*"/vault-audit=false "*"/var/lib/vector-chain=true"*) pass "vector: ghi file chuỗi, đọc audit Vault chỉ đọc" ;; *) fail "mount của vector: $vmounts" ;; esac

echo "== B. Sinh lưu lượng và ký digest"
./scripts/gateway-test.sh 8443 > "$TMP/gw.txt" 2>&1 && pass "gateway-test P1 chạy xong ($(grep -c PASS "$TMP/gw.txt") PASS) — có sự kiện của mọi nguồn" || fail "gateway-test P1 lỗi"
sleep 6   # Vector gom lô 2 s, Envoy flush 1 s
if usr1_wait digest_signed; then pass "SIGUSR1 → digester ký digest mới"; else fail "không thấy digest_signed sau SIGUSR1"; fi
sleep 5   # đợi Vector đẩy hết sự kiện đã nằm trong file chuỗi sang OpenSearch

EPOCH=$(docker compose exec -T vector ls /var/lib/vector-chain | grep -E '^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.jsonl$' | sort | tail -1 | sed 's/\.jsonl$//')
[ -n "$EPOCH" ] && pass "epoch hiện tại của chuỗi: $EPOCH" || fail "không tìm thấy file chuỗi"
python3 telemetry/siem_export.py --index topic09-events --sort chain_seq --query "{\"term\":{\"chain_epoch\":\"$EPOCH\"}}" > "$TMP/ev.ndjson" 2>"$TMP/ex.err"
python3 telemetry/siem_export.py --index topic09-digests --sort digest_seq > "$TMP/dg.ndjson" 2>>"$TMP/ex.err"
docker run --rm --network none -v topic09-lab_kms-public:/k:ro busybox:1.37 cat /k/siem-digest.json > "$TMP/pub.json"
docker run --rm --network none -v topic09-lab_kms-public:/k:ro busybox:1.37 cat /k/siem-digest.history.jsonl > "$TMP/pubhist.jsonl" 2>/dev/null
# File chuỗi: chỉ phần đã được digest phủ (phần sau có thể chưa kịp sang OpenSearch).
last=$(python3 -c 'import json,sys; L=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]; L=[d for d in L if d["chain_epoch"]==sys.argv[2]]; print(max((d["last_seq"] for d in L), default=0))' "$TMP/dg.ndjson" "$EPOCH")
docker compose exec -T vector cat "/var/lib/vector-chain/$EPOCH.jsonl" | python3 -c 'import json,sys; n=int(sys.argv[1]); [sys.stdout.write(l) for l in sys.stdin if l.strip() and json.loads(l)["chain_seq"]<=n]' "$last" > "$TMP/chain.jsonl"
echo "  ($(wc -l < "$TMP/ev.ndjson") sự kiện epoch này, $(wc -l < "$TMP/dg.ndjson") digest, file chuỗi tới seq $last)"

echo "== C. Kiểm độc lập (telemetry/chain_check.py)"
if python3 telemetry/chain_check.py --events "$TMP/ev.ndjson" --digests "$TMP/dg.ndjson" --pubkey "$TMP/pub.json" \
     --pubkey-history "$TMP/pubhist.jsonl" --chain-file "$TMP/chain.jsonl" --epoch "$EPOCH" > "$TMP/cc.txt" 2>&1; then
  pass "chain_check ĐẠT: event_hash, seq liền mạch, file chuỗi ↔ SIEM, chữ ký (khoá ghim), mắt xích, head"
else
  fail "chain_check: $(grep -c LỖI "$TMP/cc.txt") lỗi"
fi
sed 's/^/    /' "$TMP/cc.txt"
nsrc=$(python3 -c 'import json,sys; print(" ".join(sorted({json.loads(l)["source"] for l in open(sys.argv[1])})))' "$TMP/ev.ndjson")
for s in envoy auth-svc opa orders-api keycloak vault digester vector; do
  case " $nsrc " in *" $s "*) ;; *) fail "không có sự kiện nào của nguồn $s trong epoch"; ;; esac
done
pass "nguồn có mặt trong chuỗi: $nsrc"
dg_last=$(tail -1 "$TMP/dg.ndjson")
sig=$(printf '%s' "$dg_last" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["signature"])')
inp=$(printf '%s' "$dg_last" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["signed_payload"])')
v=$(docker compose run --rm --no-deps -T --entrypoint sh vault-init -c \
  "VAULT_ADDR=http://vault:8200 VAULT_TOKEN=\$(cat /run/secrets/vault_root_token) vault write -field=valid transit/verify/siem-digest input='$inp' signature='$sig'" 2>/dev/null)
[ "$v" = true ] && pass "Vault transit/verify xác nhận chữ ký digest mới nhất (valid=true)" || fail "Vault transit/verify: '${v:-lỗi}'"

echo "== D. Sổ cục bộ, schema"
ledger > "$TMP/ledger.jsonl"
if python3 - "$TMP/ledger.jsonl" "$TMP/dg.ndjson" <<'PY'
import json, sys
a = [json.loads(l)["signature"] for l in open(sys.argv[1]) if l.strip()]
b = [json.loads(l)["signature"] for l in open(sys.argv[2]) if l.strip()]
sys.exit(0 if a == b and a else 1)
PY
then pass "sổ /state/digests.jsonl có đúng $(grep -c . "$TMP/ledger.jsonl") digest, cùng chữ ký, cùng thứ tự với OpenSearch"
else fail "sổ cục bộ khác digest trong OpenSearch"; fi
if python3 telemetry/schema_check.py siem < "$TMP/ev.ndjson" > "$TMP/sc.txt" 2>&1; then
  pass "mọi sự kiện của epoch khớp telemetry/schema.json 1.1.0 ($(head -1 "$TMP/sc.txt" | cut -c1-90))"
else
  fail "schema_check siem: $(grep -m3 LỖI "$TMP/sc.txt" | tr '\n' ' ')"
fi
if grep -qE '"(chain_seq|event_hash)":' <(docker compose logs --no-log-prefix auth-svc envoy opa 2>/dev/null); then
  fail "log thô của service có trường chuỗi"
else
  pass "trường chuỗi chỉ do Vector đặt (log thô của service không có)"
fi

echo "== E. Sửa/xoá thử trên bản sao — phải bị phát hiện"
python3 telemetry/chain_check.py selftest --events "$TMP/ev.ndjson" --digests "$TMP/dg.ndjson" --pubkey "$TMP/pub.json" \
  --pubkey-history "$TMP/pubhist.jsonl" --chain-file "$TMP/chain.jsonl" > "$TMP/st.txt" 2>&1
while IFS= read -r l; do
  case "$l" in *"[PASS]"*) pass "${l#*] }";; *"[FAIL]"*) fail "${l#*] }";; *) echo "  $l";; esac
done < "$TMP/st.txt"

echo "== F. FI-4: Vault ngừng → digester fail-closed"
n0=$(nlines)
docker compose pause vault >/dev/null
if usr1_wait digest_failed; then
  r=$(docker compose logs --no-log-prefix digester | grep '"msg":"digest_failed"' | tail -1 | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["decision_reason"])')
  pass "Vault treo → digest_failed ($r)"
else
  fail "Vault treo mà không thấy digest_failed"
fi
[ "$(nlines)" = "$n0" ] && pass "không có digest nào được ghi khi Vault treo (sổ vẫn $n0)" || fail "sổ tăng khi Vault treo"
docker compose unpause vault >/dev/null
sleep 2
if usr1_wait digest_signed; then pass "Vault chạy lại → ký được digest kế tiếp"; else fail "không ký lại được sau khi Vault chạy lại"; fi
ledger > "$TMP/ledger2.jsonl"
if python3 - "$TMP/ledger2.jsonl" <<'PY'
import json, sys
L = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
a, b = L[-2], L[-1]
ok = b["digest_seq"] == a["digest_seq"] + 1 and b["prev_signature"] == a["signature"] \
     and (b["chain_epoch"] != a["chain_epoch"] or b["first_seq"] == a["last_seq"] + 1)
sys.exit(0 if ok else 1)
PY
then pass "digest sau sự cố nối liền digest trước (seq +1, prev_signature, first_seq = last_seq + 1)"
else fail "digest sau sự cố không nối liền"; fi
sleep 4
n=$(OSQ 'topic09-events/_count' '{"query":{"bool":{"filter":[{"term":{"source":"digester"}},{"term":{"event_type":"digest"}},{"term":{"decision":"deny"}}]}}}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
[ "${n:-0}" -ge 1 ] && pass "sự kiện digest_failed đã vào SIEM ($n) — H9 thấy được lúc không có digest" || fail "digest_failed không có trong SIEM"

echo
echo "Kết quả: $FAIL FAIL"
exit "$FAIL"
