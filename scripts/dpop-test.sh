#!/usr/bin/env bash
# Tuần 6 T6 — profile P2 (:8445): DPoP ở gateway (RFC 9449, SR-04, T1). Token thật của Keycloak.
#   A. ca hợp lệ  B. replay + token bị trộm (S3/S4)  C. proof sai theo từng bước §4.3
#   D. hạ cấp DPoP → Bearer (§7.2) và so sánh P0/P1  E. OPA vẫn áp dụng ở P2
#
#   ./scripts/dpop-test.sh | tee docs/evidence/dpop-p2-$(date +%F).txt
# Mã thoát = số ca FAIL. Cần lab đang chạy, client web-app-dpop (scripts/kc-apply-client.sh).
set -uo pipefail
. "$(dirname "$0")/lib/common.sh"
cd "$ROOT" || exit 1

CA="$ROOT/secrets/tls/ca.crt"
GW=https://localhost:8445
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
FAIL=0
N=0
DENIED=()

# p2 METHOD PATH AUTH_LINE PROOF [curl-args...] — gọi gateway; đặt CODE, RID, UP (yes = tới backend).
# Token và proof đi qua header đọc từ pipe, không nằm trên dòng lệnh. PROOF rỗng = không gửi DPoP.
# Hai header gom vào MỘT "-H @<(...)" ngay trên dòng lệnh curl: <(...) tạo trong lệnh gán mảng sẽ
# bị đóng khi lệnh gán xong, curl không đọc được nữa (lỗi đã gặp).
p2() {
  local method=$1 path=$2 auth=$3 proof=$4
  shift 4
  rm -f "$TMP/hdr" "$TMP/body"
  CODE=$(curl -sS --cacert "$CA" --max-time 5 -o "$TMP/body" -D "$TMP/hdr" -w '%{http_code}' -X "$method" \
    -H @<(if [ -n "$auth" ]; then printf '%s\n' "$auth"; fi; if [ -n "$proof" ]; then dpop_header "$proof"; fi) \
    "$@" "${BASE:-$GW}$path" 2>"$TMP/err")
  touch "$TMP/hdr"
  RID=$(grep -i '^x-request-id:' "$TMP/hdr" | cut -d' ' -f2 | tr -d '\r')
  grep -qi '^x-envoy-upstream-service-time:' "$TMP/hdr" && UP=yes || UP=no
}
check() { # MÔ_TẢ MÃ_MUỐN
  N=$((N + 1))
  local where="gateway"
  [ "$UP" = yes ] && where="backend"
  if [ "$CODE" = "$2" ]; then echo "  [PASS] $1 → $CODE ($where)"; else echo "  [FAIL] $1 → $CODE ($where), muốn $2"; FAIL=$((FAIL + 1)); fi
  [ "$UP" = no ] && [ -n "$RID" ] && DENIED+=("$RID|$1")
}
www() { grep -i '^www-authenticate:' "$TMP/hdr" | cut -d' ' -f2- | tr -d '\r'; }
body_user() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("user",""))' "$TMP/body" 2>/dev/null; }

# custom_proof KEY HEADER_JSON PAYLOAD_JSON — proof dựng tay cho ca sai (thiếu claim…)
custom_proof() { jws_es256 "$@"; }
b64json() { printf %s "$1" | b64url; }
# jwk_with_d KEY — JWK có cả khoá riêng d (client lỗi lộ khoá riêng trong header)
jwk_with_d() {
  local d
  d=$(openssl pkey -in "$1" -noout -text 2>/dev/null | python3 -c 'import base64, re, sys
m = re.search(r"priv:\s*([0-9a-f:\s]+?)\s*pub:", sys.stdin.read(), re.S)
b = bytes.fromhex(re.sub(r"[^0-9a-f]", "", m.group(1)))[-32:].rjust(32, b"\0")
print(base64.urlsafe_b64encode(b).rstrip(b"=").decode())')
  dpop_jwk "$1" | python3 -c 'import json, sys; j = json.load(sys.stdin); j["d"] = sys.argv[1]; print(json.dumps(j, separators=(",", ":")))' "$d"
}
flip_sig() { python3 -c 'import base64, sys
h, p, s = sys.argv[1].split(".")
b = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))); b[7] ^= 1
print(h + "." + p + "." + base64.urlsafe_b64encode(bytes(b)).rstrip(b"=").decode())' "$1"; }

START=$(date -u +%Y-%m-%dT%H:%M:%S)
echo "# Profile P2 (:8445) — DPoP ở gateway — $(date -Iseconds)"
dpop_keygen "$TMP/alice.pem"
dpop_keygen "$TMP/attacker.pem"
TOK=$("$(dirname "$0")/dpop-login.sh" alice "$TMP/alice.pem" --token) || die "không lấy được token DPoP của alice"
BEARER=$("$(dirname "$0")/pkce-login.sh" alice --token) || die "không lấy được token bearer của alice"
SUB=$(TOKEN=$TOK python3 -c 'import base64,json,os; p=os.environ["TOKEN"].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4)))["sub"])')
AUTH="Authorization: DPoP $TOK"
U=$GW/orders/whoami
echo "# Token DPoP của alice: $(redact access_token "$TOK"), cnf.jkt = $(dpop_jkt "$TMP/alice.pem")"
echo "# Khoá kẻ tấn công: jkt = $(dpop_jkt "$TMP/attacker.pem")"

echo
echo "## A. Ca hợp lệ — mỗi request một proof MỚI (jti mới, iat = bây giờ, ath = hash token)"
p2 GET /orders/whoami "$AUTH" "$(dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")"
check "A1 token DPoP + proof đúng GET /orders/whoami" 200
[ "$(body_user)" = "$SUB" ] && { N=$((N + 1)); echo "  [PASS] A1' backend nhận X-User = sub của alice"; } || { N=$((N + 1)); FAIL=$((FAIL + 1)); echo "  [FAIL] A1' X-User = '$(body_user)'"; }
p2 GET /profile/whoami "$AUTH" "$(dpop_proof "$TMP/alice.pem" GET "$GW/profile/whoami" "$TOK")"
check "A2 proof mới cho URL khác GET /profile/whoami" 200
p2 POST /orders "$AUTH" "$(dpop_proof "$TMP/alice.pem" POST "$GW/orders" "$TOK")" -d '{}'
check "A3 POST /orders (htm=POST; OPA: alice dept=sales được tạo đơn) → backend 501" 501
p2 GET /orders/whoami "$AUTH" "$(dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")" -H "X-User: admin"
[ "$CODE" = 200 ] && [ "$(body_user)" = "$SUB" ] && { N=$((N + 1)); echo "  [PASS] A4 X-User: admin tự gửi bị xoá, backend thấy sub thật"; } || { N=$((N + 1)); FAIL=$((FAIL + 1)); echo "  [FAIL] A4 X-User = '$(body_user)' ($CODE)"; }

echo
echo "## B. Replay và token bị đánh cắp (T1 — S3, S4)"
P=$(dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")
p2 GET /orders/whoami "$AUTH" "$P"
check "B0 kẻ nghe lén bắt được request hợp lệ (token + proof) — lần đầu của chủ thật" 200
p2 GET /orders/whoami "$AUTH" "$P"
check "B1 phát lại NGUYÊN request đó (cùng token, cùng proof)" 401
echo "       WWW-Authenticate: $(www)"
p2 GET /orders/whoami "Authorization: Bearer $TOK" ""
check "B2 dùng token trộm như bearer (không proof) tới P2" 401
p2 GET /orders/whoami "$AUTH" ""
check "B3 token trộm, scheme DPoP, không có proof" 401
p2 GET /orders/whoami "$AUTH" "$(dpop_proof "$TMP/attacker.pem" GET "$U" "$TOK")"
check "B4 token trộm + proof ký bằng khoá của kẻ tấn công (jkt ≠ cnf.jkt)" 401
P=$(dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")
p2 GET /profile/whoami "$AUTH" "$P"
check "B5 proof bắt được (chưa dùng) đem sang URL khác (htu)" 401
p2 DELETE /orders/whoami "$AUTH" "$P"
check "B6 proof bắt được đem sang method khác (htm)" 401
# B7: 10 request song song cùng MỘT proof — kiểm-và-ghi jti nằm trong một khoá mutex → đúng 1 lần qua.
P=$(dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")
for i in $(seq 1 10); do
  curl -s --cacert "$CA" --max-time 5 -o /dev/null -w '%{http_code}\n' -H @<(printf '%s\n' "$AUTH") -H @<(dpop_header "$P") "$U" >"$TMP/par.$i" &
done
wait
ok=$(cat "$TMP"/par.* | grep -c '^200$')
N=$((N + 1))
if [ "$ok" = 1 ]; then echo "  [PASS] B7 10 request song song cùng một proof → đúng 1 lần 200, 9 lần 401"; else echo "  [FAIL] B7 $ok lần 200 (muốn đúng 1)"; FAIL=$((FAIL + 1)); fi

echo
echo "## C. Proof sai — từng bước kiểm của RFC 9449 §4.3"
NOW=$(date +%s)
JWK=$(dpop_jwk "$TMP/alice.pem")
ATH=$(dpop_ath "$TOK")
p2 GET /orders/whoami "$AUTH" "$(DPOP_TYP=JWT dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")"
check "C1 (4) typ=JWT thay vì dpop+jwt" 401
p2 GET /orders/whoami "$AUTH" "$(b64json '{"typ":"dpop+jwt","alg":"none","jwk":'"$JWK"'}').$(b64json '{"jti":"n1","htm":"GET","htu":"'"$U"'","iat":'"$NOW"',"ath":"'"$ATH"'"}')."
check "C2 (5) alg=none, không chữ ký" 401
H=$(b64json '{"typ":"dpop+jwt","alg":"HS256","jwk":'"$JWK"'}')
PL=$(b64json '{"jti":"h1","htm":"GET","htu":"'"$U"'","iat":'"$NOW"',"ath":"'"$ATH"'"}')
p2 GET /orders/whoami "$AUTH" "$H.$PL.$(printf '%s.%s' "$H" "$PL" | openssl dgst -sha256 -hmac secret -binary | b64url)"
check "C3 (5) alg=HS256 (khoá đối xứng)" 401
p2 GET /orders/whoami "$AUTH" "$(DPOP_JWK=$(jwk_with_d "$TMP/alice.pem") dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")"
check "C4 (7) jwk chứa khoá riêng d" 401
p2 GET /orders/whoami "$AUTH" "$(flip_sig "$(dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")")"
check "C5 (6) chữ ký bị lật 1 bit" 401
p2 GET /orders/whoami "$AUTH" "$(custom_proof "$TMP/alice.pem" '{"typ":"dpop+jwt","alg":"ES256","jwk":'"$JWK"'}' '{"htm":"GET","htu":"'"$U"'","iat":'"$NOW"',"ath":"'"$ATH"'"}')"
check "C6 (3) thiếu jti" 401
p2 GET /orders/whoami "$AUTH" "$(dpop_proof "$TMP/alice.pem" GET "$U")"
check "C7 (3) thiếu ath (proof không gắn với token)" 401
p2 GET /orders/whoami "$AUTH" "$(DPOP_ATH=$(dpop_ath other-token) dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")"
check "C8 (12) ath là hash của token khác" 401
p2 GET /orders/whoami "$AUTH" "$(DPOP_HTU=https://evil.example:8445/orders/whoami dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")"
check "C9 (9) htu trỏ host khác" 401
p2 GET /orders/whoami "$AUTH" "$(DPOP_HTU=https://localhost:8443/orders/whoami dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")"
check "C10 (9) htu cho cổng P1 đem sang P2" 401
p2 GET /orders/whoami "$AUTH" "$(DPOP_IAT=$((NOW - 60)) dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")"
check "C11 (11) iat cũ 60 s (cửa sổ 30 s)" 401
p2 GET /orders/whoami "$AUTH" "$(DPOP_IAT=$((NOW + 60)) dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")"
check "C12 (11) iat ở tương lai 60 s" 401
p2 GET /orders/whoami "$AUTH" "$(dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")" -H @<(dpop_header "$(dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")")
check "C13 (1) hai header DPoP trong một request" 401
p2 GET /orders/whoami "$AUTH" "$(DPOP_JTI=$(head -c 3000 /dev/zero | tr '\0' a) dpop_proof "$TMP/alice.pem" GET "$U" "$TOK")"
check "C14 proof > 4096 byte (T10: chặn trước khi giải mã)" 401

echo
echo "## D. Hạ cấp DPoP → Bearer (RFC 9449 §7.2) — cùng token DPoP bị trộm, thử ở từng profile"
BASE=https://localhost:8443 p2 GET /orders/whoami "Authorization: Bearer $TOK" ""
check "D1 P1 :8443 — token gắn khoá gửi như bearer → bị từ chối" 401
BASE=https://localhost:8444 p2 GET /orders/whoami "Authorization: Bearer $TOK" ""
check "D2 P0 :8444 — jwt_authn không biết DPoP → CHO QUA (điểm yếu của baseline, có chủ đích)" 200
p2 GET /orders/whoami "Authorization: DPoP $BEARER" "$(dpop_proof "$TMP/alice.pem" GET "$U" "$BEARER")"
check "D3 P2 — token bearer thường (không cnf, typ=Bearer) + proof hợp lệ" 401

echo
echo "## E. Phân quyền OPA vẫn áp dụng sau DPoP"
p2 DELETE /orders/1 "$AUTH" "$(dpop_proof "$TMP/alice.pem" DELETE "$GW/orders/1" "$TOK")"
check "E1 alice DELETE /orders/1 (proof đúng, nhưng employee không được xoá — BFLA)" 403

echo
echo "## Lý do trong log auth-svc (nối bằng x-request-id; client chỉ thấy invalid_dpop_proof / invalid_token)"
sleep 1
docker compose logs auth-svc --no-log-prefix 2>/dev/null | grep '"msg":"authz_decision"' >"$TMP/log"
for e in "${DENIED[@]}"; do
  rid=${e%%|*}
  printf '  %-64s %s\n' "${e#*|}" "$(grep -F "\"request_id\":\"$rid\"" "$TMP/log" | tail -1 | python3 -c 'import json,sys
d = json.loads(sys.stdin.read() or "{}")
r = d.get("reason", "(Envoy chặn trước auth-svc)" if not d else "")
extra = ""
if d.get("cnf_jkt") and d.get("proof_jkt") and d["cnf_jkt"] != d["proof_jkt"]:
    extra = " cnf_jkt=%s… proof_jkt=%s…" % (d["cnf_jkt"][:8], d["proof_jkt"][:8])
print("profile=%s reason=%s%s" % (d.get("profile", "-"), r, extra))')"
done
echo
echo "## Thời gian quyết định ở auth-svc (duration_ms, các request được cho qua ở P2)"
# Chỉ tính request của lần chạy này (event_time ≥ START), không lẫn log cũ của container.
grep '"profile":"p2"' "$TMP/log" | grep '"decision":"allow"' | python3 -c 'import json,sys
v = sorted(d["duration_ms"] for d in map(json.loads, sys.stdin) if d["event_time"] >= sys.argv[1])
print("  n=%d  min=%.3f  median=%.3f  max=%.3f ms (gồm kiểm JWT + kiểm proof + hỏi OPA; chưa phải benchmark — tuần 11)" % (len(v), v[0], v[len(v)//2], v[-1]) if v else "  (không có)")' "$START"

echo
echo "Kết quả: $((N - FAIL))/$N PASS"
exit $FAIL
