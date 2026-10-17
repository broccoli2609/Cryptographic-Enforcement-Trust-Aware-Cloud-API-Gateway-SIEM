#!/usr/bin/env bash
# Tuần 4 — kiểm gateway từ đầu đến cuối (client → Envoy → backend) bằng token thật của Keycloak.
# Token hợp lệ → 200; token hỏng / sai loại / giả mạo → 401; header danh tính giả bị xoá.
#
#   ./scripts/gateway-test.sh [cổng]      # mặc định 8443
#   ./scripts/gateway-test.sh | tee docs/evidence/gateway-p0-$(date +%F).txt
# Mã thoát = số ca FAIL. Cần lab đang chạy và đã chạy gen-certs.sh, batch-worker-key.sh.
set -uo pipefail
. "$(dirname "$0")/lib/common.sh"

PORT=${1:-8443}
GW="https://localhost:$PORT"
CA="$ROOT/secrets/tls/ca.crt"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
FAIL=0
N=0
pass() { N=$((N + 1)); echo "  [PASS] $*"; }
fail() { N=$((N + 1)); echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }

# call TOKEN PATH [curl-args...] — gọi gateway qua TLS (kiểm cert theo CA nội bộ).
# Đặt CODE (mã HTTP) và BODY. Token đi qua header đọc từ pipe, không nằm trên dòng lệnh.
call() {
  local tok=$1 path=$2
  shift 2
  if [ -n "$tok" ]; then
    CODE=$(curl -sS --cacert "$CA" --max-time 5 -o "$TMP/body" -w '%{http_code}' -H @<(bearer "$tok") "$@" "$GW$path" 2>"$TMP/err")
  else
    CODE=$(curl -sS --cacert "$CA" --max-time 5 -o "$TMP/body" -w '%{http_code}' "$@" "$GW$path" 2>"$TMP/err")
  fi
  BODY=$(head -c 120 "$TMP/body" 2>/dev/null | tr '\n' ' ')
  [ -s "$TMP/err" ] && BODY="$BODY $(head -c 120 "$TMP/err")"
}
expect() { if [ "$CODE" = "$2" ]; then pass "$1 → HTTP $CODE  $BODY"; else fail "$1 → HTTP $CODE (muốn $2)  $BODY"; fi; }

# forge KIỂU — tạo token giả từ token thật (đọc từ biến môi trường TOKEN), in ra stdout.
forge() {
  python3 - "$1" <<'PY'
import base64, hashlib, hmac, json, os, sys
mode = sys.argv[1]
h, p, s = os.environ["TOKEN"].split(".")
b64d = lambda x: base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
b64e = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
enc = lambda o: b64e(json.dumps(o, separators=(",", ":")).encode())
if mode == "sig":          # lật 1 bit trong chữ ký
    sig = bytearray(b64d(s)); sig[10] ^= 0x01
    print(f"{h}.{p}.{b64e(bytes(sig))}")
elif mode == "payload":    # tự nâng quyền: sửa payload, giữ nguyên chữ ký cũ
    c = json.loads(b64d(p)); c["realm_access"] = {"roles": ["hr", "manager"]}; c["tier"] = "premium"
    print(f"{h}.{enc(c)}.{s}")
elif mode == "none":       # alg=none, bỏ chữ ký (RFC 8725 §2.1)
    print(f"{enc({'alg': 'none', 'typ': 'JWT'})}.{p}.")
elif mode == "hs256":      # alg confusion: ký HMAC bằng chứng chỉ CÔNG KHAI của realm làm khoá
    kid = json.loads(b64d(h))["kid"]
    hh = enc({"alg": "HS256", "typ": "JWT", "kid": kid})
    sig = hmac.new(os.environ["SECRET"].encode(), f"{hh}.{p}".encode(), hashlib.sha256).digest()
    print(f"{hh}.{p}.{b64e(sig)}")
PY
}
claim() { TOKEN=$1 python3 -c 'import base64,json,os,sys; p=os.environ["TOKEN"].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))).get(sys.argv[1],""))' "$2"; }
body_user() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("user",""))' "$TMP/body" 2>/dev/null; }

echo "# Gateway $GW — kiểm từ đầu đến cuối — $(date -Iseconds)"
ALICE=$("$(dirname "$0")/pkce-login.sh" alice --token) || die "không lấy được token của alice"
BATCH=$("$(dirname "$0")/client-credentials.sh" --token) || die "không lấy được token của batch-worker"
ALICE_ID=$("$(dirname "$0")/pkce-login.sh" alice --id-token)
ALICE_RT=$("$(dirname "$0")/pkce-login.sh" alice --refresh-token)
ALICE_SUB=$(claim "$ALICE" sub)
# PEM của chứng chỉ ký token (công khai, lấy từ JWKS) — "khoá" mà kẻ tấn công dùng cho alg confusion.
REALM_PEM=$(curl -fsS "$OIDC/certs" | python3 -c 'import json,sys,textwrap
k=[k for k in json.load(sys.stdin)["keys"] if k.get("use")=="sig"][0]
print("-----BEGIN CERTIFICATE-----\n"+"\n".join(textwrap.wrap(k["x5c"][0],64))+"\n-----END CERTIFICATE-----")')
echo "# Token thật: alice $(redact access_token "$ALICE"), batch-worker $(redact access_token "$BATCH")"

echo
echo "## A. Ca hợp lệ (phải 200)"
call "$ALICE" /orders/whoami
expect "A1 alice (Auth Code + PKCE) GET /orders/whoami" 200
[ "$(body_user)" = "$ALICE_SUB" ] && pass "A1' backend nhận X-User = sub của alice" || fail "A1' X-User ở backend = '$(body_user)', muốn $ALICE_SUB"
call "$ALICE" /profile/whoami
expect "A2 alice GET /profile/whoami" 200
call "$BATCH" /orders/whoami
expect "A3 batch-worker (Client Credentials + private_key_jwt) GET /orders/whoami" 200

echo
echo "## B. Token hỏng, giả mạo hoặc sai loại (phải 401 — T2, SR-02)"
call "" /orders/whoami
expect "B1 không có token" 401
call "$(TOKEN=$ALICE forge sig)" /orders/whoami
expect "B2 chữ ký bị lật 1 bit" 401
call "$(TOKEN=$ALICE forge payload)" /orders/whoami
expect "B3 payload sửa role=hr,manager + tier=premium, giữ chữ ký cũ" 401
call "$(TOKEN=$ALICE forge none)" /orders/whoami
expect "B4 alg=none, không chữ ký" 401
call "$(TOKEN=$ALICE SECRET=$REALM_PEM forge hs256)" /orders/whoami
expect "B5 alg confusion: HS256 ký bằng chứng chỉ công khai của realm" 401
# B6, B7: token thật, chữ ký đúng, nhưng sai audience. jwt_authn của Envoy cố ý trả 403
# ("Audiences in Jwt are not allowed") cho lỗi aud, 401 cho token thiếu/hỏng. Vẫn bị chặn,
# không tới backend; khác khuyến nghị 401 invalid_token của RFC 6750 §3.1 — ghi vào báo cáo.
call "$ALICE_ID" /orders/whoami
expect "B6 gửi ID token thay access token (typ=ID, aud=web-app)" 403
call "$ALICE_RT" /orders/whoami
expect "B7 gửi refresh token thay access token (typ=Refresh)" 403

echo
echo "## C. Header danh tính, host, đường dẫn (T5, luật 5)"
call "$ALICE" /orders/whoami -H "X-User: admin"
if [ "$CODE" = 200 ] && [ "$(body_user)" = "$ALICE_SUB" ]; then
  pass "C1 token alice + X-User: admin tự gửi → backend thấy sub thật, header giả đã bị xoá"
else
  fail "C1 X-User ở backend = '$(body_user)' (HTTP $CODE) — header giả lọt qua gateway"
fi
call "" /orders/whoami -H "X-User: admin"
expect "C2 không token + X-User: admin → không vào được backend" 401
call "$ALICE" /orders/whoami --http1.1 -H "x_user: admin"
expect "C3 header có gạch dưới (x_user) bị từ chối" 400
call "$ALICE" /admin
expect "C4 đường dẫn ngoài allow-list (/admin)" 404
call "$ALICE" /orders/whoami -H "Host: evil.example"
expect "C5 Host lạ (evil.example)" 404

echo
echo "## D. Không đi vòng qua gateway (T5, SR-01)"
for port in 8081 8082; do
  if curl -fsS --max-time 2 "http://localhost:$port/healthz" >/dev/null 2>&1; then
    fail "D backend cổng $port gọi thẳng được từ host"
  else
    pass "D backend cổng $port KHÔNG gọi thẳng được từ host"
  fi
done

echo
echo "Kết quả: $((N - FAIL))/$N PASS"
exit $FAIL
