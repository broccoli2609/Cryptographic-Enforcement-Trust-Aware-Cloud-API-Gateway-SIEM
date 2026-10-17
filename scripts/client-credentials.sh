#!/usr/bin/env bash
# Tuần 3 T6 — Client Credentials + private_key_jwt (RFC 7523, OIDC Core §9) cho batch-worker.
# Client tự ký một JWT ngắn hạn (client assertion) bằng khoá riêng ES256 thay cho client_secret.
# Sau ca đúng, chạy 5 ca sai mà Keycloak phải từ chối.
#
#   ./scripts/client-credentials.sh | tee docs/traces/client-credentials-$(date +%F).txt
#   TOKEN=$(./scripts/client-credentials.sh --token)
# Cần chạy ./scripts/batch-worker-key.sh trước (sinh + đăng ký khoá).
set -uo pipefail
. "$(dirname "$0")/lib/common.sh"

KEY="$ROOT/secrets/batch-worker/key.pem"
[ -f "$KEY" ] || die "chưa có $KEY — chạy ./scripts/batch-worker-key.sh"
MODE=${1:-trace}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
FAIL=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }

# assertion_payload AUD IAT EXP — claim của client assertion (RFC 7523 §3).
#   iss = sub = client_id; aud = issuer của AS; jti ngẫu nhiên để AS chặn dùng lại; exp ngắn (60 s).
assertion_payload() {
  printf '{"iss":"batch-worker","sub":"batch-worker","aud":"%s","jti":"%s","iat":%d,"exp":%d}' \
    "$1" "$(rand_b64url 16)" "$2" "$3"
}

# request_token ASSERTION — POST /token với grant client_credentials. Assertion đi qua stdin.
request_token() {
  post_form "$OIDC/token" "$TMP/out.json" < <(
    printf 'grant_type=client_credentials&client_assertion_type=%s&client_assertion=%s' \
      "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer" "$1"
  )
}
as_error() { echo "error=$(json_get error <"$TMP/out.json") ($(json_get error_description <"$TMP/out.json"))"; }

NOW=$(date +%s)
HEADER='{"alg":"ES256","typ":"JWT"}'
PAYLOAD=$(assertion_payload "$ISSUER" "$NOW" $((NOW + 60)))
ASSERTION=$(jws_es256 "$KEY" "$HEADER" "$PAYLOAD")
request_token "$ASSERTION"

if [ "$MODE" = --token ]; then
  [ "$HTTP_STATUS" = 200 ] || die "token endpoint trả $HTTP_STATUS: $(cat "$TMP/out.json")"
  json_get access_token <"$TMP/out.json"
  exit 0
fi

echo "# Client Credentials + private_key_jwt — client batch-worker — $(date -Iseconds)"
echo
echo "## Bước 1: client ký client assertion bằng khoá riêng ES256 (secrets/batch-worker/key.pem)"
echo "header : $HEADER"
echo "payload: $PAYLOAD"
echo "assertion = $(redact client_assertion "$ASSERTION")"
echo
echo "## Bước 2: POST $OIDC/token"
echo "> grant_type=client_credentials"
echo "> client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
echo "> client_assertion=<che>     (không có client_secret nào được gửi)"
[ "$HTTP_STATUS" = 200 ] || die "token endpoint trả $HTTP_STATUS: $(cat "$TMP/out.json")"
ACCESS=$(json_get access_token <"$TMP/out.json")
echo "< 200 OK  token_type=$(json_get token_type <"$TMP/out.json")  expires_in=$(json_get expires_in <"$TMP/out.json")  refresh_token=$(json_get refresh_token <"$TMP/out.json" | grep -q . && echo có || echo 'không có (đúng: client_credentials.use_refresh_token=false)')"
echo "access_token = $(redact access_token "$ACCESS")"
jwt_show "$ACCESS"

echo
echo "## Các ca sai — Keycloak phải từ chối"

echo "1. Phát lại đúng assertion vừa dùng (cùng jti)"
request_token "$ASSERTION"
if [ "$HTTP_STATUS" != 200 ]; then pass "HTTP $HTTP_STATUS — $(as_error)"; else fail "dùng lại assertion vẫn được token"; fi

echo "2. Assertion ký bằng khoá EC của kẻ tấn công (đúng định dạng, sai khoá)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TMP/attacker.pem"
request_token "$(jws_es256 "$TMP/attacker.pem" "$HEADER" "$(assertion_payload "$ISSUER" "$NOW" $((NOW + 60)))")"
if [ "$HTTP_STATUS" != 200 ]; then pass "HTTP $HTTP_STATUS — $(as_error)"; else fail "khoá lạ vẫn được token"; fi

echo "3. Assertion đã hết hạn (iat = -10 phút, exp = -9 phút)"
request_token "$(jws_es256 "$KEY" "$HEADER" "$(assertion_payload "$ISSUER" $((NOW - 600)) $((NOW - 540)))")"
if [ "$HTTP_STATUS" != 200 ]; then pass "HTTP $HTTP_STATUS — $(as_error)"; else fail "assertion hết hạn vẫn được token"; fi

echo "4. alg=RS256 (client bị ghim ES256 — token.endpoint.auth.signing.alg)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/rsa.pem" 2>/dev/null
h=$(printf %s '{"alg":"RS256","typ":"JWT"}' | b64url)
p=$(assertion_payload "$ISSUER" "$NOW" $((NOW + 60)) | b64url)
s=$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -sign "$TMP/rsa.pem" | b64url)
request_token "$h.$p.$s"
if [ "$HTTP_STATUS" != 200 ]; then pass "HTTP $HTTP_STATUS — $(as_error)"; else fail "alg ngoài allow-list vẫn được token"; fi

echo "5. aud sai (issuer của realm khác)"
request_token "$(jws_es256 "$KEY" "$HEADER" "$(assertion_payload "$KC_URL/realms/master" "$NOW" $((NOW + 60)))")"
if [ "$HTTP_STATUS" != 200 ]; then pass "HTTP $HTTP_STATUS — $(as_error)"; else fail "aud sai vẫn được token"; fi

echo
echo "Kết quả ca sai: $((5 - FAIL))/5 PASS"
exit $FAIL
