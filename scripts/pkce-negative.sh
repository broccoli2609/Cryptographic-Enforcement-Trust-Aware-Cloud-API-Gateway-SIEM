#!/usr/bin/env bash
# Tuần 3 T6 — các ca SAI của Authorization Code + PKCE: Keycloak phải từ chối tất cả (T3, SR-03).
# Mỗi ca in PASS nếu bị từ chối đúng cách; mã thoát = số ca FAIL.
#   ./scripts/pkce-negative.sh | tee docs/evidence/pkce-negative-$(date +%F).txt
set -uo pipefail
. "$(dirname "$0")/lib/common.sh"

GOOD_REDIRECT=http://localhost:3000/callback
USER_NAME=alice
FAIL=0
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }

# Lỗi do AS trả về (error + error_description) — không chứa bí mật, ghi được vào bằng chứng.
redirect_error() { echo "error=$(url_param "$AUTH_LOCATION" error) ($(url_param "$AUTH_LOCATION" error_description))"; }
token_error() { echo "error=$(json_get error <"$TMP/out.json") ($(json_get error_description <"$TMP/out.json"))"; }

# get_code CHALLENGE METHOD — đăng nhập hợp lệ, đặt biến CODE (rỗng nếu AS không cấp code).
get_code() {
  kc_authorize "$USER_NAME" "$1" "$2" "$GOOD_REDIRECT" "$(rand_b64url 16)" "$(rand_b64url 16)"
  CODE=$(url_param "$AUTH_LOCATION" code)
}
# exchange CODE VERIFIER REDIRECT — gọi token endpoint (VERIFIER rỗng = không gửi tham số).
exchange() {
  post_form "$OIDC/token" "$TMP/out.json" < <(
    printf 'grant_type=authorization_code&client_id=web-app&redirect_uri=%s&code=%s' "$(urlenc "$3")" "$1"
    [ -n "$2" ] && printf '&code_verifier=%s' "$2"
  )
}

echo "# PKCE — các ca sai phải bị từ chối — $(date -Iseconds)"
echo "# Client web-app (public, pkce.code.challenge.method=S256), user $USER_NAME"

echo
echo "1. Thiếu code_challenge (PKCE downgrade, RFC 9700 §4.8)"
get_code "" ""
if [ -z "$CODE" ]; then pass "không cấp code — $(redirect_error)"; else fail "AS vẫn cấp code khi thiếu code_challenge"; fi

echo
echo "2. code_challenge_method=plain (challenge = verifier, mất tính một chiều)"
pkce_new
get_code "$CODE_VERIFIER" plain
if [ -z "$CODE" ]; then pass "không cấp code — $(redirect_error)"; else fail "AS chấp nhận method plain"; fi

echo
echo "3. redirect_uri lạ (http://localhost:3000/callback/../evil) — so khớp chính xác (RFC 9700 §2.1)"
pkce_new
kc_authorize "$USER_NAME" "$CODE_CHALLENGE" S256 "http://localhost:3000/callback/../evil" x y
if [ "$AUTH_STATUS" != 302 ] && [ -z "$AUTH_FORM" ]; then
  pass "HTTP $AUTH_STATUS, không hiện form đăng nhập, không redirect — \"$AUTH_MSG\""
else
  fail "AS chấp nhận redirect_uri lạ (HTTP $AUTH_STATUS, Location=${AUTH_LOCATION%%\?*})"
fi

echo
echo "4. Có code hợp lệ nhưng code_verifier SAI (kẻ tấn công chặn được code, RFC 9700 §4.5)"
pkce_new
get_code "$CODE_CHALLENGE" S256
exchange "$CODE" "$(rand_b64url 32)" "$GOOD_REDIRECT"
if [ "$HTTP_STATUS" = 400 ]; then pass "HTTP 400 — $(token_error)"; else fail "HTTP $HTTP_STATUS — đổi được code bằng verifier sai"; fi

echo
echo "5. Có code hợp lệ nhưng KHÔNG gửi code_verifier"
pkce_new
get_code "$CODE_CHALLENGE" S256
exchange "$CODE" "" "$GOOD_REDIRECT"
if [ "$HTTP_STATUS" = 400 ]; then pass "HTTP 400 — $(token_error)"; else fail "HTTP $HTTP_STATUS — đổi được code khi thiếu verifier"; fi

echo
echo "6. Token request với redirect_uri khác lúc authorize"
pkce_new
get_code "$CODE_CHALLENGE" S256
exchange "$CODE" "$CODE_VERIFIER" "http://localhost:3000/other"
if [ "$HTTP_STATUS" = 400 ]; then pass "HTTP 400 — $(token_error)"; else fail "HTTP $HTTP_STATUS"; fi

echo
echo "7. Dùng lại code đã đổi thành công (code chỉ dùng một lần)"
pkce_new
get_code "$CODE_CHALLENGE" S256
exchange "$CODE" "$CODE_VERIFIER" "$GOOD_REDIRECT"
first=$HTTP_STATUS
exchange "$CODE" "$CODE_VERIFIER" "$GOOD_REDIRECT"
if [ "$first" = 200 ] && [ "$HTTP_STATUS" = 400 ]; then
  pass "lần 1 HTTP 200, lần 2 HTTP 400 — $(token_error)"
else
  fail "lần 1 HTTP $first, lần 2 HTTP $HTTP_STATUS"
fi

echo
echo "Kết quả: $((7 - FAIL))/7 PASS"
exit $FAIL
