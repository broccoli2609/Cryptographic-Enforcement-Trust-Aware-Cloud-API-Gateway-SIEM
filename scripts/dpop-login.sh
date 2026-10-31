#!/usr/bin/env bash
# Tuần 6 T5 — Authorization Code + PKCE + DPoP (RFC 9449) với client public web-app-dpop.
# Client tự sinh cặp khoá DPoP, gửi DPoP proof khi đổi code lấy token; Keycloak gắn token vào
# khoá (cnf.jkt). In trace từng bước rồi chạy các ca sai mà Keycloak phải từ chối.
#
#   ./scripts/dpop-login.sh alice KEY.pem                    # trace + ca sai
#   ./scripts/dpop-login.sh alice KEY.pem | tee docs/traces/dpop-token-$(date +%F).txt
#   TOKEN=$(./scripts/dpop-login.sh alice KEY.pem --token)  # chỉ in access token (cho script khác)
# KEY.pem chưa có thì sinh mới (quyền 600). Token chỉ dùng được cùng khoá này.
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

USER_NAME=${1:-alice}
KEY=${2:?cách dùng: $0 <user> <dpop-key.pem> [--token]}
MODE=${3:-trace}
REDIRECT_URI=http://localhost:3000/callback
export CLIENT_ID=web-app-dpop # kc_authorize đọc biến này
TOKEN_URL="$OIDC/token"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
say() { if [ "$MODE" = trace ]; then echo "$@"; fi; }
FAIL=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }

# show_jwt JWT — in header + payload đã giải mã (KHÔNG in JWT thô: proof cũng bắt đầu bằng eyJ…).
show_jwt() { jwt_show "$1"; }

# token_req PROOF — POST /token, body đọc từ stdin, kèm header DPoP nếu PROOF khác rỗng.
# Đặt HTTP_STATUS; body trả về ở $TMP/out.json. Proof/code đi qua pipe, không nằm trên dòng lệnh.
token_req() {
  local args=(-sS -o "$TMP/out.json" -w '%{http_code}' -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @-)
  if [ -n "$1" ]; then
    HTTP_STATUS=$(curl "${args[@]}" -H @<(dpop_header "$1") "$TOKEN_URL")
  else
    HTTP_STATUS=$(curl "${args[@]}" "$TOKEN_URL")
  fi
}
as_error() { echo "error=$(json_get error <"$TMP/out.json") ($(json_get error_description <"$TMP/out.json"))"; }

# login_code — chạy bước PKCE + đăng nhập (giống pkce-login.sh), đặt CODE và CODE_VERIFIER.
login_code() {
  pkce_new
  local state nonce
  state=$(rand_b64url 16)
  nonce=$(rand_b64url 16)
  kc_authorize "$USER_NAME" "$CODE_CHALLENGE" S256 "$REDIRECT_URI" "$state" "$nonce"
  [ "$AUTH_STATUS" = 302 ] || die "đăng nhập thất bại: HTTP $AUTH_STATUS — $AUTH_MSG"
  [ "$(url_param "$AUTH_LOCATION" state)" = "$state" ] || die "state không khớp"
  [ "$(url_param "$AUTH_LOCATION" iss)" = "$ISSUER" ] || die "iss lạ"
  CODE=$(url_param "$AUTH_LOCATION" code)
  [ -n "$CODE" ] || die "redirect không có code"
}
code_body() {
  printf 'grant_type=authorization_code&client_id=%s&redirect_uri=%s&code=%s&code_verifier=%s' \
    "$CLIENT_ID" "$(urlenc "$REDIRECT_URI")" "$CODE" "$CODE_VERIFIER"
}
refresh_body() { printf 'grant_type=refresh_token&client_id=%s&refresh_token=%s' "$CLIENT_ID" "$1"; }

# --- Bước 1: khoá DPoP của client ---
[ -f "$KEY" ] || dpop_keygen "$KEY"
JKT=$(dpop_jkt "$KEY")

# --- Bước 2–5: PKCE + đăng nhập ---
login_code

# --- Bước 6: đổi code lấy token, KÈM DPoP proof cho token endpoint (htm=POST, htu=token URL, không ath) ---
PROOF=$(dpop_proof "$KEY" POST "$TOKEN_URL")
token_req "$PROOF" < <(code_body)
[ "$HTTP_STATUS" = 200 ] || die "token endpoint trả $HTTP_STATUS: $(as_error)"
ACCESS=$(json_get access_token <"$TMP/out.json")
REFRESH=$(json_get refresh_token <"$TMP/out.json")
TOKEN_TYPE=$(json_get token_type <"$TMP/out.json")

if [ "$MODE" = --token ]; then
  printf '%s\n' "$ACCESS"
  exit 0
fi

echo "# Authorization Code + PKCE + DPoP — user $USER_NAME, client $CLIENT_ID — $(date -Iseconds)"
echo "# Issuer: $ISSUER"
echo
echo "## Bước 1: client sinh cặp khoá DPoP (EC P-256) — khoá riêng không bao giờ rời client"
echo "jwk công khai = $(dpop_jwk "$KEY")"
echo "jkt (RFC 7638) = BASE64URL(SHA-256(jwk)) = $JKT"
echo
echo "## Bước 2–5: PKCE S256 + đăng nhập như pkce-login.sh (state, iss đã kiểm) → nhận code"
echo "code = $(redact code "$CODE")"
echo
echo "## Bước 6: POST $TOKEN_URL kèm header DPoP"
echo "> grant_type=authorization_code, client_id=$CLIENT_ID, code=<che>, code_verifier=<che>"
echo "> DPoP: $(redact dpop_proof "$PROOF")"
show_jwt "$PROOF"
echo "< 200 OK  token_type=$TOKEN_TYPE  expires_in=$(json_get expires_in <"$TMP/out.json")"
[ "$TOKEN_TYPE" = DPoP ] && pass "token_type = DPoP (không phải Bearer)" || fail "token_type = $TOKEN_TYPE (muốn DPoP)"
echo
echo "## Bước 7: access token gắn với khoá (claim cnf.jkt)"
echo "access_token = $(redact access_token "$ACCESS")"
show_jwt "$ACCESS"
CNF=$(TOKEN=$ACCESS python3 -c 'import base64,json,os; p=os.environ["TOKEN"].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))).get("cnf",{}).get("jkt",""))')
[ "$CNF" = "$JKT" ] && pass "cnf.jkt trong token = jkt của khoá client ($JKT)" || fail "cnf.jkt = '$CNF', muốn $JKT"

echo
echo "## Ca sai ở token endpoint — Keycloak phải từ chối"

echo "1. Đổi code KHÔNG kèm DPoP proof (client bắt buộc DPoP: dpop.bound.access.tokens=true)"
login_code
token_req "" < <(code_body)
[ "$HTTP_STATUS" != 200 ] && pass "HTTP $HTTP_STATUS — $(as_error)" || fail "không có proof vẫn được token"

echo "2. Proof có htu sai (ký cho URL khác)"
login_code
token_req "$(DPOP_HTU=http://localhost:8080/realms/other/token dpop_proof "$KEY" POST "$TOKEN_URL")" < <(code_body)
[ "$HTTP_STATUS" != 200 ] && pass "HTTP $HTTP_STATUS — $(as_error)" || fail "htu sai vẫn được token"

echo "3. Proof cũ (iat = 10 phút trước)"
login_code
token_req "$(DPOP_IAT=$(($(date +%s) - 600)) dpop_proof "$KEY" POST "$TOKEN_URL")" < <(code_body)
[ "$HTTP_STATUS" != 200 ] && pass "HTTP $HTTP_STATUS — $(as_error)" || fail "proof cũ vẫn được token"

echo "4. Proof typ=JWT (không phải dpop+jwt)"
login_code
token_req "$(DPOP_TYP=JWT dpop_proof "$KEY" POST "$TOKEN_URL")" < <(code_body)
[ "$HTTP_STATUS" != 200 ] && pass "HTTP $HTTP_STATUS — $(as_error)" || fail "typ sai vẫn được token"

echo
echo "## Refresh token của client public cũng gắn với khoá (RFC 9449 §5)"
dpop_keygen "$TMP/attacker.pem"
echo "5. Kẻ trộm refresh token dùng khoá của mình"
token_req "$(dpop_proof "$TMP/attacker.pem" POST "$TOKEN_URL")" < <(refresh_body "$REFRESH")
[ "$HTTP_STATUS" != 200 ] && pass "HTTP $HTTP_STATUS — $(as_error)" || fail "refresh bằng khoá lạ vẫn được token"
echo "6. Refresh không kèm proof"
token_req "" < <(refresh_body "$REFRESH")
[ "$HTTP_STATUS" != 200 ] && pass "HTTP $HTTP_STATUS — $(as_error)" || fail "refresh không proof vẫn được token"
echo "7. Chủ thật refresh bằng đúng khoá → được token mới, vẫn cùng jkt"
token_req "$(dpop_proof "$KEY" POST "$TOKEN_URL")" < <(refresh_body "$REFRESH")
if [ "$HTTP_STATUS" = 200 ]; then
  NEW=$(json_get access_token <"$TMP/out.json")
  NEWCNF=$(TOKEN=$NEW python3 -c 'import base64,json,os; p=os.environ["TOKEN"].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))).get("cnf",{}).get("jkt",""))')
  [ "$NEWCNF" = "$JKT" ] && pass "HTTP 200, token mới có cnf.jkt = $NEWCNF" || fail "token mới cnf.jkt = '$NEWCNF'"
else
  fail "HTTP $HTTP_STATUS — $(as_error)"
fi

echo
echo "Kết quả ca sai + kiểm: $FAIL FAIL"
exit $FAIL
