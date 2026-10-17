#!/usr/bin/env bash
# Tuần 3 T6 — chạy Authorization Code + PKCE (S256) với client public web-app bằng curl,
# in trace từng bước (bí mật đã che). Xem docs/notes/oauth-pkce-rfc9700.md mục 1.
#
#   ./scripts/pkce-login.sh alice                       # in trace
#   ./scripts/pkce-login.sh alice | tee docs/traces/pkce-auth-code-$(date +%F).txt
#   TOKEN=$(./scripts/pkce-login.sh alice --token)     # chỉ in access token (cho script khác)
#   ./scripts/pkce-login.sh alice --id-token            # chỉ in ID token (để thử gửi nhầm loại token)
#   ./scripts/pkce-login.sh alice --refresh-token       # chỉ in refresh token (như trên)
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

USER_NAME=${1:-alice}
MODE=${2:-trace}
REDIRECT_URI=http://localhost:3000/callback
say() { if [ "$MODE" = trace ]; then echo "$@"; fi; }

say "# Authorization Code + PKCE — user $USER_NAME — $(date -Iseconds)"
say "# Issuer: $ISSUER   Client: web-app (public)"

# Bước 1–2: client tự sinh PKCE, state (chống CSRF) và nonce (gắn ID token với request này).
pkce_new
STATE=$(rand_b64url 16)
NONCE=$(rand_b64url 16)
say
say "## Bước 1–2: client sinh PKCE, state, nonce"
say "code_verifier  = $(redact code_verifier "$CODE_VERIFIER")   ← bí mật, chỉ client giữ"
say "code_challenge = $CODE_CHALLENGE   ← BASE64URL(SHA-256(code_verifier)), gửi công khai"
say "state = $STATE   nonce = $NONCE"

# Bước 3–4: trình duyệt tới /auth, user đăng nhập, AS redirect về redirect_uri kèm code.
kc_authorize "$USER_NAME" "$CODE_CHALLENGE" S256 "$REDIRECT_URI" "$STATE" "$NONCE"
say
say "## Bước 3: GET $OIDC/auth"
say "   ?response_type=code&client_id=web-app&redirect_uri=$(urlenc "$REDIRECT_URI")&scope=openid"
say "   &state=$STATE&nonce=$NONCE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"
say "< 200 — trang đăng nhập; form action = ${AUTH_FORM%%\?*}?session_code=…"
say
say "## Bước 4: POST form đăng nhập (username=$USER_NAME, password=<che>)"
[ "$AUTH_STATUS" = 302 ] || die "đăng nhập thất bại: HTTP $AUTH_STATUS — $AUTH_MSG"
CODE=$(url_param "$AUTH_LOCATION" code)
[ -n "$CODE" ] || die "redirect không có code: error=$(url_param "$AUTH_LOCATION" error)"
say "< 302 Found"
say "< Location: ${AUTH_LOCATION%%\?*}?state=$(url_param "$AUTH_LOCATION" state)&iss=$(url_param "$AUTH_LOCATION" iss)&code=$(redact code "$CODE")"

# Bước 5: client kiểm state (CSRF, RFC 9700 §4.7) và iss (mix-up, RFC 9700 §4.4 / RFC 9207).
say
say "## Bước 5: client kiểm response"
[ "$(url_param "$AUTH_LOCATION" state)" = "$STATE" ] || die "state không khớp — có thể bị CSRF, dừng"
say "state khớp giá trị đã gửi: OK"
[ "$(url_param "$AUTH_LOCATION" iss)" = "$ISSUER" ] || die "iss lạ — có thể bị mix-up, dừng"
say "iss = $ISSUER: OK"

# Bước 6: đổi code lấy token ở kênh sau, kèm code_verifier. Body đi qua stdin.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
post_form "$OIDC/token" "$TMP/tokens.json" < <(
  printf 'grant_type=authorization_code&client_id=web-app&redirect_uri=%s&code=%s&code_verifier=%s' \
    "$(urlenc "$REDIRECT_URI")" "$CODE" "$CODE_VERIFIER"
)
TOKENS=$(cat "$TMP/tokens.json")
[ "$HTTP_STATUS" = 200 ] || die "token endpoint trả $HTTP_STATUS: $TOKENS"
ACCESS=$(printf %s "$TOKENS" | json_get access_token)
IDTOK=$(printf %s "$TOKENS" | json_get id_token)
REFRESH=$(printf %s "$TOKENS" | json_get refresh_token)

case $MODE in
  --token) printf '%s\n' "$ACCESS"; exit 0 ;;
  --id-token) printf '%s\n' "$IDTOK"; exit 0 ;;
  --refresh-token) printf '%s\n' "$REFRESH"; exit 0 ;;
esac

say
say "## Bước 6: POST $OIDC/token"
say "> grant_type=authorization_code, client_id=web-app, redirect_uri=$REDIRECT_URI,"
say "> code=$(redact code "$CODE"), code_verifier=$(redact code_verifier "$CODE_VERIFIER")"
say "< 200 OK  token_type=$(printf %s "$TOKENS" | json_get token_type)  expires_in=$(printf %s "$TOKENS" | json_get expires_in)  scope=$(printf %s "$TOKENS" | json_get scope)"
say
say "## Bước 7: token nhận được (giải mã để xem, chưa kiểm chữ ký — việc của gateway)"
say "access_token  = $(redact access_token "$ACCESS")"
jwt_show "$ACCESS"
say "id_token      = $(redact id_token "$IDTOK")"
python3 - "$IDTOK" "$NONCE" <<'PY'
import base64, json, sys
p = sys.argv[1].split(".")[1]
c = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
print(f"    typ={c.get('typ')} aud={c.get('aud')} nonce khớp: {'OK' if c.get('nonce') == sys.argv[2] else 'SAI'}")
PY
say "refresh_token = $(redact refresh_token "$REFRESH")"
