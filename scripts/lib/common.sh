# shellcheck shell=bash
# Hàm dùng chung cho các script OAuth/OIDC của lab (từ tuần 3).
# Nạp bằng:  . "$(dirname "$0")/lib/common.sh"
# Chỉ cần curl, openssl, basenc, python3 (thư viện chuẩn) — không cần jq.
#
# Hai quy tắc giữ bí mật (tài sản #4, #5, #6 trong bảng tài sản):
#   1. Mật khẩu và token KHÔNG nằm trên dòng lệnh (ai trên máy cũng xem được bằng `ps`):
#      mật khẩu đi qua stdin của curl, token đi qua header đọc từ pipe  -H @<(...).
#   2. Bằng chứng ghi vào repo không chứa token/mã uỷ quyền thô (SR-10): dùng redact_*.

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
KC_URL=${KC_URL:-http://localhost:8080}
REALM=${REALM:-topic09}
ISSUER="$KC_URL/realms/$REALM"
OIDC="$ISSUER/protocol/openid-connect"
TODAY=$(date +%F)

die() { echo "LỖI: $*" >&2; exit 1; }

# env_get TÊN — đọc một biến trong .env mà không `source` cả file
# (source sẽ chạy mọi dòng trong .env như lệnh shell).
env_get() {
  local v
  v=$(grep -E "^$1=" "$ROOT/.env" 2>/dev/null | tail -1 | cut -d= -f2-)
  [ -n "$v" ] || die "thiếu $1 trong .env"
  printf '%s' "$v"
}

# b64url — đọc stdin (nhị phân), in base64url không padding (RFC 4648 §5, RFC 7515 §2).
b64url() { basenc --base64url -w0 | tr -d '='; }

# rand_b64url N — N byte ngẫu nhiên từ CSPRNG của OpenSSL, mã hoá base64url.
rand_b64url() { openssl rand "$1" | b64url; }

# json_get KEY — đọc JSON từ stdin, in giá trị của KEY (rỗng nếu không có).
json_get() {
  python3 -c 'import json, sys
d = json.load(sys.stdin)
v = d.get(sys.argv[1], "") if isinstance(d, dict) else ""
print(v if isinstance(v, str) else json.dumps(v))' "$1"
}

# bearer TOKEN — in dòng header Authorization; dùng kèm curl -H @<(bearer "$T")
# để token không xuất hiện trong danh sách tiến trình.
bearer() { printf 'Authorization: Bearer %s\n' "$1"; }

# jwt_show TOKEN — in header và payload đã giải mã của JWT.
# CHỈ để xem, KHÔNG kiểm chữ ký. Không in phần chữ ký.
jwt_show() {
  python3 - "$1" <<'PY'
import base64, json, sys
parts = sys.argv[1].split(".")
def dec(s):
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
print("    header :", json.dumps(dec(parts[0]), ensure_ascii=False))
body = json.dumps(dec(parts[1]), ensure_ascii=False, indent=2)
print("    payload:", body.replace("\n", "\n    "))
PY
}

# redact TÊN GIÁ_TRỊ — mô tả một bí mật mà không lộ nó: độ dài + 12 ký tự hex đầu của SHA-256.
# Đủ để đối chiếu hai lần chạy dùng cùng giá trị hay không, nhưng không dùng lại được.
redact() {
  printf '<%s: %d ký tự, sha256=%s…>' "$1" "${#2}" \
    "$(printf %s "$2" | openssl dgst -sha256 -r | cut -c1-12)"
}

# ---------- PKCE (RFC 7636) ----------

# pkce_new — sinh cặp PKCE mới vào hai biến CODE_VERIFIER, CODE_CHALLENGE.
#   code_verifier  = 32 byte ngẫu nhiên (256 bit) → base64url = 43 ký tự (RFC 7636 §4.1)
#   code_challenge = BASE64URL(SHA-256(ASCII(code_verifier)))       (RFC 7636 §4.2, S256)
pkce_new() {
  CODE_VERIFIER=$(rand_b64url 32)
  CODE_CHALLENGE=$(printf %s "$CODE_VERIFIER" | openssl dgst -sha256 -binary | b64url)
}

# ---------- Giả lập trình duyệt đăng nhập Keycloak ----------

# _location FILE_HEADER — giá trị header Location (bỏ \r).
_location() { { grep -i '^location:' "$1" || true; } | tail -1 | cut -d' ' -f2- | tr -d '\r'; }

# url_param URL TÊN — giá trị một tham số query trong URL (đã giải mã %XX).
url_param() {
  python3 -c 'import sys, urllib.parse as u
q = u.parse_qs(u.urlsplit(sys.argv[1]).query)
print(q.get(sys.argv[2], [""])[0])' "$1" "$2"
}

# _kc_page_msg — đọc trang HTML của Keycloak từ stdin, in thông báo lỗi trên trang (nếu có).
_kc_page_msg() {
  python3 -c 'import html, re, sys
p = sys.stdin.read()
m = (re.search(r"class=\"instruction\"[^>]*>\s*([^<]+)", p)
     or re.search(r"kc-feedback-text\"[^>]*>\s*([^<]+)", p)
     or re.search(r"<title>([^<]+)", p))
print(html.unescape(m.group(1)).strip() if m else "")'
}

# kc_authorize USER CHALLENGE METHOD REDIRECT_URI STATE NONCE
# Làm bước 3–5 của Authorization Code như một trình duyệt:
#   GET /auth → nhận trang đăng nhập → POST username/password → bắt redirect chứa code.
# CHALLENGE hoặc METHOD rỗng = không gửi tham số đó (để thử ca sai).
# Kết quả nằm trong biến: AUTH_STATUS (mã HTTP cuối), AUTH_LOCATION (header Location),
# AUTH_FORM (URL form đăng nhập), AUTH_MSG (thông báo lỗi trên trang, nếu có).
kc_authorize() {
  local user=$1 challenge=$2 method=$3 redirect=$4 state=$5 nonce=$6
  local d
  d=$(mktemp -d)
  local args=(-G "$OIDC/auth" -d response_type=code -d "client_id=${CLIENT_ID:-web-app}"
    --data-urlencode "redirect_uri=$redirect" -d scope=openid -d "state=$state" -d "nonce=$nonce")
  [ -n "$challenge" ] && args+=(-d "code_challenge=$challenge")
  [ -n "$method" ] && args+=(-d "code_challenge_method=$method")

  # Bước 3: GET /auth. Cookie phiên đăng nhập giữ trong thư mục tạm, xoá khi xong.
  AUTH_STATUS=$(curl -sS -o "$d/body" -D "$d/hdr" -w '%{http_code}' -c "$d/jar" -b "$d/jar" "${args[@]}")
  AUTH_LOCATION=$(_location "$d/hdr")
  AUTH_FORM=""
  AUTH_MSG=$(_kc_page_msg <"$d/body")
  if [ "$AUTH_STATUS" = 200 ]; then
    AUTH_FORM=$(python3 -c 'import html, re, sys
p = sys.stdin.read()
m = (re.search(r"<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"", p)
     or re.search(r"action=\"([^\"]*login-actions/authenticate[^\"]*)\"", p))
print(html.unescape(m.group(1)) if m else "")' <"$d/body")
  fi
  if [ -n "$AUTH_FORM" ]; then
    # Bước 4: POST form đăng nhập. Mật khẩu đi qua stdin (password@-), không nằm trên dòng lệnh.
    # Không theo redirect (-L) để bắt được Location chứa code.
    AUTH_STATUS=$(env_get LAB_USER_PASSWORD |
      curl -sS -o "$d/body" -D "$d/hdr" -w '%{http_code}' -c "$d/jar" -b "$d/jar" "$AUTH_FORM" \
        --data-urlencode "username=$user" --data-urlencode "password@-" -d credentialId=)
    AUTH_LOCATION=$(_location "$d/hdr")
    AUTH_MSG=$(_kc_page_msg <"$d/body")
  fi
  rm -rf "$d"
}

# post_form URL OUT — POST body x-www-form-urlencoded đọc từ stdin, ghi body trả về vào file OUT,
# đặt biến HTTP_STATUS. Body đi qua stdin để code, verifier, client assertion không nằm trên
# dòng lệnh (printf là lệnh dựng sẵn của bash, không tạo tiến trình mới nên không hiện trong ps):
#   post_form "$OIDC/token" "$TMP/tok.json" < <(printf 'code=%s&code_verifier=%s' "$C" "$V")
post_form() {
  HTTP_STATUS=$(curl -sS -o "$2" -w '%{http_code}' \
    -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @- "$1")
}

# urlenc GIÁ_TRỊ — mã hoá %XX (chỉ dùng cho giá trị không bí mật, vì nằm trên dòng lệnh python).
urlenc() { python3 -c 'import sys, urllib.parse as u; print(u.quote(sys.argv[1], safe=""))' "$1"; }

# ---------- JWS ES256 (dùng cho private_key_jwt, tuần 6 dùng lại cho DPoP proof) ----------

# sign_es256 KEY.pem — đọc signing input (header.payload) từ stdin, in chữ ký base64url.
# openssl trả chữ ký ECDSA dạng DER: SEQUENCE { INTEGER r, INTEGER s }.
# JWS yêu cầu r ‖ s, mỗi số đúng 32 byte big-endian (RFC 7518 §3.4) → đổi định dạng bằng python.
sign_es256() {
  openssl dgst -sha256 -sign "$1" | python3 -c 'import sys
der = sys.stdin.buffer.read()
assert der[0] == 0x30, "không phải SEQUENCE"
i, out = 2, b""
for _ in range(2):
    assert der[i] == 0x02, "không phải INTEGER"
    n = der[i + 1]
    v = der[i + 2 : i + 2 + n].lstrip(b"\x00")   # DER thêm 0x00 nếu bit cao = 1
    out += v.rjust(32, b"\x00")                   # đệm trái cho đủ 32 byte
    i += 2 + n
sys.stdout.buffer.write(out)' | b64url
}

# jws_es256 KEY.pem HEADER_JSON PAYLOAD_JSON — in JWS compact: b64(header).b64(payload).b64(sig)
jws_es256() {
  local h p
  h=$(printf %s "$2" | b64url)
  p=$(printf %s "$3" | b64url)
  printf '%s.%s.%s' "$h" "$p" "$(printf '%s.%s' "$h" "$p" | sign_es256 "$1")"
}

# ---------- DPoP (RFC 9449) — tuần 6 ----------
# Client giữ một cặp khoá riêng (tài sản #9). Mỗi request kèm một "DPoP proof": JWT ngắn hạn
# ký bằng khoá riêng, mang khoá công khai trong header (jwk), ghi method (htm) + URL (htu) +
# thời điểm (iat) + mã ngẫu nhiên (jti), và — khi gọi API — hash của access token (ath).
# Keycloak gắn token vào khoá bằng claim cnf.jkt = thumbprint của khoá công khai.

# dpop_keygen FILE — sinh khoá EC P-256 cho DPoP, quyền 600.
dpop_keygen() { (umask 077 && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null); }

# dpop_jwk FILE — JWK CÔNG KHAI của khoá: chỉ crv, kty, x, y (không có "d" = khoá riêng),
# khoá xếp theo thứ tự chữ cái, không khoảng trắng — đúng dạng RFC 7638 §3 để tính thumbprint.
dpop_jwk() {
  openssl pkey -in "$1" -pubout -outform DER | python3 -c 'import base64, json, sys
der = sys.stdin.buffer.read()
pt = der[-65:]   # SubjectPublicKeyInfo của P-256 dài 91 byte; 65 byte cuối là điểm 04 || X || Y
assert len(der) == 91 and pt[0] == 4, "không phải khoá công khai P-256"
b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
print(json.dumps({"crv": "P-256", "kty": "EC", "x": b(pt[1:33]), "y": b(pt[33:])}, separators=(",", ":")))'
}

# dpop_jkt FILE — thumbprint JWK (RFC 7638) = BASE64URL(SHA-256(JWK dạng gọn)).
dpop_jkt() { dpop_jwk "$1" | tr -d '\n' | openssl dgst -sha256 -binary | b64url; }

# dpop_ath TOKEN — BASE64URL(SHA-256(ASCII(access token))) (RFC 9449 §4.2).
dpop_ath() { printf %s "$1" | openssl dgst -sha256 -binary | b64url; }

# dpop_proof FILE METHOD URL [ACCESS_TOKEN] — in một DPoP proof MỚI (jti ngẫu nhiên, iat = bây giờ).
# Có ACCESS_TOKEN thì thêm ath (bắt buộc khi gọi resource server). Để thử ca sai, đặt biến:
#   DPOP_TYP, DPOP_IAT, DPOP_JTI, DPOP_HTM, DPOP_HTU, DPOP_ATH, DPOP_JWK (JSON thay cho khoá thật).
dpop_proof() {
  local key=$1 htm=${DPOP_HTM:-$2} htu=${DPOP_HTU:-$3} tok=${4:-} header payload ath
  header=$(printf '{"typ":"%s","alg":"ES256","jwk":%s}' "${DPOP_TYP:-dpop+jwt}" "${DPOP_JWK:-$(dpop_jwk "$key")}")
  payload=$(printf '{"jti":"%s","htm":"%s","htu":"%s","iat":%d' \
    "${DPOP_JTI:-$(rand_b64url 16)}" "$htm" "$htu" "${DPOP_IAT:-$(date +%s)}")
  ath=${DPOP_ATH:-}
  [ -z "$ath" ] && [ -n "$tok" ] && ath=$(dpop_ath "$tok")
  [ -n "$ath" ] && payload+=$(printf ',"ath":"%s"' "$ath")
  jws_es256 "$key" "$header" "$payload}"
}

# dpop_header PROOF — dòng header DPoP cho curl -H @<(dpop_header "$P")
dpop_header() { printf 'DPoP: %s\n' "$1"; }

# dpop_auth TOKEN — dòng Authorization theo scheme DPoP (RFC 9449 §7.1), không phải Bearer.
dpop_auth() { printf 'Authorization: DPoP %s\n' "$1"; }

# ---------- Admin REST API ----------

# kc_admin_token — access token quản trị (realm master, client admin-cli).
# Mật khẩu admin đi qua stdin của curl (password@-), không nằm trên dòng lệnh.
kc_admin_token() {
  local user
  user=$(grep -E '^KC_ADMIN_USER=' "$ROOT/.env" | cut -d= -f2-)
  env_get KC_ADMIN_PASSWORD |
    curl -fsS "$KC_URL/realms/master/protocol/openid-connect/token" \
      -d grant_type=password -d client_id=admin-cli \
      --data-urlencode "username=${user:-admin}" --data-urlencode "password@-" |
    json_get access_token
}

# kc_api TOKEN [curl-args...] ĐƯỜNG_DẪN — gọi Admin REST API của realm, ví dụ:
#   kc_api "$ADM" users?briefRepresentation=false
kc_api() {
  local tok=$1
  shift
  local path=${*: -1}
  curl -fsS -H @<(bearer "$tok") "${@:1:$#-1}" "$KC_URL/admin/realms/$REALM${path:+/$path}"
}
