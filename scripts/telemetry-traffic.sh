#!/usr/bin/env bash
# Tuần 8 — sinh một lượt request đại diện qua cả ba profile để MỌI nguồn log đều có sự kiện:
# Envoy (P0/P1/P2), auth-svc, OPA, orders-api, profile-api. Có ca cho qua, ca gateway chặn
# (BFLA, ABAC, token hỏng, DPoP replay) và ca backend chặn (BOLA, ẩn salary_band).
#
#   ./scripts/telemetry-traffic.sh [FILE_TSV]
#
# In mỗi request một dòng (cổng, mã HTTP, mô tả, request_id). Có FILE_TSV thì ghi thêm
#   request_id<TAB>cổng<TAB>mã HTTP<TAB>mô tả
# để script khác nối với log. Script này KHÔNG chấm đúng/sai — việc chấm ở telemetry-schema-test.sh
# (khớp schema) và siem-test.sh (đường ống Vector → OpenSearch).
# Token và proof đi qua header đọc từ pipe, không nằm trên dòng lệnh, không in ra.
set -uo pipefail
. "$(dirname "$0")/lib/common.sh"
cd "$ROOT" || exit 1

CA="$ROOT/secrets/tls/ca.crt"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
OUT=${1:-}
[ -n "$OUT" ] && : >"$OUT"
JSON=(-H 'Content-Type: application/json' -d)

# req MÔ_TẢ CỔNG METHOD PATH DÒNG_AUTH PROOF [curl-args...]
# DÒNG_AUTH rỗng = không gửi Authorization; PROOF rỗng = không gửi header DPoP.
req() {
  local label=$1 port=$2 method=$3 path=$4 auth=$5 proof=$6 code rid
  shift 6
  rm -f "$TMP/hdr"
  code=$(curl -sS --cacert "$CA" --max-time 5 -o "$TMP/body" -D "$TMP/hdr" -w '%{http_code}' -X "$method" \
    -H @<(if [ -n "$auth" ]; then printf '%s\n' "$auth"; fi; if [ -n "$proof" ]; then dpop_header "$proof"; fi) \
    "$@" "https://localhost:$port$path" 2>/dev/null)
  touch "$TMP/hdr"
  rid=$(grep -i '^x-request-id:' "$TMP/hdr" | cut -d' ' -f2 | tr -d '\r')
  printf '  :%s  %s  %-66s %s\n' "$port" "$code" "$label" "$rid"
  [ -n "$OUT" ] && printf '%s\t%s\t%s\t%s\n' "$rid" "$port" "$code" "$label" >>"$OUT"
  return 0
}
b() { printf 'Authorization: Bearer %s' "$1"; }
sub_of() { TOKEN=$1 python3 -c 'import base64,json,os; p=os.environ["TOKEN"].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4)))["sub"])'; }

for u in alice bob carol dave; do
  printf -v "TOK_${u^^}" '%s' "$("$(dirname "$0")/pkce-login.sh" "$u" --token)" || die "không lấy được token của $u"
done
TOK_BATCH=$("$(dirname "$0")/client-credentials.sh" --token) || die "không lấy được token của batch-worker"
dpop_keygen "$TMP/alice.pem"
dpop_keygen "$TMP/attacker.pem"
TOK_DPOP=$("$(dirname "$0")/dpop-login.sh" alice "$TMP/alice.pem" --token) || die "không lấy được token DPoP của alice"
SUB_ALICE=$(sub_of "$TOK_ALICE")

# Một đơn của chính alice (lấy từ danh sách server đã lọc) và một đơn của người khác.
OWN=$(curl -sS --cacert "$CA" --max-time 5 -H @<(b "$TOK_ALICE") https://localhost:8443/orders |
  python3 -c 'import json,sys; o=json.load(sys.stdin).get("orders") or [{}]; print(o[0].get("id",""))' 2>/dev/null)
OWN=${OWN:-ord-1001}
OTHER=ord-1002 # fixture: đơn của bob

echo "# Lượt request mẫu cho telemetry — $(date -Iseconds)"
echo "## P0 :8444 — chỉ Envoy jwt_authn"
req "alice GET /orders/whoami"                              8444 GET /orders/whoami "$(b "$TOK_ALICE")" ""
req "không token"                                           8444 GET /orders/whoami "" ""
req "alice GET đơn của bob (BOLA — P0 không có OPA, backend chặn)" 8444 GET "/orders/$OTHER" "$(b "$TOK_ALICE")" ""

echo "## P1 :8443 — JWT chặt + OPA"
req "alice GET /orders/whoami"                              8443 GET /orders/whoami "$(b "$TOK_ALICE")" ""
req "alice GET /orders (danh sách, server lọc)"             8443 GET /orders "$(b "$TOK_ALICE")" ""
req "alice GET đơn của mình"                                8443 GET "/orders/$OWN" "$(b "$TOK_ALICE")" ""
req "alice GET đơn của bob (BOLA: gateway cho qua, backend chặn)" 8443 GET "/orders/$OTHER" "$(b "$TOK_ALICE")" ""
req "alice DELETE đơn (BFLA: OPA chặn, role_not_allowed)"   8443 DELETE "/orders/$OWN" "$(b "$TOK_ALICE")" ""
req "bob POST /orders (ABAC dept)"                          8443 POST /orders "$(b "$TOK_BOB")" "" "${JSON[@]}" '{"item":"pen"}'
req "alice GET /orders/export (ABAC tier)"                  8443 GET /orders/export "$(b "$TOK_ALICE")" ""
req "dave (manager) GET hồ sơ alice — ẩn salary_band"       8443 GET "/profile/$SUB_ALICE" "$(b "$TOK_DAVE")" ""
req "carol (hr) GET hồ sơ alice"                            8443 GET "/profile/$SUB_ALICE" "$(b "$TOK_CAROL")" ""
req "alice PATCH hồ sơ mình (chỉ hr được sửa)"              8443 PATCH "/profile/$SUB_ALICE" "$(b "$TOK_ALICE")" "" "${JSON[@]}" '{"title":"CEO"}'
req "batch-worker GET /orders (client credentials)"         8443 GET /orders "$(b "$TOK_BATCH")" ""
req "không token"                                           8443 GET /orders/whoami "" ""
req "token rác"                                             8443 GET /orders/whoami "Authorization: Bearer not.a.jwt" ""
req "token gắn DPoP gửi như Bearer (hạ cấp)"                8443 GET /orders/whoami "$(b "$TOK_DPOP")" ""
req "alice GET /nope (không có route)"                      8443 GET /nope "$(b "$TOK_ALICE")" ""

echo "## P2 :8445 — P1 + DPoP"
U=https://localhost:8445/orders/whoami
PROOF=$(dpop_proof "$TMP/alice.pem" GET "$U" "$TOK_DPOP")
req "alice + proof mới"                                     8445 GET /orders/whoami "$(dpop_auth "$TOK_DPOP")" "$PROOF"
req "phát lại NGUYÊN proof đó (replay)"                     8445 GET /orders/whoami "$(dpop_auth "$TOK_DPOP")" "$PROOF"
req "token trộm + proof ký bằng khoá khác"                  8445 GET /orders/whoami "$(dpop_auth "$TOK_DPOP")" "$(dpop_proof "$TMP/attacker.pem" GET "$U" "$TOK_DPOP")"
req "token trộm, không có proof"                            8445 GET /orders/whoami "$(dpop_auth "$TOK_DPOP")" ""
req "alice + proof mới, GET đơn của bob (BOLA ở P2)"        8445 GET "/orders/$OTHER" "$(dpop_auth "$TOK_DPOP")" "$(dpop_proof "$TMP/alice.pem" GET "https://localhost:8445/orders/$OTHER" "$TOK_DPOP")"
