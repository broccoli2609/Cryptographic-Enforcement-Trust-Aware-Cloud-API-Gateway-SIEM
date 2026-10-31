#!/usr/bin/env bash
# Tuần 5 T6 — kiểm phân quyền ở gateway (OPA) từ đầu đến cuối bằng token thật của Keycloak.
#   RBAC: route + method theo role · ABAC 1: POST /orders chỉ dept=sales · ABAC 2: GET /orders/export chỉ tier=premium
#
#   ./scripts/authz-test.sh | tee docs/evidence/authz-opa-p1-$(date +%F).txt
# Mã thoát = số ca FAIL. Cần lab đang chạy và đã chạy batch-worker-key.sh.
#
# Cách đọc kết quả: backend chưa có nghiệp vụ (tuần 7) nên route được phép trả 501 từ BACKEND.
#   "QUA"  = request tới được backend (có header x-envoy-upstream-service-time) — gateway cho phép
#   "CHẶN" = gateway trả 403 trước khi tới backend
set -uo pipefail
. "$(dirname "$0")/lib/common.sh"
cd "$ROOT" || exit 1

CA="$ROOT/secrets/tls/ca.crt"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
FAIL=0
N=0
DENIED_IDS=()

# call PORT TOKEN METHOD PATH [curl-args...] — đặt CODE, UPSTREAM (yes/no), RID (x-request-id).
call() {
  local port=$1 tok=$2 method=$3 path=$4
  shift 4
  CODE=$(curl -sS --cacert "$CA" --max-time 5 -o "$TMP/body" -D "$TMP/hdr" -w '%{http_code}' \
    -X "$method" -H @<(bearer "$tok") "$@" "https://localhost:$port$path" 2>"$TMP/err")
  grep -qi '^x-envoy-upstream-service-time:' "$TMP/hdr" && UPSTREAM=yes || UPSTREAM=no
  RID=$(grep -i '^x-request-id:' "$TMP/hdr" | cut -d' ' -f2 | tr -d '\r')
}

# expect MÔ_TẢ qua|chặn
expect() {
  N=$((N + 1))
  local got
  if [ "$UPSTREAM" = yes ]; then got="QUA (backend $CODE)"; else got="CHẶN ($CODE)"; fi
  if { [ "$2" = qua ] && [ "$UPSTREAM" = yes ]; } || { [ "$2" = chặn ] && [ "$UPSTREAM" = no ] && [ "$CODE" = 403 ]; }; then
    echo "  [PASS] $1 → $got"
  else
    echo "  [FAIL] $1 → $got (muốn $2)"
    FAIL=$((FAIL + 1))
  fi
  [ "$UPSTREAM" = no ] && DENIED_IDS+=("$RID|$1")
}

echo "# Phân quyền ở gateway (OPA, P1 :8443) — $(date -Iseconds)"
for u in alice bob carol dave; do
  printf -v "TOK_${u^^}" '%s' "$("$(dirname "$0")/pkce-login.sh" "$u" --token)" || die "không lấy được token của $u"
done
TOK_BATCH=$("$(dirname "$0")/client-credentials.sh" --token) || die "không lấy được token của batch-worker"
echo "# User (idp/README.md): alice employee/sales/standard · bob employee/engineering/premium"
echo "#   carol employee+hr/hr/standard · dave employee+manager/sales/premium · batch-worker role batch"
echo "# Policy: $(docker compose exec -T auth-svc /app -healthcheck >/dev/null 2>&1 && echo 'auth-svc healthy') — topic09.authz, xem policy/authz.rego"

echo
echo "## A. RBAC — route + method theo role"
call 8443 "$TOK_ALICE" GET /orders/whoami;       expect "A1 alice   GET    /orders/whoami (mọi role)" qua
call 8443 "$TOK_BATCH" GET /profile/whoami;      expect "A2 batch   GET    /profile/whoami (mọi role)" qua
call 8443 "$TOK_DAVE" DELETE /orders/1;          expect "A3 dave    DELETE /orders/1 (manager)" qua
call 8443 "$TOK_ALICE" DELETE /orders/1;         expect "A4 alice   DELETE /orders/1 (employee → BFLA)" chặn
call 8443 "$TOK_CAROL" DELETE /orders/1;         expect "A5 carol   DELETE /orders/1 (hr → BFLA)" chặn
call 8443 "$TOK_BATCH" GET /orders;              expect "A6 batch   GET    /orders (batch đọc danh sách)" qua
call 8443 "$TOK_BATCH" POST /orders -d '{}';     expect "A7 batch   POST   /orders (batch không tạo đơn)" chặn
call 8443 "$TOK_BATCH" GET /orders/1;            expect "A8 batch   GET    /orders/1 (batch không đọc từng đơn)" chặn
call 8443 "$TOK_CAROL" GET /profile/u-1;         expect "A9 carol   GET    /profile/u-1 (hr)" qua
call 8443 "$TOK_ALICE" GET /profile/u-1;         expect "A10 alice  GET    /profile/u-1 (employee xem hồ sơ người khác)" chặn
call 8443 "$TOK_DAVE" PATCH /profile/u-1 -d '{}'; expect "A11 dave   PATCH  /profile/u-1 (chỉ hr sửa hồ sơ)" chặn
call 8443 "$TOK_DAVE" PUT /orders/1 -d '{}';     expect "A12 dave   PUT    /orders/1 (method không có trong bảng)" chặn
call 8443 "$TOK_DAVE" GET /orders/a.b;           expect "A13 dave   GET    /orders/a.b (tham số sai mẫu)" chặn

echo
echo "## B. ABAC 1 — POST /orders chỉ cho dept = sales"
call 8443 "$TOK_ALICE" POST /orders -d '{}';     expect "B1 alice (sales)" qua
call 8443 "$TOK_DAVE" POST /orders -d '{}';      expect "B2 dave (sales, manager)" qua
call 8443 "$TOK_BOB" POST /orders -d '{}';       expect "B3 bob (engineering)" chặn
call 8443 "$TOK_CAROL" POST /orders -d '{}';     expect "B4 carol (hr)" chặn

echo
echo "## C. ABAC 2 — GET /orders/export chỉ cho tier = premium"
call 8443 "$TOK_BOB" GET /orders/export;         expect "C1 bob (premium)" qua
call 8443 "$TOK_DAVE" GET /orders/export;        expect "C2 dave (premium)" qua
call 8443 "$TOK_ALICE" GET /orders/export;       expect "C3 alice (standard)" chặn
call 8443 "$TOK_CAROL" GET /orders/export;       expect "C4 carol (standard)" chặn

echo
echo "## D. Header tự gửi không nâng được quyền (input của OPA chỉ lấy từ token đã kiểm)"
call 8443 "$TOK_ALICE" DELETE /orders/1 -H "X-User-Roles: manager" -H "X-User-Dept: hr" -H "X-User-Tier: premium"
expect "D1 alice DELETE /orders/1 + X-User-Roles: manager" chặn
call 8443 "$TOK_ALICE" GET /orders/export -H "X-User-Tier: premium"
expect "D2 alice GET /orders/export + X-User-Tier: premium" chặn

echo
echo "## E. So sánh P0 :8444 (không có OPA) — cùng request BFLA lọt tới backend"
call 8444 "$TOK_ALICE" DELETE /orders/1
N=$((N + 1))
if [ "$UPSTREAM" = yes ]; then
  echo "  [PASS] E1 alice DELETE /orders/1 trên P0 → QUA (backend $CODE): P0 chỉ xác thực, không phân quyền — đúng định nghĩa baseline"
else
  echo "  [FAIL] E1 P0 → CHẶN ($CODE): P0 không được có phân quyền, so sánh tuần 11 sẽ sai"
  FAIL=$((FAIL + 1))
fi

echo
echo "## Lý do từ chối trong log auth-svc (nối bằng x-request-id; client chỉ thấy {\"error\":\"forbidden\"})"
sleep 1
docker compose logs auth-svc --no-log-prefix 2>/dev/null | grep '"msg":"authz_decision"' >"$TMP/log"
for e in "${DENIED_IDS[@]}"; do
  rid=${e%%|*}
  line=$(grep -F "\"request_id\":\"$rid\"" "$TMP/log" | tail -1)
  printf '  %-58s %s\n' "${e#*|}" "$(printf %s "$line" | python3 -c 'import json,sys
d = json.loads(sys.stdin.read() or "{}")
print("reason=%s route=%s policy=%s@%s" % (d.get("reason"), d.get("policy_route"), d.get("policy_id"), d.get("policy_version")))')"
done

echo
echo "Kết quả: $((N - FAIL))/$N PASS"
exit $FAIL
