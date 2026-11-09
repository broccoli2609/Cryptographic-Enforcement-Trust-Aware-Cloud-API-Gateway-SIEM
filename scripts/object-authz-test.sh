#!/usr/bin/env bash
# Tuần 7 T6 — kiểm quyền mức ĐỐI TƯỢNG và THUỘC TÍNH ở backend, đầu-cuối bằng token thật
# (T4 Broken authorization, SR-06, kịch bản S7 BOLA/BFLA; OWASP API1, API3, API5).
#
#   A. BOLA (API1) orders-api — gateway CHO QUA, backend CHẶN
#   B. manager chỉ thao tác đơn cùng phòng ban (quan hệ người gọi ↔ đối tượng)
#   C. property-level (API3) profile-api — salary_band chỉ hr; mass assignment; tách nhiệm vụ
#   D. BFLA (API5) — gateway chặn, request không tới backend
#   E. P0 :8444 (gateway chỉ xác thực) — backend là lớp phân quyền duy nhất, vẫn chặn;
#      header X-User-Roles giả bị Envoy xoá
#   F. Log 2 tầng: mỗi ca nối log gateway (auth-svc / Envoy) với log backend bằng x-request-id
#
#   ./scripts/object-authz-test.sh | tee docs/evidence/object-authz-$(date +%F).txt
# Mã thoát = số ca FAIL. Cần lab đang chạy và đã chạy batch-worker-key.sh.
# Script restart orders-api + profile-api lúc đầu để nạp lại fixture (dữ liệu chỉ ở bộ nhớ).
set -uo pipefail
. "$(dirname "$0")/lib/common.sh"
cd "$ROOT" || exit 1

CA="$ROOT/secrets/tls/ca.crt"
FIXTURE="$ROOT/workloads/fixtures/orders.json"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
FAIL=0
N=0
: >"$TMP/cases.tsv"

# call PORT TOKEN METHOD PATH [curl-args...] — đặt CODE, UP (yes = tới backend), RID, PORT.
# Token đi qua header đọc từ pipe, không nằm trên dòng lệnh.
call() {
  local tok=$2 method=$3 path=$4
  PORT=$1
  shift 4
  CODE=$(curl -sS --cacert "$CA" --max-time 5 -o "$TMP/body" -D "$TMP/hdr" -w '%{http_code}' \
    -X "$method" -H @<(bearer "$tok") "$@" "https://localhost:$PORT$path" 2>"$TMP/err")
  touch "$TMP/body" "$TMP/hdr"
  grep -qi '^x-envoy-upstream-service-time:' "$TMP/hdr" && UP=yes || UP=no
  RID=$(grep -i '^x-request-id:' "$TMP/hdr" | cut -d' ' -f2 | tr -d '\r')
}
JSON=(-H 'Content-Type: application/json' --data-binary)

# body_ok BIỂU_THỨC — biểu thức Python trên b = JSON body (biểu thức viết sẵn trong script này).
body_ok() {
  python3 -c 'import json, os, sys
b = json.load(open(sys.argv[1]))
sys.exit(0 if eval(sys.argv[2], {"b": b, "env": os.environ}) else 1)' "$TMP/body" "$1" 2>/dev/null
}

# expect MÔ_TẢ LỚP MÃ [QUYẾT_ĐỊNH_BACKEND] [BIỂU_THỨC_BODY]
#   LỚP = backend (phải tới backend) | gateway (gateway chặn, không tới backend)
#   QUYẾT_ĐỊNH_BACKEND = "deny/not_owner"… — chấm ở phần F bằng log backend.
expect() {
  local desc=$1 layer=$2 want=$3 decision=${4:-} check=${5:-} where=gateway ok=yes note=""
  [ "$UP" = yes ] && where=backend
  { [ "$where" = "$layer" ] && [ "$CODE" = "$want" ]; } || ok=no
  if [ "$ok" = yes ] && [ -n "$check" ] && ! body_ok "$check"; then ok=no; note=" — body sai"; fi
  N=$((N + 1))
  if [ "$ok" = yes ]; then echo "  [PASS] $desc → $CODE ($where)"; else
    echo "  [FAIL] $desc → $CODE ($where)$note, muốn $want ($layer)"
    FAIL=$((FAIL + 1))
  fi
  [ -n "$RID" ] && printf '%s\t%s\t%s\t%s\t%s\n' "$RID" "$PORT" "$layer" "$decision" "$desc" >>"$TMP/cases.tsv"
}

sub_of() { TOKEN=$1 python3 -c 'import base64, json, os
p = os.environ["TOKEN"].split(".")[1]
print(json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))["sub"])'; }
orders_of() { python3 -c 'import json, sys
print(" ".join(o["id"] for o in json.load(open(sys.argv[1])) if o["owner_id"] == sys.argv[2]))' "$FIXTURE" "$1"; }

echo "# Phân quyền mức đối tượng/thuộc tính ở backend (tuần 7) — $(date -Iseconds)"
echo "# Nạp lại fixture: restart orders-api + profile-api (dữ liệu chỉ nằm trong bộ nhớ)"
docker compose restart orders-api profile-api >/dev/null 2>&1 &&
  docker compose up -d --wait orders-api profile-api >/dev/null 2>&1 || die "không restart được backend"

for u in alice bob carol dave; do
  printf -v "TOK_${u^^}" '%s' "$("$(dirname "$0")/pkce-login.sh" "$u" --token)" || die "không lấy được token của $u"
done
TOK_BATCH=$("$(dirname "$0")/client-credentials.sh" --token) || die "không lấy được token của batch-worker"

# Chờ Envoy thấy lại backend (DNS của cluster làm mới mỗi 5 s).
for _ in $(seq 1 15); do
  call 8443 "$TOK_ALICE" GET /orders/whoami
  [ "$CODE" = 200 ] && break
  sleep 1
done
[ "$CODE" = 200 ] || die "gateway chưa tới được orders-api ($CODE)"

SUB_ALICE=$(sub_of "$TOK_ALICE")
SUB_BOB=$(sub_of "$TOK_BOB")
SUB_CAROL=$(sub_of "$TOK_CAROL")
SUB_DAVE=$(sub_of "$TOK_DAVE")
read -ra A <<<"$(orders_of "$SUB_ALICE")"
read -ra B <<<"$(orders_of "$SUB_BOB")"
read -ra D <<<"$(orders_of "$SUB_DAVE")"
[ "${#A[@]}" = 5 ] && [ "${#B[@]}" = 5 ] && [ "${#D[@]}" = 5 ] ||
  die "fixture không khớp sub trong token (realm đã ghim id user chưa? xem idp/realm-topic09.json)"
export ALICE_IDS="${A[*]}" SUB_ALICE
echo "# Fixture (workloads/fixtures/orders.json): 3 chủ × 5 đơn, ID xen kẽ"
echo "#   alice (sales):       ${A[*]}"
echo "#   bob   (engineering): ${B[*]}"
echo "#   dave  (sales, manager): ${D[*]}"
echo "# User không có đơn: carol (hr). Hồ sơ: workloads/fixtures/profiles.json (4 người, có salary_band)"

echo
echo "## A. BOLA (OWASP API1) — gateway cho qua (employee được GET /orders/{id}), backend kiểm owner_id"
call 8443 "$TOK_ALICE" GET "/orders/${A[0]}"
expect "A1 alice GET đơn của mình ${A[0]}" backend 200 allow/owner 'b["id"] == "'"${A[0]}"'"'
call 8443 "$TOK_ALICE" GET "/orders/${B[0]}"
expect "A2 alice GET ${B[0]} (đơn của bob — ID mình +1)" backend 404 deny/not_owner '"item" not in b'
cp "$TMP/body" "$TMP/bola_body"
call 8443 "$TOK_ALICE" GET "/orders/${D[0]}"
expect "A3 alice GET ${D[0]} (đơn của dave, CÙNG phòng sales)" backend 404 deny/not_owner
call 8443 "$TOK_BOB" GET "/orders/${A[0]}"
expect "A4 bob   GET ${A[0]} (đơn của alice)" backend 404 deny/not_owner
call 8443 "$TOK_ALICE" GET /orders/ord-9999
expect "A5 alice GET ord-9999 (không tồn tại)" backend 404 deny/not_found
N=$((N + 1))
if cmp -s "$TMP/body" "$TMP/bola_body"; then
  echo "  [PASS] A6 body của A2 (đơn người khác) giống hệt A5 (không tồn tại): $(cat "$TMP/body") — không dò được đơn nào có thật"
else
  echo "  [FAIL] A6 body A2 khác A5 — kẻ tấn công phân biệt được"
  FAIL=$((FAIL + 1))
fi
call 8443 "$TOK_ALICE" GET /orders
expect "A7 alice GET /orders (danh sách lọc ở server)" backend 200 allow/filtered \
  'sorted(o["id"] for o in b["orders"]) == sorted(env["ALICE_IDS"].split())'
call 8443 "$TOK_CAROL" GET "/orders/${A[0]}"
expect "A8 carol (hr) GET ${A[0]} (hr không có quyền gì với đơn hàng)" backend 404 deny/not_owner
call 8443 "$TOK_ALICE" POST /orders "${JSON[@]}" '{"item":"Pen","quantity":1,"owner_id":"'"$SUB_BOB"'"}'
expect "A9 alice POST /orders kèm owner_id của bob (mass assignment)" backend 400 deny/unknown_field
call 8443 "$TOK_ALICE" POST /orders "${JSON[@]}" '{"item":"Week 7 demo order","quantity":2}'
expect "A10 alice POST /orders hợp lệ → owner_id do server đặt = sub của alice" backend 201 allow/owner_is_caller \
  'b["owner_id"] == env["SUB_ALICE"] and b["dept"] == "sales"'

echo
echo "## B. manager — chỉ đơn CÙNG phòng ban (gateway không biết đơn thuộc phòng nào)"
call 8443 "$TOK_DAVE" GET "/orders/${A[0]}"
expect "B1 dave (manager sales) GET ${A[0]} (đơn sales của alice)" backend 200 allow/dept_manager
call 8443 "$TOK_DAVE" GET "/orders/${B[0]}"
expect "B2 dave GET ${B[0]} (đơn engineering)" backend 404 deny/not_owner
call 8443 "$TOK_DAVE" DELETE "/orders/${B[4]}"
expect "B3 dave DELETE ${B[4]} (OPA: manager được DELETE; đơn engineering)" backend 404 deny/not_owner
call 8443 "$TOK_DAVE" DELETE "/orders/${A[4]}"
expect "B4 dave DELETE ${A[4]} (đơn sales)" backend 204 allow/dept_manager
call 8443 "$TOK_ALICE" GET "/orders/${A[4]}"
expect "B5 alice GET ${A[4]} sau khi bị xoá" backend 404 deny/not_found
call 8443 "$TOK_BATCH" GET /orders
expect "B6 batch-worker GET /orders (job đối soát đọc tất cả: 15 + 1 tạo − 1 xoá)" backend 200 allow/batch_all 'b["count"] == 15'

echo
echo "## C. Property-level (OWASP API3) — profile-api"
call 8443 "$TOK_CAROL" GET "/profile/$SUB_ALICE"
expect "C1 carol (hr) GET hồ sơ alice → có salary_band" backend 200 allow/hr '"salary_band" in b'
call 8443 "$TOK_DAVE" GET "/profile/$SUB_ALICE"
expect "C2 dave (manager sales) GET hồ sơ alice → KHÔNG có salary_band" backend 200 allow/dept_manager \
  '"salary_band" not in b and b["title"] != ""'
call 8443 "$TOK_DAVE" GET "/profile/$SUB_BOB"
expect "C3 dave GET hồ sơ bob (engineering)" backend 404 deny/not_allowed
call 8443 "$TOK_ALICE" GET /profile/me
expect "C4 alice GET /profile/me → hồ sơ mình, không có salary_band" backend 200 allow/self \
  'b["user_id"] == env["SUB_ALICE"] and "salary_band" not in b'
call 8443 "$TOK_CAROL" PATCH "/profile/$SUB_ALICE" "${JSON[@]}" '{"dept":"hr"}'
expect "C5 carol PATCH hồ sơ alice {dept} (mass assignment)" backend 400 deny/unknown_field
call 8443 "$TOK_CAROL" PATCH "/profile/$SUB_CAROL" "${JSON[@]}" '{"salary_band":"B5"}'
expect "C6 carol PATCH salary_band của CHÍNH MÌNH (tách nhiệm vụ)" backend 403 deny/self_salary_change
call 8443 "$TOK_CAROL" PATCH "/profile/$SUB_ALICE" "${JSON[@]}" '{"salary_band":"B3"}'
expect "C7 carol PATCH salary_band của alice" backend 200 allow/hr_update 'b["salary_band"] == "B3"'

echo
echo "## D. BFLA (OWASP API5) — gateway chặn theo route + method, request không tới backend"
call 8443 "$TOK_ALICE" DELETE "/orders/${A[0]}"
expect "D1 alice (employee) DELETE ${A[0]} — đơn của chính mình" gateway 403
call 8443 "$TOK_DAVE" PATCH "/profile/$SUB_ALICE" "${JSON[@]}" '{"title":"x"}'
expect "D2 dave (manager) PATCH hồ sơ (chỉ hr)" gateway 403
call 8443 "$TOK_ALICE" GET "/profile/$SUB_BOB"
expect "D3 alice (employee) GET /profile/{id} (chỉ hr, manager)" gateway 403

echo
echo "## E. P0 :8444 — gateway chỉ xác thực, không gửi role/dept: backend là lớp phân quyền duy nhất"
call 8444 "$TOK_ALICE" GET "/orders/${B[0]}"
expect "E1 alice GET ${B[0]} (BOLA) — không có OPA vẫn bị chặn" backend 404 deny/not_owner
call 8444 "$TOK_ALICE" DELETE "/orders/${A[0]}"
expect "E2 alice DELETE ${A[0]} (BFLA lọt gateway P0) — backend: không phải manager" backend 403 deny/not_dept_manager
call 8444 "$TOK_ALICE" PATCH "/profile/$SUB_ALICE" "${JSON[@]}" '{"salary_band":"B5"}'
expect "E3 alice tự nâng salary_band qua P0" backend 403 deny/forbidden_property
call 8444 "$TOK_CAROL" GET "/profile/$SUB_ALICE"
expect "E4 carol GET hồ sơ alice qua P0 (thiếu role → ít quyền nhất)" backend 404 deny/not_allowed
call 8444 "$TOK_ALICE" PATCH "/profile/$SUB_ALICE" -H "X-User-Roles: hr" -H "X-User-Dept: hr" "${JSON[@]}" '{"salary_band":"B5"}'
expect "E5 như E3 + tự gửi X-User-Roles: hr (Envoy xoá trước khi tới backend)" backend 403 deny/forbidden_property

echo
echo "## F. Log 2 tầng — nối bằng x-request-id (không in principal/sub, không in token)"
sleep 2 # Envoy đẩy access log mỗi 1 s
docker compose logs --no-log-prefix auth-svc >"$TMP/authsvc.log" 2>/dev/null
docker compose logs --no-log-prefix orders-api profile-api >"$TMP/backend.log" 2>/dev/null
docker compose logs --no-log-prefix envoy >"$TMP/envoy.log" 2>/dev/null
python3 - "$TMP" >"$TMP/f.out" <<'PY'
import json, sys
tmp = sys.argv[1]

def load(name):
    d = {}
    for line in open(f"{tmp}/{name}", encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except ValueError:
            continue
        if j.get("request_id"):
            d.setdefault(j["request_id"], []).append(j)
    return d

auth, back, envoy = load("authsvc.log"), load("backend.log"), load("envoy.log")
n = fail = 0
for row in open(f"{tmp}/cases.tsv", encoding="utf-8"):
    rid, port, layer, want, desc = row.rstrip("\n").split("\t")
    n += 1
    a = [x for x in auth.get(rid, []) if x.get("msg") == "authz_decision"]
    b = [x for x in back.get(rid, []) if x.get("msg") == "request"]
    if port == "8444":
        e = envoy.get(rid, [])
        gw_ok = bool(e) and not a
        gw_ok = gw_ok and bool(e[-1].get("upstream_cluster"))
        gw = (f"Envoy P0 — jwt_authn: token hợp lệ → chuyển thẳng {e[-1].get('upstream_cluster')} "
              "(không có ext_authz/OPA)") if e else "(không thấy log Envoy)"
    elif a:
        x = a[-1]
        gw_ok = (x["decision"] == "allow") == (layer == "backend")
        gw = f"auth-svc {x['decision']} reason={x['reason']} route={x.get('policy_route') or '-'} policy={x.get('policy_id')}@{x.get('policy_version')}"
    else:
        gw_ok, gw = False, "(không thấy log auth-svc)"
    if layer == "backend":
        if b:
            y = b[-1]
            got = f"{y.get('backend_object_authz')}/{y.get('backend_authz_reason')}"
            red = f" redacted={y['backend_redacted_fields']}" if y.get("backend_redacted_fields") else ""
            be_ok = got == want
            be = f"backend_object_authz={y.get('backend_object_authz')} reason={y.get('backend_authz_reason')}{red} [{y.get('service')} {y.get('route_template')} → {y.get('status_code')}]"
            if not be_ok:
                be += f"  ← muốn {want}"
        else:
            be_ok, be = False, "(không thấy log backend)"
    else:
        be_ok = not b
        be = "không có dòng log nào — request không tới backend" if be_ok else "CÓ log backend: request đã lọt!"
    ok = gw_ok and be_ok
    fail += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {desc}")
    print(f"           gateway: {gw}")
    print(f"           backend: {be}")
print(f"__COUNT__ {n} {fail}")
PY
grep -v '^__COUNT__' "$TMP/f.out"
read -r _ fn ff < <(grep '^__COUNT__' "$TMP/f.out")
N=$((N + ${fn:-0}))
FAIL=$((FAIL + ${ff:-1}))

echo
echo "Kết quả: $((N - FAIL))/$N PASS"
exit $FAIL
