#!/usr/bin/env bash
# Tuần 9 T6 — sự kiện quản trị Keycloak vào SIEM (SR-12, T11, RP7, F6; dùng cho hunt H4).
# Gán role realm "manager" cho alice qua Admin REST, rồi gỡ ngay; khẳng định trong OpenSearch có
# 2 sự kiện idp_admin_event (ADMIN_CREATE, ADMIN_DELETE) đúng loại/đường dẫn, đích băm bằng đúng
# HMAC của sub alice (cùng công thức principal_hash), không có UUID/IP thô. Mã thoát = số FAIL.
# Trạng thái cuối giống ban đầu. Dùng alice vì theo idp/realm-topic09.json alice CHỈ có employee
# (dave vốn có manager — gán rồi gỡ trên dave sẽ xoá mất role gốc; lỗi này đã xảy ra 21/11).
set -u
cd "$(dirname "$0")/.." || exit 1
. scripts/lib/common.sh
FAIL=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

ADM=$(kc_admin_token) || die "không lấy được token admin — Keycloak đã chạy chưa?"
TGT=$(kc_api "$ADM" "users?username=alice&exact=true" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
ROLE=$(kc_api "$ADM" "roles/manager")
has_manager() { kc_api "$ADM" "users/$TGT/role-mappings/realm" | python3 -c 'import json,sys; print(any(r["name"]=="manager" for r in json.load(sys.stdin)))'; }
[ "$(has_manager)" = False ] || die "alice đang có role manager — khác idp/realm-topic09.json, dừng để không đổi trạng thái realm"
# Gỡ lại cả khi script dừng giữa chừng (Ctrl-C, lỗi mạng) — realm không bị kẹt ở trạng thái thử.
trap 'printf "[%s]" "$ROLE" | kc_api "$ADM" -o /dev/null -X DELETE -H "Content-Type: application/json" --data-binary @- "users/$TGT/role-mappings/realm" 2>/dev/null; rm -rf "$TMP"' EXIT

FROM=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "== Gán rồi gỡ role manager cho alice (Admin REST, tài khoản admin của realm master)"
printf '[%s]' "$ROLE" | kc_api "$ADM" -o /dev/null -H 'Content-Type: application/json' --data-binary @- "users/$TGT/role-mappings/realm"
[ "$(has_manager)" = True ] && pass "đã gán manager cho alice" || fail "gán role không thành công"
printf '[%s]' "$ROLE" | kc_api "$ADM" -o /dev/null -X DELETE -H 'Content-Type: application/json' --data-binary @- "users/$TGT/role-mappings/realm"
[ "$(has_manager)" = False ] && pass "đã gỡ lại — realm về trạng thái ban đầu" || fail "gỡ role không thành công — kiểm tay!"

echo "== SIEM"
q="{\"size\":10,\"sort\":[{\"event_time\":\"asc\"}],\"query\":{\"bool\":{\"filter\":[{\"term\":{\"event_type\":\"idp_admin_event\"}},{\"term\":{\"admin_resource_type\":\"REALM_ROLE_MAPPING\"}},{\"range\":{\"event_time\":{\"gte\":\"$FROM\"}}}]}}}"
for _ in $(seq 1 15); do
  sleep 2
  docker compose exec -T opensearch curl -s -H 'Content-Type: application/json' 'http://127.0.0.1:9200/topic09-events/_search' -d "$q" > "$TMP/hits.json"
  [ "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["hits"]["hits"]))' "$TMP/hits.json")" -ge 2 ] && break
done
KEY=$(env_get SIEM_HMAC_KEY)
python3 - "$TMP/hits.json" "$TGT" <<PY > "$TMP/check.txt"
import hashlib, hmac, json, sys
hits = [h["_source"] for h in json.load(open(sys.argv[1]))["hits"]["hits"]]
dave = sys.argv[2]
want = hmac.new(b"""$KEY""", ("principal:" + dave).encode(), hashlib.sha256).hexdigest()
ops = [h.get("idp_event") for h in hits]
print("ops", ",".join(ops))
print("path", ",".join(sorted({h.get("admin_resource_path", "") for h in hits})))
print("target", "ok" if hits and all(h.get("admin_target_hash") == want for h in hits) else "sai")
raw = json.dumps(hits)
print("raw", "lộ" if dave in raw or "172." in raw or "admin_target\"" in raw else "sạch")
print("chain", "ok" if hits and all("chain_seq" in h and "event_hash" in h for h in hits) else "thiếu")
print("actor", "ok" if hits and all(len(h.get("principal_hash", "")) == 64 for h in hits) else "thiếu")
PY
get() { awk -v k="$1" '$1==k {print $2}' "$TMP/check.txt"; }
[ "$(get ops)" = "ADMIN_CREATE,ADMIN_DELETE" ] && pass "SIEM có 2 sự kiện quản trị đúng thứ tự: $(get ops)" || fail "sự kiện quản trị trong SIEM: '$(get ops)' (muốn ADMIN_CREATE,ADMIN_DELETE)"
[ "$(get path)" = "users/{id}/role-mappings/realm" ] && pass "đường dẫn đã ẩn UUID: users/{id}/role-mappings/realm" || fail "admin_resource_path = '$(get path)'"
[ "$(get target)" = ok ] && pass "admin_target_hash = HMAC-SHA256(khoá, \"principal:\" ‖ sub của alice) — nối được với principal_hash (H4)" || fail "admin_target_hash không khớp HMAC của alice"
[ "$(get actor)" = ok ] && pass "người thao tác (admin) có principal_hash" || fail "thiếu principal_hash của admin"
[ "$(get raw)" = sạch ] && pass "không UUID / IP / khoá thô admin_target trong SIEM" || fail "sự kiện quản trị lộ giá trị thô"
[ "$(get chain)" = ok ] && pass "sự kiện quản trị nằm trong hash chain (chain_seq + event_hash)" || fail "sự kiện quản trị thiếu trường chuỗi"

echo
echo "Kết quả: $FAIL FAIL"
exit "$FAIL"
