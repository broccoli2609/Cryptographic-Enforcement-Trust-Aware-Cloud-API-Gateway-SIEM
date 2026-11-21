#!/usr/bin/env bash
# Tuần 9 T6 — kiểm 6 hunt (detections/H*.json) trên dữ liệu THẬT do chính script sinh ra.
# Cần lab chạy đủ, đã chạy `make dpop-login` (secrets/dpop/alice.pem) và batch-worker-key.sh.
# Mã thoát = số mục FAIL. Mất ~3 phút. Realm và SIEM thật trở về như cũ (index tạm bị xoá).
#
#   0. Lưu lượng BÌNH THƯỜNG (alice gọi route được phép) → H1, H2, H3, H5 không được báo gì
#   1. Kịch bản tấn công: dpop-test (S4 → H1, H2), gateway-test (S1/S2 → H3), authz-test +
#      leo quyền qua Admin API (S6 → H4), object-authz-test (S7 → H5) → cả 5 hunt phải báo
#   2. H9 trên BẢN SAO index (topic09-events-h9test): bản sao nguyên vẹn → sạch; sửa 1 sự kiện +
#      xoá 1 sự kiện → bị phát hiện (S10). H9 trên index thật: băm lại + kiểm chữ ký sạch.
set -u
cd "$(dirname "$0")/.." || exit 1
. scripts/lib/common.sh
FAIL=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
TMP=$(mktemp -d)
OSC() { docker compose exec -T opensearch curl -s -H 'Content-Type: application/json' "$@"; }
cleanup() {
  OSC -X DELETE 'http://127.0.0.1:9200/topic09-events-h9test' >/dev/null 2>&1
  [ -n "${ALICE:-}" ] && [ -n "${MGR:-}" ] && printf '[%s]' "$MGR" | kc_api "$ADM" -o /dev/null -X DELETE -H 'Content-Type: application/json' --data-binary @- "users/$ALICE/role-mappings/realm" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
CA=secrets/tls/ca.crt
get() { curl -s --cacert "$CA" --max-time 5 -o /dev/null -w '%{http_code}' -H @<(bearer "$1") "https://localhost:8443$2"; }
# part_count FILE HUNT PART — số phát hiện của một part trong kết quả JSON của hunt.py
part_count() { python3 -c 'import json,sys; r=json.load(open(sys.argv[1]))["results"]; print(len(r.get(sys.argv[2],{}).get("parts",{}).get(sys.argv[3],[])))' "$@"; }
part_note() { python3 -c 'import json,sys; r=json.load(open(sys.argv[1]))["results"]; f=r.get(sys.argv[2],{}).get("parts",{}).get(sys.argv[3],[]); print(f[0].get("note","") if f else "")' "$@"; }
settle() { sleep 8; }   # Envoy flush 1 s + Vector gom lô 2 s + refresh của OpenSearch

echo "== 0. Lưu lượng bình thường — không hunt nào (H1, H2, H3, H5) được báo"
B0=$(now)
TA=$(./scripts/pkce-login.sh alice --token) || { echo "không lấy được token alice"; exit 1; }
for p in /orders/whoami /orders /profile/whoami /profile/me /orders; do get "$TA" "$p" >/dev/null; done
settle
python3 detections/hunt.py --since "$B0" --only H1,H2,H3,H5 --expect-none H1,H2,H3,H5 > "$TMP/base.txt" 2>&1
while IFS= read -r l; do case "$l" in *"[PASS]"*) pass "bình thường: ${l#*] }";; *"[FAIL]"*) fail "bình thường: ${l#*] } — dương tính giả";; esac; done < "$TMP/base.txt"

echo "== 1. Kịch bản tấn công"
A0=$(now)
./scripts/dpop-test.sh > "$TMP/dpop.txt" 2>&1;           echo "  S4  dpop-test (replay, token trộm + khoá lạ, hạ cấp): $(grep -c PASS "$TMP/dpop.txt") PASS"
./scripts/gateway-test.sh 8443 > "$TMP/gw.txt" 2>&1;     echo "  S1/S2 gateway-test P1 (token giả, kid lạ, header hỏng): $(grep -c PASS "$TMP/gw.txt") PASS"
./scripts/authz-test.sh > "$TMP/authz.txt" 2>&1;         echo "  S6  authz-test (route không đủ role/dept/tier): $(grep -c PASS "$TMP/authz.txt") PASS"
./scripts/object-authz-test.sh > "$TMP/obj.txt" 2>&1;    echo "  S7  object-authz-test (BOLA, BFLA, mass assignment): $(grep -c PASS "$TMP/obj.txt") PASS"

# S6 — leo quyền qua Admin API: alice (employee) gọi /profile/{id} bị chặn → admin gán manager →
# token mới của alice được PDP cho qua → gỡ role (cleanup cũng gỡ nếu script dừng giữa chừng).
ADM=$(kc_admin_token) || { echo "không lấy được token admin"; exit 1; }
ALICE=$(kc_api "$ADM" "users?username=alice&exact=true" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
has() { kc_api "$ADM" "users/$ALICE/role-mappings/realm" | python3 -c 'import json,sys; print(any(r["name"]=="manager" for r in json.load(sys.stdin)))'; }
if [ "$(has)" = True ]; then ALICE=""; fail "alice đã có role manager trực tiếp — bỏ qua kịch bản leo quyền"; else
  MGR=$(kc_api "$ADM" "roles/manager")
  c1=$(get "$TA" /profile/00000000-0000-4000-8000-000000000000)
  printf '[%s]' "$MGR" | kc_api "$ADM" -o /dev/null -H 'Content-Type: application/json' --data-binary @- "users/$ALICE/role-mappings/realm"
  TA2=$(./scripts/pkce-login.sh alice --token)
  c2=$(get "$TA2" /profile/00000000-0000-4000-8000-000000000000)
  printf '[%s]' "$MGR" | kc_api "$ADM" -o /dev/null -X DELETE -H 'Content-Type: application/json' --data-binary @- "users/$ALICE/role-mappings/realm"
  [ "$(has)" = False ] && echo "  S6  leo quyền: alice /profile/{id} trước = $c1, sau khi được gán manager = $c2; đã gỡ role" || fail "không gỡ được role manager của alice — kiểm tay!"
  [ "$c1" = 403 ] && [ "$c2" != 403 ] && pass "leo quyền có hiệu lực thật ở gateway (403 → $c2)" || fail "leo quyền không như dự kiến ($c1 → $c2)"
fi
settle
docker compose kill -s USR1 digester >/dev/null 2>&1; sleep 6   # ký digest để H9 có phần đã ký mới

python3 detections/hunt.py --since "$A0" --expect H1,H2,H3,H4,H5 --json "$TMP/hunt.json" > "$TMP/hunt.txt" 2>&1
cp "$TMP/hunt.txt" "$TMP/hunt-attack.txt"
while IFS= read -r l; do case "$l" in *"[PASS]"*) pass "tấn công: ${l#*] }";; *"[FAIL]"*) fail "tấn công: ${l#*] } — hunt bỏ sót";; esac; done < "$TMP/hunt.txt"
for spec in "H1|gửi lại proof đã dùng (P2)" "H2|proof ký bằng khoá khác khoá gắn token" "H2|hạ cấp: token DPoP gửi kiểu Bearer / token thường gửi vào P2" \
            "H3|Envoy chặn: chữ ký sai / kid lạ / header hỏng" "H4|dò quyền: ≥ 3 lần PDP từ chối cùng principal" \
            "H4|role của cùng principal thay đổi trong cửa sổ" "H4|gán/gỡ role qua Admin API (và user đó có hoạt động sau đó)" \
            "H5|BOLA: ≥ 3 lần backend từ chối đối tượng cùng principal" "H5|BFLA: gọi chức năng không đủ role"; do
  h=${spec%%|*}; p=${spec#*|}
  n=$(part_count "$TMP/hunt.json" "$h" "$p")
  [ "${n:-0}" -ge 1 ] && pass "$h / $p: $n phát hiện" || fail "$h / $p: không phát hiện"
done
used=$(python3 -c 'import json,sys; f=json.load(open(sys.argv[1]))["results"]["H4"]["parts"]["gán/gỡ role qua Admin API (và user đó có hoạt động sau đó)"]; print(max((int(x["note"].split(" có ")[1].split()[0]) for x in f if x["group"]["idp_event"]=="ADMIN_CREATE"), default=0))' "$TMP/hunt.json" 2>/dev/null)
[ "${used:-0}" -ge 1 ] && pass "H4 nối được: user vừa được gán role có $used sự kiện SAU thao tác (admin_target_hash = principal_hash)" || fail "H4 không nối được admin event với hoạt động sau đó"

echo "== 2. H9 — sửa/xoá log trên BẢN SAO index"
EPOCH=$(python3 telemetry/siem_export.py --index topic09-digests --sort digest_seq 2>/dev/null | tail -1 | python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(d["chain_epoch"], d["last_seq"])')
E=${EPOCH% *}; L=${EPOCH#* }
OSC -X DELETE 'http://127.0.0.1:9200/topic09-events-h9test' >/dev/null
OSC -X POST 'http://127.0.0.1:9200/_reindex?refresh=true' -d "{\"source\":{\"index\":\"topic09-events\",\"query\":{\"bool\":{\"filter\":[{\"term\":{\"chain_epoch\":\"$E\"}},{\"range\":{\"chain_seq\":{\"lte\":$L}}}]}}},\"dest\":{\"index\":\"topic09-events-h9test\"}}" > "$TMP/reindex.json"
n=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("created",0))' "$TMP/reindex.json")
echo "  bản sao: epoch $E, seq 1..$L → $n sự kiện"
SINCE_ALL=$(date -u -d '-1 day' +%Y-%m-%dT%H:%M:%SZ)
python3 detections/hunt.py --index topic09-events-h9test --since "$SINCE_ALL" --only H9 --json "$TMP/h9a.json" > /dev/null 2>&1
[ "$(part_count "$TMP/h9a.json" H9 'băm lại + kiểm chữ ký digest (phần đã ký)')" = 0 ] && [ "$(part_count "$TMP/h9a.json" H9 'thiếu chain_seq trong epoch')" = 0 ] \
  && pass "H9: bản sao nguyên vẹn → băm lại + chữ ký + seq đều sạch (không báo nhầm)" || fail "H9 báo lỗi trên bản sao nguyên vẹn: $(part_note "$TMP/h9a.json" H9 'băm lại + kiểm chữ ký digest (phần đã ký)')"
# Chọn 2 sự kiện của Envoy trong phần đã ký: sửa decision của cái thứ nhất, xoá cái thứ hai.
read -r K1 K2 < <(OSC 'http://127.0.0.1:9200/topic09-events-h9test/_search' -d '{"size":2,"_source":["chain_seq"],"query":{"term":{"source":"envoy"}},"sort":[{"chain_seq":"asc"}]}' |
  python3 -c 'import json,sys; print(" ".join(str(h["_source"]["chain_seq"]) for h in json.load(sys.stdin)["hits"]["hits"]))')
OSC -X POST 'http://127.0.0.1:9200/topic09-events-h9test/_update_by_query?refresh=true' \
  -d "{\"query\":{\"term\":{\"chain_seq\":$K1}},\"script\":{\"lang\":\"painless\",\"source\":\"ctx._source.decision = ctx._source.decision == 'allow' ? 'deny' : 'allow'\"}}" >/dev/null
OSC -X POST 'http://127.0.0.1:9200/topic09-events-h9test/_delete_by_query?refresh=true' -d "{\"query\":{\"term\":{\"chain_seq\":$K2}}}" >/dev/null
echo "  đã sửa decision của seq $K1 (T1565.001) và xoá seq $K2 (T1070) trong bản sao"
python3 detections/hunt.py --index topic09-events-h9test --since "$SINCE_ALL" --only H9 --json "$TMP/h9b.json" > "$TMP/h9b.txt" 2>&1
cv=$(python3 -c 'import json,sys; print("\n".join(x["note"] for x in json.load(open(sys.argv[1]))["results"]["H9"]["parts"]["băm lại + kiểm chữ ký digest (phần đã ký)"]))' "$TMP/h9b.json")
echo "$cv" | grep -q "seq $K1 .*KHÔNG khớp nội dung" && pass "H9 phát hiện sự kiện bị sửa (seq $K1: event_hash không khớp)" || fail "H9 không phát hiện sự kiện bị sửa"
echo "$cv" | grep -q "thiếu sự kiện seq $K2" && pass "H9 phát hiện sự kiện bị xoá (seq $K2 thiếu trong phần digest đã phủ)" || fail "H9 không phát hiện sự kiện bị xoá"
[ "$(part_count "$TMP/h9b.json" H9 'thiếu chain_seq trong epoch')" -ge 1 ] && pass "H9 (truy vấn nhanh, không cần băm lại): epoch có khoảng trống seq" || fail "H9 seq_gaps không thấy khoảng trống"
cp "$TMP/h9b.txt" "$TMP/hunt-h9.txt"

echo "== 3. H9 trên index THẬT"
python3 detections/hunt.py --since "$SINCE_ALL" --only H9 --json "$TMP/h9c.json" > "$TMP/h9c.txt" 2>&1
[ "$(part_count "$TMP/h9c.json" H9 'băm lại + kiểm chữ ký digest (phần đã ký)')" = 0 ] && pass "SIEM thật: mọi sự kiện đã ký băm lại khớp, chữ ký digest hợp lệ" || fail "SIEM thật có lỗi chuỗi: $(part_note "$TMP/h9c.json" H9 'băm lại + kiểm chữ ký digest (phần đã ký)')"
[ "$(part_count "$TMP/h9c.json" H9 'thiếu chain_seq trong epoch')" = 0 ] && pass "SIEM thật: không epoch nào thiếu seq" || fail "SIEM thật thiếu seq"
[ "$(part_count "$TMP/h9c.json" H9 'digest cũ hoặc mất digest')" = 0 ] && pass "SIEM thật: digest mới (< 10 phút), digest_seq liền mạch" || fail "digest cũ hoặc mất: $(part_note "$TMP/h9c.json" H9 'digest cũ hoặc mất digest')"

echo
echo "---- Chi tiết hunt trên kịch bản tấn công (cửa sổ từ $A0) ----"
cat "$TMP/hunt-attack.txt"
echo
echo "---- Chi tiết H9 trên bản sao đã bị sửa/xoá ----"
grep -A12 "^H9" "$TMP/hunt-h9.txt"
echo
echo "Kết quả: $FAIL FAIL"
exit "$FAIL"
