#!/usr/bin/env bash
# SR-11 fail closed ở HAI lớp — kể cả với token hợp lệ, KHÔNG BAO GIỜ 200 khi bộ phận kiểm hỏng:
#   Lớp 1 (tuần 4): auth-svc sập → Envoy (failure_mode_allow: false) trả 403.
#   Lớp 2 (tuần 5): OPA sập hoặc treo → auth-svc trả 503 (temporarily_unavailable).
# Script dừng/treo từng thành phần rồi bật lại.
#   ./scripts/failclosed-test.sh | tee docs/evidence/failclosed-$(date +%F).txt
# Mã thoát = số mục FAIL.
set -uo pipefail
. "$(dirname "$0")/lib/common.sh"
cd "$ROOT" || exit 1

CA="$ROOT/secrets/tls/ca.crt"
FAIL=0
N=0
pass() { N=$((N + 1)); echo "  [PASS] $*"; }
fail() { N=$((N + 1)); echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
# code PORT — đặt c (mã HTTP) và TIME (giây, để thấy ca OPA treo bị cắt sau OPA_TIMEOUT).
# Gán biến trực tiếp, không gọi trong $(...) — subshell sẽ làm mất TIME.
code() {
  local out
  out=$(curl -s --cacert "$CA" --max-time 5 -o /dev/null -w '%{http_code} %{time_total}' -H @<(bearer "$TOKEN") "https://localhost:$1/orders/whoami")
  c=${out%% *}
  TIME=${out#* }
}
health() { docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q "$1")" 2>/dev/null; }
wait_healthy() { for _ in $(seq 1 30); do [ "$(health "$1")" = healthy ] && return 0; sleep 2; done; return 1; }
last_reason() { # lý do của quyết định gần nhất trong log auth-svc
  docker compose logs auth-svc --no-log-prefix 2>/dev/null | grep '"msg":"authz_decision"' | tail -1 |
    python3 -c 'import json,sys; print(json.loads(sys.stdin.read() or "{}").get("reason", "?"))'
}
restore() {
  docker compose unpause opa >/dev/null 2>&1
  docker compose start opa auth-svc >/dev/null 2>&1
}
TMP=$(mktemp -d)
trap 'restore; rm -rf "$TMP"' EXIT # dù script dừng giữa chừng, auth-svc và OPA vẫn được bật lại

TOKEN=$("$(dirname "$0")/pkce-login.sh" alice --token) || die "không lấy được token của alice"
# P2 (tuần 6): token DPoP + proof MỚI cho mỗi lần gọi — để thấy ext_authz fail closed cả ở P2.
dpop_keygen "$TMP/k.pem"
DTOKEN=$("$(dirname "$0")/dpop-login.sh" alice "$TMP/k.pem" --token) || die "không lấy được token DPoP của alice"
code_p2() {
  local u=https://localhost:8445/orders/whoami
  c=$(curl -s --cacert "$CA" --max-time 5 -o /dev/null -w '%{http_code}' \
    -H @<(dpop_auth "$DTOKEN"; dpop_header "$(dpop_proof "$TMP/k.pem" GET "$u" "$DTOKEN")") "$u")
}
echo "# Fail-closed hai lớp (SR-11) — $(date -Iseconds)"
echo "# Token: alice $(redact access_token "$TOKEN") — token HỢP LỆ trong suốt bài test; route GET /orders/whoami (policy cho phép)"

echo
echo "## Lớp 1 — auth-svc (ext_authz của Envoy)"
echo "1. Bình thường"
code 8443; [ "$c" = 200 ] && pass "P1 :8443 → $c" || fail "P1 :8443 → $c (muốn 200)"

echo "2. docker compose stop auth-svc"
docker compose stop auth-svc >/dev/null 2>&1
code 8443
if [ "$c" = 403 ]; then pass "P1 :8443 → $c — chặn khi không hỏi được auth-svc"; else fail "P1 :8443 → $c (muốn 403; 200 là lỗ hổng fail-open)"; fi
sleep 2 # Envoy đẩy access log ra stdout theo chu kỳ ~1 s
echo "   Envoy ghi lý do: $(docker compose logs envoy --no-log-prefix 2>&1 | grep '"listener_port":8443' | tail -1 | python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(d["status_code"], d["response_code_details"])' 2>/dev/null)"
code_p2
if [ "$c" = 403 ]; then pass "P2 :8445 → $c — token DPoP + proof hợp lệ vẫn bị chặn khi auth-svc sập"; else fail "P2 :8445 → $c (muốn 403)"; fi
code 8444
[ "$c" = 200 ] && pass "P0 :8444 → $c — P0 không phụ thuộc auth-svc (để so sánh)" || fail "P0 :8444 → $c (muốn 200)"

echo "3. docker compose start auth-svc (đợi healthy, tối đa 60 s)"
docker compose start auth-svc >/dev/null 2>&1
wait_healthy auth-svc
code 8443; [ "$c" = 200 ] && pass "P1 :8443 → $c — hoạt động lại sau khi auth-svc lên" || fail "P1 :8443 → $c (muốn 200)"
code_p2; [ "$c" = 200 ] && pass "P2 :8445 → $c — hoạt động lại sau khi auth-svc lên" || fail "P2 :8445 → $c (muốn 200)"

echo
echo "## Lớp 2 — OPA (PDP), auth-svc là PEP"
echo "4. docker compose stop opa  (OPA sập: kết nối bị từ chối / không phân giải được tên)"
docker compose stop opa >/dev/null 2>&1
code 8443
if [ "$c" = 503 ] || [ "$c" = 403 ]; then pass "P1 :8443 → $c (${TIME}s) — auth-svc ghi reason=$(last_reason)"; else fail "P1 :8443 → $c (muốn 503/403; 200 là fail-open)"; fi
code 8444
[ "$c" = 200 ] && pass "P0 :8444 → $c — P0 không có OPA (để so sánh)" || fail "P0 :8444 → $c (muốn 200)"

echo "5. docker compose start opa (đợi healthy)"
docker compose start opa >/dev/null 2>&1
wait_healthy opa
code 8443; [ "$c" = 200 ] && pass "P1 :8443 → $c — hoạt động lại sau khi OPA lên" || fail "P1 :8443 → $c (muốn 200)"

echo "6. docker compose pause opa  (OPA treo: nhận kết nối nhưng không trả lời — ca timeout)"
docker compose pause opa >/dev/null 2>&1
code 8443
if [ "$c" = 503 ] || [ "$c" = 403 ]; then
  pass "P1 :8443 → $c sau ${TIME}s — auth-svc tự cắt theo OPA_TIMEOUT (250ms), reason=$(last_reason)"
else
  fail "P1 :8443 → $c (muốn 503/403; 200 là fail-open)"
fi

echo "7. docker compose unpause opa"
docker compose unpause opa >/dev/null 2>&1
sleep 1
code 8443; [ "$c" = 200 ] && pass "P1 :8443 → $c — hoạt động lại" || fail "P1 :8443 → $c (muốn 200)"

echo
echo "Kết quả: $((N - FAIL))/$N PASS"
exit $FAIL
