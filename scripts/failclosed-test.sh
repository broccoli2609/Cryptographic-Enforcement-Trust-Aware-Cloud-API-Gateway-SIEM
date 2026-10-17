#!/usr/bin/env bash
# Tuần 4 T6 — SR-11 fail closed: auth-svc sập thì Envoy (failure_mode_allow: false) phải trả 403,
# KHÔNG BAO GIỜ 200 — kể cả với token hợp lệ. Script dừng auth-svc rồi bật lại.
#   ./scripts/failclosed-test.sh | tee docs/evidence/failclosed-auth-svc-$(date +%F).txt
# Mã thoát = số mục FAIL.
set -uo pipefail
. "$(dirname "$0")/lib/common.sh"
cd "$ROOT" || exit 1

CA="$ROOT/secrets/tls/ca.crt"
FAIL=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
code() { curl -s --cacert "$CA" --max-time 5 -o /dev/null -w '%{http_code}' -H @<(bearer "$TOKEN") "https://localhost:$1/orders/whoami"; }
health() { docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q auth-svc)" 2>/dev/null; }
restore() { docker compose start auth-svc >/dev/null 2>&1; }
trap restore EXIT # dù script dừng giữa chừng, auth-svc vẫn được bật lại

TOKEN=$("$(dirname "$0")/pkce-login.sh" alice --token) || die "không lấy được token của alice"
echo "# Fail-closed khi auth-svc sập (SR-11) — $(date -Iseconds)"
echo "# Token: alice $(redact access_token "$TOKEN") — token HỢP LỆ trong suốt bài test"

echo
echo "1. Bình thường"
c=$(code 8443); [ "$c" = 200 ] && pass "P1 :8443 → $c" || fail "P1 :8443 → $c (muốn 200)"

echo
echo "2. docker compose stop auth-svc"
docker compose stop auth-svc >/dev/null 2>&1
c=$(code 8443)
if [ "$c" = 403 ]; then pass "P1 :8443 → $c — chặn khi không hỏi được auth-svc"; else fail "P1 :8443 → $c (muốn 403; 200 là lỗ hổng fail-open)"; fi
sleep 2 # Envoy đẩy access log ra stdout theo chu kỳ ~1 s
echo "   Envoy ghi lý do: $(docker compose logs envoy --no-log-prefix 2>&1 | grep '"listener_port":8443' | tail -1 | python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(d["status_code"], d["response_code_details"])' 2>/dev/null)"
c=$(code 8444)
[ "$c" = 200 ] && pass "P0 :8444 → $c — P0 không phụ thuộc auth-svc (để so sánh)" || fail "P0 :8444 → $c (muốn 200)"

echo
echo "3. docker compose start auth-svc (đợi healthy, tối đa 60 s)"
restore
for _ in $(seq 1 30); do [ "$(health)" = healthy ] && break; sleep 2; done
c=$(code 8443); [ "$c" = 200 ] && pass "P1 :8443 → $c — hoạt động lại sau khi auth-svc lên" || fail "P1 :8443 → $c (muốn 200)"

echo
echo "Kết quả: $((4 - FAIL))/4 PASS"
exit $FAIL
