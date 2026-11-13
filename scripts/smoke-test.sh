#!/usr/bin/env bash
# Kiểm nhanh lab sau "docker compose up -d --build".
# Chạy:  ./scripts/smoke-test.sh      (mã thoát = số mục FAIL; tuần 8: 26 mục PASS là đạt)
set -u
cd "$(dirname "$0")/.." || exit 1
FAIL=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

health() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$(docker compose ps -q "$1")" 2>/dev/null; }

echo "Đợi Keycloak sẵn sàng (tối đa 3 phút)..."
for _ in $(seq 1 36); do
  [ "$(health keycloak)" = healthy ] && break
  sleep 5
done

for svc in keycloak opa auth-svc orders-api profile-api opensearch vector; do
  s=$(health "$svc")
  if [ "$s" = healthy ]; then pass "$svc: healthy"; else fail "$svc: $s"; fi
done
# Image Envoy distroless không có công cụ cho healthcheck → kiểm trạng thái chạy + gọi qua TLS bên dưới.
s=$(docker inspect -f '{{.State.Status}}' "$(docker compose ps -q envoy)" 2>/dev/null)
if [ "$s" = running ]; then pass "envoy: running"; else fail "envoy: ${s:-không có}"; fi

if curl -fsS http://localhost:8080/realms/topic09/.well-known/openid-configuration | grep -q '"issuer":"http://localhost:8080/realms/topic09"'; then
  pass "Keycloak trả discovery document của realm topic09 (đã import idp/realm-topic09.json)"
else
  fail "Không lấy được discovery document của realm topic09"
fi

if docker compose port keycloak 8080 | grep -q '^127\.0\.0\.1:'; then
  pass "Port Keycloak chỉ mở trên 127.0.0.1"
else
  fail "Port Keycloak đang mở ra ngoài localhost"
fi

for pair in orders-api:8081 profile-api:8082; do
  name=${pair%%:*}; port=${pair##*:}
  if docker run --rm --network topic09-backend busybox:1.37 wget -qO- "http://$name:$port/healthz" | grep -q '"status":"ok"'; then
    pass "$name trả 200 khi gọi từ bên trong mạng backend"
  else
    fail "$name không trả lời trong mạng backend"
  fi
  if curl -fsS --max-time 2 "http://localhost:$port/healthz" >/dev/null 2>&1; then
    fail "$name gọi thẳng được từ host — backend đang bị lộ (T5)"
  else
    pass "$name KHÔNG gọi thẳng được từ host"
  fi
done

# --- Gateway (tuần 4) ---
if [ "$(docker compose port envoy 8443) $(docker compose port envoy 8444) $(docker compose port envoy 8445)" = "127.0.0.1:8443 127.0.0.1:8444 127.0.0.1:8445" ]; then
  pass "Port Envoy (8443 P1, 8444 P0, 8445 P2) chỉ mở trên 127.0.0.1"
else
  fail "Port Envoy mở ngoài localhost hoặc chưa mở"
fi
if [ -z "$(docker compose port auth-svc 9191 2>/dev/null)" ]; then
  pass "auth-svc không có port ra host"
else
  fail "auth-svc đang publish port ra host"
fi
# --- OPA (tuần 5): REST API không xác thực → chỉ auth-svc được với tới (T8, quyết định 2026-10-03) ---
if [ -z "$(docker compose port opa 8181 2>/dev/null)" ]; then
  pass "OPA không có port ra host"
else
  fail "OPA đang publish port ra host — ai trên máy cũng hỏi/đổi được policy"
fi
members=$(docker network inspect topic09-policy -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | tr ' ' '\n' | sed -E 's/^topic09-lab-//; s/-[0-9]+$//' | grep . | sort | tr '\n' ' ')
internal=$(docker network inspect topic09-policy -f '{{.Internal}}' 2>/dev/null)
if [ "$members" = "auth-svc opa " ] && [ "$internal" = true ]; then
  pass "Mạng topic09-policy (internal) chỉ có auth-svc + opa"
else
  fail "Mạng topic09-policy: thành viên '$members', internal=$internal (muốn 'auth-svc opa', true)"
fi

CA=secrets/tls/ca.crt
if openssl s_client -connect localhost:8443 -servername localhost -tls1_3 -CAfile "$CA" -verify_return_error -brief </dev/null 2>&1 | grep -q "Protocol version: TLSv1.3"; then
  pass "Gateway bắt tay TLS 1.3, cert hợp lệ theo CA nội bộ"
else
  fail "Gateway không bắt tay được TLS 1.3 (đã chạy scripts/gen-certs.sh chưa?)"
fi
SIEM_FROM=$(date -u +%Y-%m-%dT%H:%M:%SZ)
for port in 8443 8444 8445; do
  code=$(curl -s --cacert "$CA" --max-time 5 -o /dev/null -w '%{http_code}' "https://localhost:$port/orders/whoami")
  if [ "$code" = 401 ]; then pass "Gateway :$port không token → 401"; else fail "Gateway :$port không token → $code (muốn 401)"; fi
done

# --- SIEM (tuần 8): Vector → OpenSearch. Cả hai không có port, ở mạng kín riêng (TB5) ---
# "docker port" chỉ in cổng ĐÃ publish (image OpenSearch có EXPOSE nên "docker compose port" in ":0").
pub="$(docker port "$(docker compose ps -q opensearch)" 2>/dev/null)$(docker port "$(docker compose ps -q vector)" 2>/dev/null)"
if [ -z "$pub" ]; then pass "OpenSearch và Vector không publish cổng nào ra host"; else fail "SIEM đang publish cổng ra host: $pub"; fi
members=$(docker network inspect topic09-telemetry -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | tr ' ' '\n' | sed -E 's/^topic09-lab-//; s/-[0-9]+$//' | grep . | sort | tr '\n' ' ')
internal=$(docker network inspect topic09-telemetry -f '{{.Internal}}' 2>/dev/null)
if [ "$members" = "opensearch vector " ] && [ "$internal" = true ]; then
  pass "Mạng topic09-telemetry (internal) chỉ có opensearch + vector"
else
  fail "Mạng topic09-telemetry: thành viên '$members', internal=$internal (muốn 'opensearch vector', true)"
fi
init=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$(docker compose ps -aq opensearch-init)" 2>/dev/null)
if [ "$init" = "exited 0" ]; then pass "opensearch-init đã nạp mapping (dynamic: strict) rồi thoát mã 0"; else fail "opensearch-init: ${init:-không có} (muốn 'exited 0')"; fi
# Đầu-cuối: ba request 401 ở trên phải thành sự kiện của Envoy trong SIEM (Envoy đẩy log 1 s, Vector gom lô 2 s).
n=0
for _ in $(seq 1 10); do
  sleep 2
  docker compose exec -T opensearch curl -s -X POST 'http://127.0.0.1:9200/topic09-events/_refresh' >/dev/null 2>&1
  n=$(docker compose exec -T opensearch curl -s -H 'Content-Type: application/json' 'http://127.0.0.1:9200/topic09-events/_count' \
    -d "{\"query\":{\"bool\":{\"filter\":[{\"term\":{\"source\":\"envoy\"}},{\"term\":{\"status_code\":401}},{\"range\":{\"event_time\":{\"gte\":\"$SIEM_FROM\"}}}]}}}" 2>/dev/null |
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("count", 0))' 2>/dev/null)
  [ "${n:-0}" -ge 3 ] && break
done
if [ "${n:-0}" -ge 3 ]; then pass "Đường ống telemetry sống: 3 request 401 vừa rồi đã thành sự kiện Envoy trong SIEM"; else fail "SIEM chỉ nhận ${n:-0}/3 sự kiện Envoy sau 20 s (xem: docker compose logs vector)"; fi

echo
docker compose ps
exit $FAIL
