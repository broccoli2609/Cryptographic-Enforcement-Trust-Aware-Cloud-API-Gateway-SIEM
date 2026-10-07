#!/usr/bin/env bash
# Kiểm nhanh lab sau "docker compose up -d --build".
# Chạy:  ./scripts/smoke-test.sh      (mã thoát = số mục FAIL)
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

for svc in keycloak orders-api profile-api; do
  s=$(health "$svc")
  if [ "$s" = healthy ]; then pass "$svc: healthy"; else fail "$svc: $s"; fi
done

if curl -fsS http://localhost:8080/realms/master/.well-known/openid-configuration | grep -q '"issuer":"http://localhost:8080/realms/master"'; then
  pass "Keycloak trả discovery document, issuer = http://localhost:8080/realms/master"
else
  fail "Không lấy được discovery document của Keycloak"
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

echo
docker compose ps
exit $FAIL
