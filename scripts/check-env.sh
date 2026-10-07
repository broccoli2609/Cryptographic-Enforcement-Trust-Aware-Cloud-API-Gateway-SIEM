#!/usr/bin/env bash
# Kiểm môi trường lab: in phiên bản công cụ và báo chỗ còn thiếu.
# Chạy:  ./scripts/check-env.sh      (mã thoát 0 = đủ, 1 = còn thiếu)
set -u
FAILED=0
ok()   { printf '  [OK]   %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; FAILED=1; }

echo "== Hệ điều hành"
if uname -r | grep -qi microsoft; then ok "WSL2, kernel $(uname -r)"; else warn "Không thấy kernel WSL: $(uname -r)"; fi
. /etc/os-release && ok "$PRETTY_NAME"
if [ "$(ps -p 1 -o comm= 2>/dev/null)" = systemd ]; then ok "systemd đang chạy"; else warn "systemd chưa bật: Docker sẽ không tự khởi động (xem doc, mục Docker)"; fi

echo "== Docker"
if command -v docker >/dev/null 2>&1; then
  ok "$(docker --version)"
  if docker compose version >/dev/null 2>&1; then ok "$(docker compose version)"; else fail "Thiếu plugin docker compose"; fi
  if docker info >/dev/null 2>&1; then ok "Gọi được Docker daemon không cần sudo"
  else fail "Không gọi được Docker daemon: daemon chưa chạy, hoặc user chưa vào nhóm docker (chạy lại terminal sau usermod)"; fi
else
  fail "Chưa có lệnh docker"
fi

echo "== Go"
if command -v go >/dev/null 2>&1; then ok "$(go version)"; else fail "Chưa có go, hoặc PATH chưa có /usr/local/go/bin"; fi

echo "== perf"
PERF=$(find /usr/lib -maxdepth 3 -path '*linux-tools*' -name perf -type f 2>/dev/null | sort -V | tail -n1)
if [ -n "$PERF" ]; then ok "perf ở $PERF"; else warn "Chưa cài linux-tools-generic"; fi
echo "  perf_event_paranoid = $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo '?')"

exit $FAILED
