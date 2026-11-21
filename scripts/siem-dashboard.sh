#!/usr/bin/env bash
# Tuần 9 T6 — dashboard SIEM tĩnh: chạy 6 hunt rồi sinh một file HTML tự chứa (chỉ số đếm đã gom).
#   ./scripts/siem-dashboard.sh                   # cửa sổ 24 giờ gần nhất
#   ./scripts/siem-dashboard.sh 2026-11-21T00:00:00Z
# Kết quả: docs/evidence/siem-dashboard-<ngày>.html (mở bằng trình duyệt; không tải gì từ mạng).
set -euo pipefail
cd "$(dirname "$0")/.."
SINCE=${1:-$(date -u -d '-1 day' +%Y-%m-%dT%H:%M:%SZ)}
OUT=docs/evidence/siem-dashboard-$(date +%F).html
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
python3 detections/hunt.py --since "$SINCE" --json "$TMP" > /dev/null
python3 telemetry/dashboard.py --since "$SINCE" --hunts "$TMP" --out "$OUT"
# Bảo đảm trang không chứa định danh / bí mật: chạy cùng bộ mẫu với scanner SR-10.
python3 - "$OUT" <<'PY'
import re, sys
t = open(sys.argv[1], encoding="utf-8").read()
bad = [n for n, rx in [("JWT", r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"), ("PEM", r"-----BEGIN"), ("hash 64 hex", r"\b[0-9a-f]{64}\b"),
                      ("UUID", r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")] if re.search(rx, t)]
print("kiểm nội dung dashboard: " + ("SẠCH (không JWT/PEM/hash định danh/UUID)" if not bad else "CÓ: " + ", ".join(bad)))
sys.exit(1 if bad else 0)
PY
