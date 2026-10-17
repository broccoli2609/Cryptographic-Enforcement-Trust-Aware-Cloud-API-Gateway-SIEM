#!/usr/bin/env bash
# Tuần 3 T6 — đăng nhập (Auth Code + PKCE) lần lượt từng user và in bảng claim quan trọng
# trong access token: bằng chứng realm cấp đúng role, dept, tier, aud, typ.
#   ./scripts/token-claims.sh [user...] | tee docs/evidence/token-claims-$(date +%F).txt
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

USERS=("$@")
[ ${#USERS[@]} -gt 0 ] || USERS=(alice bob carol dave)

echo "# Claim trong access token (Auth Code + PKCE, client web-app) — $(date -Iseconds)"
printf '%-8s %-12s %-9s %-12s %-7s %-6s %s\n' user dept tier aud typ alg realm_roles
for u in "${USERS[@]}"; do
  # Token truyền cho python qua biến môi trường: /proc/<pid>/environ chỉ chủ tiến trình đọc
  # được, còn tham số dòng lệnh thì mọi user trên máy xem được bằng ps.
  TOKEN=$("$(dirname "$0")/pkce-login.sh" "$u" --token) python3 - <<'PY'
import base64, json, os
t = os.environ["TOKEN"].split(".")
dec = lambda s: json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
h, c = dec(t[0]), dec(t[1])
print(f"{c['preferred_username']:8} {c.get('dept', '-'):12} {c.get('tier', '-'):9} "
      f"{str(c['aud']):12} {c['typ']:7} {h['alg']:6} {c['realm_access']['roles']}")
PY
done
