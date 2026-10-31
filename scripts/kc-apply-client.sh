#!/usr/bin/env bash
# Áp MỘT client trong idp/realm-topic09.json vào Keycloak ĐANG CHẠY mà không xoá realm.
#
# Vì sao cần: realm import theo IGNORE_EXISTING — realm đã có thì Keycloak bỏ qua file. Sửa file
# rồi muốn áp thì hoặc xoá realm (mất dữ liệu, phải đăng ký lại khoá batch-worker), hoặc dùng
# script này. Máy sạch không cần script: import realm lần đầu đã có client.
# Nguồn sự thật vẫn là file realm JSON — script đọc client + scopeMappings từ đó, không tự chế.
#
#   ./scripts/kc-apply-client.sh web-app-dpop
# Client đã tồn tại thì không tạo lại (không ghi đè); scope mapping thì luôn được đảm bảo.
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

CID_NAME=${1:?cách dùng: $0 <clientId>}
REALM_FILE="$ROOT/idp/realm-topic09.json"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Lấy client + danh sách role từ realm JSON.
python3 - "$REALM_FILE" "$CID_NAME" "$TMP" <<'PY'
import json, sys
realm, name, tmp = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
clients = [c for c in realm["clients"] if c["clientId"] == name]
if not clients:
    sys.exit(f"không có client {name} trong {sys.argv[1]}")
json.dump(clients[0], open(f"{tmp}/client.json", "w"))
roles = [r for m in realm.get("scopeMappings", []) if m.get("client") == name for r in m["roles"]]
open(f"{tmp}/roles.txt", "w").write("".join(r + "\n" for r in roles))  # mỗi dòng có "\n", kể cả dòng cuối
PY

ADM=$(kc_admin_token) || die "không lấy được token admin — Keycloak đã chạy chưa?"
id_of() { kc_api "$ADM" "clients?clientId=$CID_NAME" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")'; }

ID=$(id_of)
if [ -z "$ID" ]; then
  kc_api "$ADM" -o /dev/null -H 'Content-Type: application/json' --data-binary @"$TMP/client.json" clients
  ID=$(id_of)
  echo "Đã tạo client $CID_NAME (id $ID) từ $REALM_FILE"
else
  echo "Client $CID_NAME đã có (id $ID) — giữ nguyên, không ghi đè."
fi

# Scope mapping (fullScopeAllowed: false): chỉ những role này được vào token của client.
ROLES_JSON="["
# "|| [ -n "$role" ]": vẫn đọc dòng cuối nếu file thiếu "\n" (lỗi từng làm mất role hr).
while read -r role || [ -n "$role" ]; do
  [ -n "$role" ] || continue
  ROLES_JSON+="$(kc_api "$ADM" "roles/$role"),"
done <"$TMP/roles.txt"
ROLES_JSON="${ROLES_JSON%,}]"
if [ "$ROLES_JSON" != "[]" ]; then
  printf '%s' "$ROLES_JSON" | kc_api "$ADM" -o /dev/null -H 'Content-Type: application/json' --data-binary @- \
    "clients/$ID/scope-mappings/realm"
fi
echo "Scope mapping realm role: $(kc_api "$ADM" "clients/$ID/scope-mappings/realm" | python3 -c 'import json,sys; print(sorted(r["name"] for r in json.load(sys.stdin)))')"
echo "Thuộc tính DPoP: dpop.bound.access.tokens = $(kc_api "$ADM" "clients/$ID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["attributes"].get("dpop.bound.access.tokens", "(không có)"))')"
