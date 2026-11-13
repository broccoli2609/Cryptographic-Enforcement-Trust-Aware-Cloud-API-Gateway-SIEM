#!/usr/bin/env bash
# Scanner SR-10 — SIEM và dataset không được chứa token, khoá, mã uỷ quyền, bí mật của lab hay
# định danh thô của người dùng (luật telemetry). Chạy tự động được: mã thoát nói lên kết quả.
#
#   ./scripts/siem-scan.sh            quét TOÀN BỘ index topic09-events + mọi file trong dataset/
#   ./scripts/siem-scan.sh --stdin    quét dữ liệu đưa vào stdin (để thử chính scanner)
#
# Tìm: "eyJ" (JWT) · "-----BEGIN" (khoá PEM) · "code=" (mã uỷ quyền) · header Bearer/DPoP ·
#      giá trị các biến bí mật trong .env (mật khẩu, khoá HMAC) · sub/username/email của user
#      trong idp/realm-topic09.json.
# Chỉ in số dòng + loại + tên trường, không in giá trị tìm thấy.
# Mã thoát: 0 = sạch · 1 = có phát hiện · 2 = không quét được.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

scan() { python3 telemetry/secret_scan.py --env .env --realm idp/realm-topic09.json --label "$1"; }

if [ "${1:-}" = "--stdin" ]; then
  scan "stdin"
  exit $?
fi

RC=0
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
if ! ./scripts/siem-export.sh >"$TMP" 2>/dev/null; then
  echo "không đọc được SIEM (lab đang chạy chưa?)" >&2
  exit 2
fi
scan "SIEM (index topic09-events)" <"$TMP" || RC=1

# dataset/ (tuần 10): mỗi file quét riêng. .gitkeep và file rỗng thì bỏ qua.
while IFS= read -r -d '' f; do
  scan "$f" <"$f" || RC=1
done < <(find dataset -type f ! -name .gitkeep -size +0c -print0 2>/dev/null)

exit $RC
