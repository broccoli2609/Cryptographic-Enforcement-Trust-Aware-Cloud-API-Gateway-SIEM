#!/usr/bin/env bash
# Tuần 3 T6 — khoá cho client batch-worker (private_key_jwt, tài sản #3).
#   1. Sinh khoá riêng EC P-256 + chứng chỉ tự ký vào secrets/batch-worker/ (nếu chưa có).
#   2. Đăng ký chứng chỉ (chỉ khoá CÔNG KHAI) vào client batch-worker qua Admin REST API.
# Khoá riêng không bao giờ rời máy client; Keycloak chỉ giữ khoá công khai để kiểm chữ ký.
#
#   ./scripts/batch-worker-key.sh            # sinh nếu chưa có, rồi đăng ký
#   ./scripts/batch-worker-key.sh --rotate   # sinh khoá MỚI (xoay khoá), rồi đăng ký
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

DIR="$ROOT/secrets/batch-worker"
KEY="$DIR/key.pem"
CERT="$DIR/cert.pem"

umask 077 # mọi file tạo ra chỉ chủ sở hữu đọc được
mkdir -p "$DIR"
chmod 700 "$ROOT/secrets" "$DIR"

if [ ! -f "$KEY" ] || [ "${1:-}" = --rotate ]; then
  echo "Sinh khoá EC P-256 mới cho batch-worker…"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$KEY.new"
  openssl req -x509 -new -key "$KEY.new" -subj "/CN=batch-worker/O=topic09-lab" \
    -days 365 -sha256 -out "$CERT.new" 2>/dev/null
  mv "$KEY.new" "$KEY"
  mv "$CERT.new" "$CERT"
else
  echo "Đã có khoá ở secrets/batch-worker/ — giữ nguyên (dùng --rotate để thay)."
fi
chmod 600 "$KEY"
echo "Chứng chỉ: $(openssl x509 -in "$CERT" -noout -subject -enddate | tr '\n' ' ')"
echo "Vân tay khoá công khai (SHA-256): $(openssl pkey -in "$KEY" -pubout -outform DER | openssl dgst -sha256 -r | cut -c1-16)…"

ADM=$(kc_admin_token) || die "không lấy được token admin — Keycloak đã chạy chưa?"
CID=$(kc_api "$ADM" "clients?clientId=batch-worker" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
# Endpoint chính thức để nạp chứng chỉ cho xác thực client bằng JWT:
# lưu vào thuộc tính jwt.credential.certificate của client.
kc_api "$ADM" -o /dev/null -F "keystoreFormat=Certificate PEM" -F "file=@$CERT" \
  "clients/$CID/certificates/jwt.credential/upload-certificate"
echo "Đã đăng ký chứng chỉ vào client batch-worker (thuộc tính jwt.credential.certificate)."
