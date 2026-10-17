#!/usr/bin/env bash
# Tuần 4 T5 — CA nội bộ + chứng chỉ TLS cho Envoy (tài sản #10, #11). Khoá EC P-256.
#   secrets/tls/ca.key     khoá riêng CA       600  — KHÔNG mount vào container nào
#   secrets/tls/ca.crt     root cert (công khai) — client dùng: curl --cacert secrets/tls/ca.crt
#   secrets/tls/envoy.key  khoá riêng TLS Envoy 644  — xem giải thích quyền bên dưới
#   secrets/tls/envoy.crt  cert Envoy do CA ký, SAN = localhost, 127.0.0.1, envoy; hạn 90 ngày
#
#   ./scripts/gen-certs.sh           # tạo nếu chưa có
#   ./scripts/gen-certs.sh --renew   # cấp lại cert + khoá Envoy, giữ nguyên CA
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

DIR="$ROOT/secrets/tls"
mkdir -p "$DIR"
# Thư mục 700: user khác trên máy không mở được bất kỳ file nào bên trong, kể cả file 644.
chmod 700 "$ROOT/secrets" "$DIR"
cd "$DIR"

if [ ! -f ca.key ]; then
  echo "Tạo CA nội bộ (EC P-256, hạn 3 năm)…"
  (umask 077 && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key)
  openssl req -x509 -new -key ca.key -sha256 -days 1095 -subj "/CN=topic09-lab Root CA/O=topic09-lab" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -out ca.crt
fi

if [ ! -f envoy.key ] || [ "${1:-}" = --renew ]; then
  echo "Cấp cert TLS cho Envoy (EC P-256, hạn 90 ngày)…"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out envoy.key
  openssl req -new -key envoy.key -subj "/CN=localhost/O=topic09-lab" -out envoy.csr
  # Phần mở rộng của cert lá: không phải CA, chỉ dùng làm server TLS, SAN khớp tên client gọi.
  openssl x509 -req -in envoy.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -days 90 \
    -extfile <(printf '%s\n' \
      "basicConstraints=critical,CA:FALSE" \
      "keyUsage=critical,digitalSignature" \
      "extendedKeyUsage=serverAuth" \
      "subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:envoy" \
      "authorityKeyIdentifier=keyid") \
    -out envoy.crt 2>/dev/null
  rm -f envoy.csr
fi

# Quyền file:
#   ca.key 600   — chỉ chủ sở hữu (ký cert mới).
#   envoy.key 644 — Envoy trong container chạy uid 65532, cần đọc được file bind-mount.
#                   Trên host, thư mục 700 ở trên vẫn chặn mọi user khác.
chmod 600 ca.key
chmod 644 envoy.key envoy.crt ca.crt

echo "CA   : $(openssl x509 -in ca.crt -noout -subject -enddate | tr '\n' ' ')"
echo "Envoy: $(openssl x509 -in envoy.crt -noout -subject -enddate | tr '\n' ' ')"
echo "       $(openssl x509 -in envoy.crt -noout -ext subjectAltName | tail -1 | sed 's/^ *//')"
openssl verify -CAfile ca.crt envoy.crt
