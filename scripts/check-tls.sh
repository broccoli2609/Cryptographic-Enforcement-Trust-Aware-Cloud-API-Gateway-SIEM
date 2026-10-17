#!/usr/bin/env bash
# Tuần 4 T5 — SR-01: gateway chỉ nói TLS 1.3, cert hợp lệ theo CA nội bộ.
#   ./scripts/check-tls.sh [host:port] | tee docs/evidence/tls13-$(date +%F).txt
# Mã thoát = số mục FAIL.
set -uo pipefail
. "$(dirname "$0")/lib/common.sh"

HOSTPORT=${1:-localhost:8443}
CA="$ROOT/secrets/tls/ca.crt"
[ -f "$CA" ] || die "chưa có $CA — chạy ./scripts/gen-certs.sh"
FAIL=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }

echo "# TLS của gateway $HOSTPORT — $(date -Iseconds)"
echo "# $(openssl version)"

echo
echo "## 1. openssl s_client -tls1_3 -CAfile ca.crt -verify_return_error"
out=$(openssl s_client -connect "$HOSTPORT" -servername localhost -tls1_3 -CAfile "$CA" \
  -verify_return_error -brief </dev/null 2>&1)
echo "$out" | grep -E "Protocol version|Ciphersuite|Peer certificate|Hash used|Signature type|Verification|Server Temp Key|Negotiated TLS1.3 group" | sed 's/^/    /'
if echo "$out" | grep -q "Protocol version: TLSv1.3" && echo "$out" | grep -q "Verification: OK"; then
  pass "bắt tay TLS 1.3, cert hợp lệ theo CA nội bộ"
else
  fail "không bắt tay được TLS 1.3 hoặc cert không hợp lệ"
fi

echo
echo "## 2. openssl s_client -tls1_2 (phải THẤT BẠI — không cho hạ cấp)"
out=$(openssl s_client -connect "$HOSTPORT" -servername localhost -tls1_2 -CAfile "$CA" </dev/null 2>&1)
rc=$?
echo "$out" | grep -iE "alert|error|Protocol|Cipher is" | head -3 | sed 's/^/    /'
# Lưu ý: s_client vẫn in "Protocol : TLSv1.2" (phiên bản nó ĐÃ THỬ) kể cả khi bắt tay thất bại.
# Dấu hiệu thất bại thật: không thoả thuận được cipher ("Cipher is (NONE)") / alert protocol_version.
if [ $rc -ne 0 ] && echo "$out" | grep -qE "Cipher is \(NONE\)|alert protocol version"; then
  pass "TLS 1.2 bị từ chối khi bắt tay (openssl thoát mã $rc)"
else
  fail "gateway chấp nhận TLS 1.2"
fi

echo
echo "## 3. curl --tlsv1.2 --tls-max 1.2 (phía client giới hạn TLS 1.2 — phải thất bại)"
if out=$(curl -sS --cacert "$CA" --tlsv1.2 --tls-max 1.2 "https://$HOSTPORT/" -o /dev/null 2>&1); then
  fail "curl TLS 1.2 kết nối được"
else
  echo "    $out"
  pass "curl không kết nối được bằng TLS 1.2"
fi

echo
echo "## 4. HTTP thường (không TLS) vào cổng $HOSTPORT (phải không có phản hồi HTTP)"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$HOSTPORT/" 2>/dev/null)
if [ "$code" = 000 ]; then pass "không có phản hồi HTTP (mã curl 000) — không có kênh rõ"; else fail "nhận HTTP $code qua kênh không mã hoá"; fi

echo
echo "## 5. Thông tin cert gateway (secrets/tls/envoy.crt)"
openssl x509 -in "$ROOT/secrets/tls/envoy.crt" -noout -subject -issuer -enddate -ext subjectAltName,extendedKeyUsage 2>/dev/null | sed 's/^/    /'
openssl x509 -in "$ROOT/secrets/tls/envoy.crt" -noout -text | grep -E "Public Key Algorithm|NIST CURVE|Signature Algorithm" | sort -u | sed 's/^ */    /'

echo
echo "Kết quả: $((4 - FAIL))/4 PASS"
exit $FAIL
