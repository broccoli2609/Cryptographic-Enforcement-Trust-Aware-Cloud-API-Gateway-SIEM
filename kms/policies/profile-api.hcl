# Policy của profile-api (tạo ở tuần 9 T5, dùng từ tuần 10 — Secure Storage, SR-13, CR-08, M9).
# CHỈ mã hoá / giải mã bằng khoá pii-enc (AES-256-GCM96, không export).
#
# Không có: rewrap/rotate (việc của người vận hành, runbook tuần 12), ký siem-digest, đọc cấu hình
# khoá, sys/*, auth/*. Lộ token này = giải mã được salary_band (residual risk T12, ghi trong
# security-model.md); không đọc được khoá và không giả được digest SIEM.
path "transit/encrypt/pii-enc" {
  capabilities = ["update"]
}

path "transit/decrypt/pii-enc" {
  capabilities = ["update"]
}
