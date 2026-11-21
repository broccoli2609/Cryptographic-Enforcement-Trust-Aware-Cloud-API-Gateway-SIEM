# Policy của digester (tuần 9 T5, TB4, T7, RC6) — quyền tối thiểu: CHỈ ký bằng khoá siem-digest.
#
# Không có: đọc/xoay/xoá khoá, verify, encrypt/decrypt pii-enc, sys/*, auth/* (token tạo với
# -no-default-policy nên cũng không có lookup-self/renew-self của policy "default").
# Lộ token này = kẻ tấn công ký được digest giả cho tới khi token bị thu hồi (residual risk T7);
# không đọc được khoá riêng (khoá Transit không export) và không giải mã được dữ liệu.
#
# Đường dẫn chính xác, không dùng "*" hay "+": transit/sign/siem-digest/<thuật toán băm> là
# đường dẫn KHÁC và không được phép (ed25519 không cần).
path "transit/sign/siem-digest" {
  capabilities = ["update"]
}
