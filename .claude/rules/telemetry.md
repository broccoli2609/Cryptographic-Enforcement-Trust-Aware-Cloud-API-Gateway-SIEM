---
paths:
  - "telemetry/**"
  - "detections/**"
  - "kms/**"
  - "dataset/**"
---
# Luật cho SIEM, Vault và dataset

- SIEM và dataset không chứa token thô, mã uỷ quyền, cookie, khoá riêng (SR-10). Scanner tìm `eyJ`, `-----BEGIN`, `code=` và giá trị khoá HMAC phải chạy được tự động.
- Định danh người dùng băm bằng HMAC (khoá trong `.env`), không dùng hash trần.
- Hash chain `H_i = SHA256(H_{i-1} || event_i)` tính trong Vector. Digester lấy đầu chuỗi từ Vector, **không** đọc từ OpenSearch.
- Mỗi digest có số thứ tự, thời điểm, chữ ký của digest trước; `verify-chain` phải phát hiện được digest bị xoá (khoảng trống > 5 phút).
- Vault: token của digester chỉ có quyền `transit/sign/siem-digest`; app không dùng root token; bật audit device; không đẩy stdout của Vault dev vào SIEM. Lưu public key + version kèm digest (Vault dev mất dữ liệu khi restart).
- Hunt query: mỗi query có giả thuyết, trường bằng chứng, và ATT&CK mapping chỉ khi có bằng chứng thật.
