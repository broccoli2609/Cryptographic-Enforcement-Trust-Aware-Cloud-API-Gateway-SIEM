---
paths:
  - "policy/**"
---
# Luật cho OPA / Rego

- `default allow := false`. Mọi kết quả trả kèm `policy_id`, `policy_version`, `reason`.
- Input chỉ lấy từ claim của token đã kiểm, không lấy từ header client.
- Mỗi rule có `opa test`; có test cho ca deny, không chỉ ca allow.
- REST API của OPA mặc định không xác thực: OPA không có `ports:`, chỉ chung network với auth-svc, hoặc bật `--authentication=token --authorization=basic`.
- Test fail-closed: `docker stop opa` rồi gọi API phải ra 403/503, không bao giờ 200.
