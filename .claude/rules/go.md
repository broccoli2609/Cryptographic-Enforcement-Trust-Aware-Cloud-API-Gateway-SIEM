---
paths:
  - "**/*.go"
  - "**/go.mod"
---
# Quy ước Go

- Ưu tiên thư viện chuẩn (`net/http`, `log/slog`, `crypto/*`). Dependency mới phải hỏi trước.
- Log bằng `slog` JSON ra stdout, qua `internal/service.NewLogger` hoặc tương đương; mỗi dòng có `service`, `event_time`, `request_id`.
- Không log header, body, token, query string. Route ghi theo `r.Pattern`.
- HTTP server luôn có `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `MaxHeaderBytes`; tắt êm khi nhận SIGTERM.
- Handler không `panic`; lỗi trả JSON `{"error": "<code>"}` với mã HTTP đúng.
- Test dạng bảng (table-driven) cho mọi luật bảo mật: mỗi ca sai một test riêng, tên test nói rõ ca đó.
- Trước khi báo xong: `gofmt -l .` rỗng, `go vet ./...` và `go test ./...` qua. Dán kết quả lệnh, không chỉ nói "đã chạy".
