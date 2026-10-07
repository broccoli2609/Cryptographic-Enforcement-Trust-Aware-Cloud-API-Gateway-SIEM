# Cách mở một phiên Claude Code cho hiệu quả

File này dành cho bạn đọc, Claude Code không tự nạp nó.

## Ba lớp ngữ cảnh — vì sao không bị quá tải

| Lớp | File | Khi nào được nạp |
|---|---|---|
| Luôn có | `CLAUDE.md` (~70 dòng) | Mọi phiên, lúc khởi động |
| Theo thư mục | `.claude/rules/*.md` | Chỉ khi Claude đọc/sửa file khớp `paths:` (Go, gateway, compose, telemetry, policy) |
| Theo yêu cầu | `docs/context/*.md` | Chỉ khi Claude tự mở vì việc cần — CLAUDE.md chỉ ghi đường dẫn, không dùng `@` |

Không dùng cú pháp `@file` trong CLAUDE.md cho các file lớn: file được import bằng `@` bị nạp ngay từ đầu phiên, tốn ngữ cảnh mọi lần.

## Mỗi phiên = một việc

1. Mở terminal Ubuntu: `cd ~/topic09-lab && claude -n w3-t5-realm` (đặt tên theo tuần–buổi–việc để `claude --resume w3-t5-realm` sau này).
2. Dán **prompt mở phiên** (dưới). Với việc mới hoặc lớn, bấm `Shift+Tab` để vào plan mode trước khi cho sửa code.
3. Trong phiên: gõ `/context` để xem đã dùng bao nhiêu ngữ cảnh. Khi phiên dài, dùng `/compact` kèm hướng dẫn giữ lại gì.
4. Sửa cùng một lỗi hai lần không được → `/clear`, viết lại prompt rõ hơn, thường nhanh hơn cố tiếp.
5. Việc tra cứu/đọc nhiều file → bảo Claude "dùng subagent để tìm", kết quả gọn hơn.
6. Hết việc → dán **prompt kết thúc phiên**, xem diff, tự commit.
7. Việc tiếp theo → `/clear` hoặc mở phiên mới, đừng nối vào phiên cũ.

## Prompt mẫu

**Mở phiên**

```text
Đọc docs/context/progress.md. Việc của phiên này: <Tuần X T5/T6 — mô tả ngắn, lấy từ docs/context/plan.md>.
Trước khi làm, nêu kế hoạch 3–6 bước và lệnh kiểm cho từng bước, rồi chờ tôi đồng ý.
```

**Kết thúc phiên**

```text
Kết thúc phiên: chạy lại test liên quan và dán kết quả; cập nhật docs/context/progress.md
(Đang làm, Tiếp theo, 1–3 dòng nhật ký); thêm quyết định mới vào docs/context/decisions.md nếu có;
đề xuất commit message. Không commit.
```

**Khi kẹt**

```text
Dừng sửa code. Liệt kê 3 giả thuyết nguyên nhân, mỗi cái kèm một lệnh để kiểm. Chưa sửa gì.
```

**Thu gọn ngữ cảnh**

```text
/compact Giữ lại: việc đang làm, danh sách file đã sửa, lệnh test, lỗi còn lại, quyết định đã chốt trong phiên.
```

## Phiên đầu tiên — Tuần 2 T6 (làm bù)

```text
Đọc docs/context/progress.md. Việc của phiên này: Tuần 2 T6 — chạy setup lab trên máy.
Chạy ./scripts/check-env.sh và giải thích từng dòng [FAIL]/[WARN]. Lệnh nào cần sudo thì đưa cho tôi tự chạy.
Sau đó lần lượt: check-perf.sh → docker compose up -d --build → smoke-test.sh. Dừng sau mỗi bước để tôi xác nhận.
```
