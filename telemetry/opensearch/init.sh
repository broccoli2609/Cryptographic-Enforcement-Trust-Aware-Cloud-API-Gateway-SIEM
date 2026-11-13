#!/bin/sh
# Chạy MỘT LẦN mỗi khi `docker compose up` (service opensearch-init), trước khi Vector khởi động:
# nạp mapping của index topic09-events vào OpenSearch. Mapping sinh từ telemetry/schema.json
# (make siem-mapping) và có "dynamic": "strict" — OpenSearch từ chối tài liệu có trường lạ.
#
# Vì sao phải chạy TRƯỚC Vector: nếu Vector ghi tài liệu đầu tiên khi chưa có template,
# OpenSearch tự đoán kiểu dữ liệu (mọi chuỗi thành "text", không strict) và không sửa lại được
# nếu không xoá index.
set -eu
OS=http://opensearch:9200
H='Content-Type: application/json'

# 1. Template: áp dụng cho index tạo SAU thời điểm này.
curl -fsS -X PUT -H "$H" --data-binary @/init/index-template.json "$OS/_index_template/topic09-events" >/dev/null
echo "index template topic09-events: đã nạp"

# 2. Index đã có từ lần chạy trước mà schema vừa thêm trường → cập nhật mapping tại chỗ.
#    404 = chưa có index (lần đầu), bỏ qua. Mã khác (ví dụ 400 do đổi kiểu một trường đã có)
#    là lỗi thật: dừng, để Vector không khởi động với mapping lệch schema.
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$H" --data-binary @/init/index-mapping.json "$OS/topic09-events/_mapping")
case "$code" in
  200) echo "index topic09-events: mapping đã cập nhật" ;;
  404) echo "index topic09-events: chưa có, sẽ được tạo theo template" ;;
  *) echo "index topic09-events: cập nhật mapping thất bại (HTTP $code)" >&2; exit 1 ;;
esac
