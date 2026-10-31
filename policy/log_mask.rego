# Che dữ liệu trong decision log của OPA (SR-10).
#
# OPA ghi MỖI quyết định ra stdout (--set=decision_logs.console=true), gồm cả input. Trước
# khi ghi, OPA đánh giá data.system.log.mask: mỗi phần tử là một JSON pointer bị xoá khỏi
# bản ghi (bản ghi có thêm trường "erased" liệt kê các pointer đã xoá).
#
# input.path là đường dẫn thật (/orders/123, /profile/<id>) — giống luật của backend và
# auth-svc, log chỉ giữ route theo mẫu: result.route ("orders.read") đã đủ cho hunt H4/H5.
package system.log

mask contains "/input/path"
