#!/usr/bin/env bash
# Kiểm perf có đếm được cycles trong WSL2 không, và lưu bằng chứng vào docs/evidence/.
# Chạy:  ./scripts/check-perf.sh
# Mã thoát: 0 = đếm được cycles; 1 = không (xem kết luận in ra cuối).
set -u
cd "$(dirname "$0")/.." || exit 1
OUT="docs/evidence/perf-check-$(date +%Y-%m-%d).txt"
mkdir -p docs/evidence

# Lệnh /usr/bin/perf là script bọc, nó tìm perf đúng với kernel đang chạy và báo
# "WARNING: perf not found for kernel ...-microsoft-standard-WSL2" vì Ubuntu không đóng gói
# perf cho kernel của WSL. Ta gọi thẳng file perf của gói linux-tools-generic.
PERF=$(find /usr/lib -maxdepth 3 -path '*linux-tools*' -name perf -type f 2>/dev/null | sort -V | tail -n1)
if [ -z "$PERF" ]; then
  echo "Chưa có perf. Cài:  sudo apt install -y linux-tools-common linux-tools-generic"
  exit 1
fi

{
  echo "# perf check — $(date -Is)"
  echo "kernel:     $(uname -r)"
  echo "cpu:        $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
  echo "perf:       $PERF ($($PERF --version 2>&1))"
  echo "paranoid:   $(cat /proc/sys/kernel/perf_event_paranoid)"
  echo
  echo "\$ perf stat -e cycles,instructions,task-clock -- ls"
  "$PERF" stat -e cycles,instructions,task-clock -- ls 2>&1 >/dev/null
} | tee "$OUT"

echo
if grep -Eq 'Permission denied|perf_event_paranoid' "$OUT"; then
  echo "KẾT LUẬN: bị chặn quyền. Chạy:  sudo sysctl -w kernel.perf_event_paranoid=1  rồi chạy lại script."
  exit 1
elif grep -Eq '<not (supported|counted)>[[:space:]]+cycles' "$OUT"; then
  echo "KẾT LUẬN: máy ảo WSL2 không đưa bộ đếm phần cứng (PMU) cho Linux, cycles = <not supported>."
  echo "          Dùng phương án dự phòng: go test -bench (ns/op) + benchstat. Ghi hạn chế vào báo cáo."
  exit 1
elif grep -Eq '^[[:space:]]*[0-9][0-9.,]*[[:space:]]+cycles' "$OUT"; then
  echo "KẾT LUẬN: đếm được cycles. Bằng chứng đã lưu ở $OUT"
  exit 0
else
  echo "KẾT LUẬN: không đọc được kết quả, xem $OUT"
  exit 1
fi
