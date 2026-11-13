#!/usr/bin/env bash
# In sự kiện trong SIEM (index topic09-events) ra stdout, mỗi dòng một JSON, xếp theo event_time.
#
#   ./scripts/siem-export.sh                        mọi sự kiện
#   ./scripts/siem-export.sh 2026-11-13T07:00:00Z   chỉ sự kiện có event_time ≥ thời điểm đó
#
# OpenSearch không có "ports" (luật T5), nên script gọi curl TỪ BÊN TRONG container opensearch
# (docker compose exec). Dùng scroll API để lấy hết, không bị giới hạn 10 000 kết quả.
# Số sự kiện in ra stderr. Dùng cho siem-scan.sh, siem-test.sh, và xuất dataset ở tuần 10.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - "${1:-}" <<'PY'
import json, subprocess, sys

since = sys.argv[1]
BASE = "http://127.0.0.1:9200"


def call(method, path, body=None):
    cmd = ["docker", "compose", "exec", "-T", "opensearch", "curl", "-sS", "-X", method,
           "-H", "Content-Type: application/json", BASE + path]
    if body is not None:
        cmd += ["--data-binary", "@-"]
    p = subprocess.run(cmd, input=None if body is None else json.dumps(body).encode(),
                       stdin=subprocess.DEVNULL if body is None else None,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        sys.exit("không gọi được OpenSearch (lab đang chạy chưa?): " + p.stderr.decode(errors="replace")[:300])
    try:
        return json.loads(p.stdout or b"{}")
    except ValueError:
        sys.exit("OpenSearch trả nội dung không phải JSON: " + p.stdout.decode(errors="replace")[:200])


call("POST", "/topic09-events/_refresh")  # tài liệu vừa ghi phải tìm thấy được ngay
query = {"range": {"event_time": {"gte": since}}} if since else {"match_all": {}}
r = call("POST", "/topic09-events/_search?scroll=1m",
         {"size": 1000, "sort": [{"event_time": "asc"}], "query": query})
if "error" in r:
    reason = r["error"].get("type") if isinstance(r["error"], dict) else r["error"]
    if reason == "index_not_found_exception":
        print("0 sự kiện (index chưa được tạo)", file=sys.stderr)
        sys.exit(0)
    sys.exit("OpenSearch báo lỗi: %s" % reason)
n = 0
while True:
    hits = r.get("hits", {}).get("hits", [])
    if not hits:
        break
    for h in hits:
        print(json.dumps(h["_source"], ensure_ascii=False, sort_keys=True))
        n += 1
    r = call("POST", "/_search/scroll", {"scroll": "1m", "scroll_id": r["_scroll_id"]})
if r.get("_scroll_id"):
    call("DELETE", "/_search/scroll", {"scroll_id": r["_scroll_id"]})
print("%d sự kiện" % n, file=sys.stderr)
PY
