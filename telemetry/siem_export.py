#!/usr/bin/env python3
"""Xuất tài liệu từ OpenSearch của lab ra NDJSON (mỗi dòng một _source) — chỉ thư viện chuẩn.

OpenSearch không có port ra host (T5), nên lệnh gọi đi qua `docker compose exec opensearch curl`.
Phân trang bằng search_after theo trường sắp xếp — không giới hạn 10 000 tài liệu.

Số trong _source giữ NGUYÊN VĂN (2.0 vẫn là 2.0) và khoá sắp xếp, để telemetry/chain_check.py băm
lại đúng từng byte như Vector đã băm.

  python3 telemetry/siem_export.py --index topic09-events --sort chain_seq \
      --query '{"term":{"chain_epoch":"…"}}' > ev.ndjson
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chain_check import canon, loads  # noqa: E402


def search(body, index):
    r = subprocess.run(
        ["docker", "compose", "exec", "-T", "opensearch", "curl", "-s", "-H", "Content-Type: application/json",
         "http://127.0.0.1:9200/%s/_search" % index, "--data-binary", "@-"],
        input=json.dumps(body).encode(), capture_output=True, check=True)
    return loads(r.stdout.decode("utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", required=True)
    ap.add_argument("--sort", required=True, help="trường sắp xếp tăng dần (số), ví dụ chain_seq")
    ap.add_argument("--query", default='{"match_all":{}}')
    ap.add_argument("--tiebreak", help="trường keyword phá hoà khi --sort trùng (ví dụ event_hash)")
    ap.add_argument("--page", type=int, default=2000)
    a = ap.parse_args()
    sort = [{a.sort: "asc"}] + ([{a.tiebreak: "asc"}] if a.tiebreak else [])
    body = {"size": a.page, "query": json.loads(a.query), "sort": sort}
    n = 0
    while True:
        res = search(body, a.index)
        if "error" in res:
            status = int(res.get("status", 0))
            if status == 404:
                break  # index chưa có
            sys.exit("OpenSearch lỗi: %s" % json.dumps(res["error"])[:300])
        hits = res["hits"]["hits"]
        for h in hits:
            print(canon(h["_source"]))
            n += 1
        if len(hits) < a.page:
            break
        body["search_after"] = [json.loads(canon(x)) for x in hits[-1]["sort"]]
    print("đã xuất %d tài liệu từ %s" % (n, a.index), file=sys.stderr)


if __name__ == "__main__":
    main()
