#!/usr/bin/env python3
"""Chạy các hunt H1, H2, H3, H4, H5, H9 (detections/H*.json) trên SIEM của lab — chỉ thư viện chuẩn.

Mỗi file H*.json: giả thuyết, mối đe doạ, trường bằng chứng, ATT&CK (chỉ khi có bằng chứng thật),
và một hay nhiều "part" — mỗi part một kiểu truy vấn:

  terms            lọc + gom nhóm theo group_by; nhóm có ≥ threshold sự kiện = một phát hiện
  cardinality      nhóm theo group_by có ≥ min_distinct giá trị khác nhau của trường distinct
                   (ví dụ cùng principal_hash mà subject_roles đổi)
  join             bước 1 lấy request_id của sự kiện khớp query; bước 2 tra sự kiện khác cùng
                   request_id (lookup) rồi gom nhóm — OpenSearch không có join, runner làm hộ
  admin_then_use   sự kiện quản trị gán quyền cho admin_target_hash, rồi đếm sự kiện của chính
                   principal_hash đó SAU thời điểm gán
  seq_gaps         epoch nào có sự kiện trong cửa sổ: chain_seq có liền mạch không (thiếu = bị xoá)
  digest_freshness digest mới nhất còn mới không; digest_seq có liền mạch không
  chain_verify     tính lại event_hash + đầu chuỗi và kiểm chữ ký digest (telemetry/chain_check.py)

OpenSearch không có port ra host: truy vấn đi qua `docker compose exec opensearch curl`.

  python3 detections/hunt.py                         # cửa sổ 24 giờ gần nhất, mọi hunt
  python3 detections/hunt.py --since 2026-11-21T06:00:00Z --only H1,H2
  python3 detections/hunt.py --expect H1,H5 --expect-none H3   (mã thoát = số kỳ vọng không đạt)
"""
import argparse
import datetime as dt
import glob
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "telemetry"))
from chain_check import check as chain_check, loads, canon, ts as parse_ts  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)


def search(index, body):
    r = subprocess.run(
        ["docker", "compose", "exec", "-T", "opensearch", "curl", "-s", "-H", "Content-Type: application/json",
         "http://127.0.0.1:9200/%s/_search" % index, "--data-binary", "@-"],
        input=json.dumps(body).encode(), capture_output=True, check=True, cwd=os.path.join(HERE, ".."))
    res = json.loads(r.stdout.decode("utf-8"))
    if "error" in res:
        if res.get("status") == 404:
            return {"hits": {"hits": [], "total": {"value": 0}}, "aggregations": {}}
        raise RuntimeError("OpenSearch: %s" % json.dumps(res["error"])[:300])
    return res


def window(q, since, field="event_time"):
    return {"bool": {"filter": [q, {"range": {field: {"gte": since}}}]}}


def nested_terms(fields, leaf):
    """terms lồng nhau theo fields; trường thiếu → "∅" (vẫn đếm)."""
    agg = leaf
    for f in reversed(fields):
        agg = {"g": {"terms": {"field": f, "size": 50, "missing": "∅"}, "aggs": agg}}
    return agg


def leaf_aggs():
    return {"first": {"min": {"field": "event_time"}}, "last": {"max": {"field": "event_time"}}}


def ts(v):
    return v.get("value_as_string", "") if isinstance(v, dict) else ""


def part_terms(p, ctx):
    res = search(ctx.index, {"size": 0, "query": window(p["query"], ctx.since), "aggs": nested_terms(p["group_by"], leaf_aggs())})
    out = []
    for key, b in _walk(res, p["group_by"]):
        if b["doc_count"] >= p.get("threshold", 1):
            out.append({"group": dict(zip(p["group_by"], key)), "count": b["doc_count"],
                        "first": ts(b["first"]), "last": ts(b["last"])})
    return out


def _walk(res, fields):
    aggs = res.get("aggregations") or {}
    if "g" not in aggs:
        return []
    out = []

    def rec(a, path):
        for b in a["g"]["buckets"]:
            key = path + (b["key"],)
            if len(key) == len(fields):
                out.append((key, b))
            else:
                rec(b, key)
    rec(aggs, ())
    return out


def part_cardinality(p, ctx):
    leaf = dict(leaf_aggs())
    leaf["n"] = {"cardinality": {"field": p["distinct"]}}
    leaf["vals"] = {"terms": {"field": p["distinct"], "size": 10}}
    res = search(ctx.index, {"size": 0, "query": window(p["query"], ctx.since), "aggs": nested_terms(p["group_by"], leaf)})
    out = []
    for key, b in _walk(res, p["group_by"]):
        if b["n"]["value"] >= p.get("min_distinct", 2):
            out.append({"group": dict(zip(p["group_by"], key)), "count": b["doc_count"],
                        "first": ts(b["first"]), "last": ts(b["last"]),
                        "note": "%s khác nhau: %s" % (p["distinct"], ", ".join(v["key"] for v in b["vals"]["buckets"]))})
    return out


def part_join(p, ctx):
    res = search(ctx.index, {"size": 10000, "_source": [p["key"]], "query": window(p["query"], ctx.since)})
    ids = sorted({h["_source"].get(p["key"]) for h in res["hits"]["hits"] if h["_source"].get(p["key"])})
    if not ids:
        return []
    q2 = {"bool": {"filter": [p["lookup"], {"terms": {p["key"]: ids}}]}}
    res2 = search(ctx.index, {"size": 0, "query": q2, "aggs": nested_terms(p["group_by"], leaf_aggs())})
    out = []
    for key, b in _walk(res2, p["group_by"]):
        if b["doc_count"] >= p.get("threshold", 1):
            out.append({"group": dict(zip(p["group_by"], key)), "count": b["doc_count"],
                        "first": ts(b["first"]), "last": ts(b["last"]),
                        "note": "%d request bị backend từ chối trong cửa sổ (nối qua %s)" % (len(ids), p["key"])})
    return out


def part_admin_then_use(p, ctx):
    res = search(ctx.index, {"size": 500, "sort": [{"event_time": "asc"}], "query": window(p["query"], ctx.since),
                             "_source": ["event_time", "admin_target_hash", "idp_event", "admin_resource_path"]})
    out = []
    for h in res["hits"]["hits"]:
        s = h["_source"]
        tgt = s.get("admin_target_hash")
        if not tgt:
            continue
        q = {"bool": {"filter": [{"term": {"principal_hash": tgt}}, {"range": {"event_time": {"gt": s["event_time"]}}}]}}
        used = search(ctx.index, {"size": 0, "query": q, "aggs": {"t": {"terms": {"field": "event_type"}}}})
        n = used["hits"]["total"]["value"]
        kinds = ", ".join("%s=%d" % (b["key"], b["doc_count"]) for b in used["aggregations"]["t"]["buckets"])
        out.append({"group": {"idp_event": s.get("idp_event"), "admin_target_hash": tgt}, "count": 1,
                    "first": s["event_time"], "last": s["event_time"],
                    "note": "user bị tác động có %d sự kiện SAU thao tác%s" % (n, (" (" + kinds + ")") if kinds else "")})
    return out


def active_epochs(ctx):
    res = search(ctx.index, {"size": 0, "query": window({"exists": {"field": "chain_epoch"}}, ctx.since),
                             "aggs": {"e": {"terms": {"field": "chain_epoch", "size": 100}}}})
    return [b["key"] for b in (res.get("aggregations") or {}).get("e", {}).get("buckets", [])]


def part_seq_gaps(p, ctx):
    out = []
    for ep in active_epochs(ctx):
        res = search(ctx.index, {"size": 0, "query": {"term": {"chain_epoch": ep}},
                                 "aggs": {"lo": {"min": {"field": "chain_seq"}}, "hi": {"max": {"field": "chain_seq"}}}})
        n = res["hits"]["total"]["value"]
        lo, hi = int(res["aggregations"]["lo"]["value"]), int(res["aggregations"]["hi"]["value"])
        if lo != 1 or hi - lo + 1 != n:
            out.append({"group": {"chain_epoch": ep}, "count": (hi - lo + 1) - n + (lo - 1), "first": "", "last": "",
                        "note": "seq %d..%d nhưng chỉ có %d sự kiện — thiếu %d (bị xoá khỏi SIEM?)" % (lo, hi, n, hi - n)})
    return out


def part_digest_freshness(p, ctx):
    res = search(ctx.digest_index, {"size": 0, "aggs": {"last": {"max": {"field": "created_at"}},
                                                         "hi": {"max": {"field": "digest_seq"}}, "lo": {"min": {"field": "digest_seq"}}}})
    n = res["hits"]["total"]["value"]
    out = []
    if n == 0:
        return [{"group": {"digests": "none"}, "count": 0, "first": "", "last": "", "note": "chưa có digest nào"}]
    a = res["aggregations"]
    last = a["last"]["value_as_string"]
    age = (NOW - parse_ts(last)).total_seconds()
    if age > p.get("max_age_s", 600):
        out.append({"group": {"digest": "stale"}, "count": 1, "first": last, "last": last,
                    "note": "digest mới nhất đã %.0f s tuổi (> %d s) — digester/Vault ngừng hoặc digest bị xoá ở cuối" % (age, p.get("max_age_s", 600))})
    lo, hi = int(a["lo"]["value"]), int(a["hi"]["value"])
    if lo != 1 or hi - lo + 1 != n:
        out.append({"group": {"digest": "seq_gap"}, "count": hi - n, "first": "", "last": "",
                    "note": "digest_seq %d..%d nhưng chỉ có %d digest — digest bị xoá" % (lo, hi, n)})
    return out


def export(index, query, sort):
    body = {"size": 2000, "query": query, "sort": [{sort: "asc"}]}
    rows = []
    while True:
        r = subprocess.run(
            ["docker", "compose", "exec", "-T", "opensearch", "curl", "-s", "-H", "Content-Type: application/json",
             "http://127.0.0.1:9200/%s/_search" % index, "--data-binary", "@-"],
            input=json.dumps(body).encode(), capture_output=True, check=True, cwd=os.path.join(HERE, ".."))
        res = loads(r.stdout.decode("utf-8"))  # giữ số nguyên văn để băm lại
        hits = res.get("hits", {}).get("hits", [])
        rows += [h["_source"] for h in hits]
        if len(hits) < 2000:
            return rows
        body["search_after"] = [json.loads(canon(x)) for x in hits[-1]["sort"]]


def pinned_keys():
    keys = set()
    for f in ("siem-digest.json", "siem-digest.history.jsonl"):
        r = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", "topic09-lab_kms-public:/k:ro",
                            "busybox:1.37", "cat", "/k/" + f], capture_output=True)
        if r.returncode != 0:
            continue
        txt = r.stdout.decode()
        if f.endswith(".json"):
            keys |= {k["public_key"] for k in json.loads(txt)["data"]["keys"].values()}
        else:
            keys |= {json.loads(l)["public_key"] for l in txt.splitlines() if l.strip()}
    return keys


def part_chain_verify(p, ctx):
    digests = export(ctx.digest_index, {"match_all": {}}, "digest_seq")
    keys = pinned_keys()
    out = []
    for ep in active_epochs(ctx):
        events = export(ctx.index, {"term": {"chain_epoch": ep}}, "chain_seq")
        covered = [d for d in digests if d["chain_epoch"] == ep]
        last_signed = max((int(d["last_seq"]) for d in covered), default=0)
        # chỉ kiểm phần đã có digest phủ — sự kiện sau digest gần nhất chưa có gì để so
        evs = [e for e in events if int(e["chain_seq"]) <= last_signed] if last_signed else events
        errs = chain_check(evs, digests, keys, only_epoch=ep, quiet=True)
        for e in errs:
            out.append({"group": {"chain_epoch": ep}, "count": 1, "first": "", "last": "", "note": e})
    return out


KINDS = {"terms": part_terms, "cardinality": part_cardinality, "join": part_join,
         "admin_then_use": part_admin_then_use, "seq_gaps": part_seq_gaps,
         "digest_freshness": part_digest_freshness, "chain_verify": part_chain_verify}


class Ctx:
    def __init__(self, index, digest_index, since):
        self.index, self.digest_index, self.since = index, digest_index, since


def main():
    ap = argparse.ArgumentParser(description="Chạy hunt trên SIEM")
    ap.add_argument("--since", help="RFC 3339 UTC; mặc định 24 giờ trước")
    ap.add_argument("--index", default="topic09-events")
    ap.add_argument("--digest-index", default="topic09-digests")
    ap.add_argument("--only", default="", help="H1,H5…")
    ap.add_argument("--expect", default="", help="các hunt BẮT BUỘC có phát hiện")
    ap.add_argument("--expect-none", default="", help="các hunt KHÔNG được có phát hiện")
    ap.add_argument("--json", help="ghi kết quả ra file JSON")
    a = ap.parse_args()
    since = a.since or (NOW - dt.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ctx = Ctx(a.index, a.digest_index, since)
    only = {x for x in a.only.split(",") if x}
    print("Hunt trên index %s, cửa sổ từ %s (bây giờ %s)" % (a.index, since, NOW.strftime("%Y-%m-%dT%H:%M:%SZ")))
    results = {}
    for path in sorted(glob.glob(os.path.join(HERE, "H*.json"))):
        h = json.load(open(path, encoding="utf-8"))
        if only and h["id"] not in only:
            continue
        print("\n%s — %s" % (h["id"], h["name"]))
        print("  giả thuyết: %s" % h["hypothesis"])
        total = 0
        parts = {}
        for p in h["parts"]:
            try:
                f = KINDS[p["kind"]](p, ctx)
            except Exception as e:  # một part lỗi không làm dừng các hunt khác
                print("  [%s] LỖI khi chạy: %s" % (p["name"], e))
                f = []
            parts[p["name"]] = f
            total += len(f)
            print("  [%s] %d phát hiện" % (p["name"], len(f)))
            for x in f[:8]:
                g = ", ".join("%s=%s" % (k, (v[:12] + "…") if isinstance(v, str) and len(v) > 16 and k.endswith(("hash", "jkt")) else v)
                              for k, v in x["group"].items())
                print("      - %s | %d sự kiện%s%s" % (g, x["count"], (" | " + x["first"][:19]) if x.get("first") else "",
                                                     (" | " + x["note"][:150]) if x.get("note") else ""))
            if len(f) > 8:
                print("      … còn %d" % (len(f) - 8))
        results[h["id"]] = {"name": h["name"], "findings": total, "parts": parts, "attack": h.get("attack", [])}
    if a.json:
        json.dump({"since": since, "index": a.index, "results": results}, open(a.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    bad = 0
    print()
    for hid in [x for x in a.expect.split(",") if x]:
        ok = results.get(hid, {}).get("findings", 0) > 0
        bad += 0 if ok else 1
        print("  [%s] %s có phát hiện (%d)" % ("PASS" if ok else "FAIL", hid, results.get(hid, {}).get("findings", 0)))
    for hid in [x for x in a.expect_none.split(",") if x]:
        ok = results.get(hid, {}).get("findings", 0) == 0
        bad += 0 if ok else 1
        print("  [%s] %s không có phát hiện (%d)" % ("PASS" if ok else "FAIL", hid, results.get(hid, {}).get("findings", 0)))
    return bad


if __name__ == "__main__":
    sys.exit(main())
