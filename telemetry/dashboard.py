#!/usr/bin/env python3
"""Sinh dashboard SIEM TĨNH (một file HTML tự chứa) — tuần 9 T6, thay cho OpenSearch Dashboards.

Vì sao tĩnh (người dùng chọn 21/11): OpenSearch không có tài khoản; mở OpenSearch Dashboards ra
host thì mọi tiến trình trên máy đọc/sửa/xoá được log qua Dev Tools — đi ngược luật "chỉ Envoy và
Keycloak có cổng". File HTML này chỉ chứa SỐ ĐẾM đã gom (không có sự kiện thô, không có hash định
danh), sinh lại được bất cứ lúc nào: `make siem-dashboard`.

Màu: bảng màu tham chiếu của skill dataviz (ô 1 xanh, ô 2 cam), đã chạy validate_palette cho cả
chế độ sáng và tối (21/11, đạt mọi kiểm tra). Chỉ thư viện chuẩn Python; trang không tải gì từ mạng.

  python3 telemetry/dashboard.py --since 2026-11-21T00:00:00Z --hunts hunts.json --out docs/evidence/siem-dashboard.html
"""
import argparse
import datetime as dt
import html
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "detections"))
from hunt import search  # noqa: E402  (hunt.py tự thêm telemetry/ vào sys.path)
from chain_check import ts as parse_ts  # noqa: E402

E = html.escape


def q_window(since, *filters):
    return {"bool": {"filter": [{"range": {"event_time": {"gte": since}}}] + list(filters)}}


def collect(since):
    d = {}
    r = search("topic09-events", {"size": 0, "track_total_hits": True, "query": q_window(since),
                                  "aggs": {"src": {"terms": {"field": "source", "size": 20}},
                                           "epochs": {"cardinality": {"field": "chain_epoch"}}}})
    d["total"] = r["hits"]["total"]["value"]
    d["by_source"] = [(b["key"], b["doc_count"]) for b in r["aggregations"]["src"]["buckets"]]
    d["epochs"] = r["aggregations"]["epochs"]["value"]
    r = search("topic09-events", {"size": 0, "query": q_window(since, {"term": {"source": "envoy"}}),
                                  "aggs": {"p": {"terms": {"field": "profile", "size": 5},
                                                 "aggs": {"d": {"terms": {"field": "decision", "size": 3}}}}}})
    d["by_profile"] = {b["key"]: {x["key"]: x["doc_count"] for x in b["d"]["buckets"]} for b in r["aggregations"]["p"]["buckets"]}
    r = search("topic09-events", {"size": 0, "query": q_window(since, {"exists": {"field": "decision"}}),
                                  "aggs": {"h": {"date_histogram": {"field": "event_time", "fixed_interval": "5m", "min_doc_count": 0},
                                                 "aggs": {"d": {"terms": {"field": "decision", "size": 3}}}}}})
    d["timeline"] = [(b["key_as_string"], {x["key"]: x["doc_count"] for x in b["d"]["buckets"]}) for b in r["aggregations"]["h"]["buckets"]]
    r = search("topic09-events", {"size": 0, "query": q_window(since, {"term": {"decision": "deny"}}),
                                  "aggs": {"s": {"terms": {"field": "source", "size": 10},
                                                 "aggs": {"r": {"terms": {"field": "decision_reason", "size": 5}}}}}})
    d["deny"] = sorted(((b["key"], x["key"], x["doc_count"]) for b in r["aggregations"]["s"]["buckets"] for x in b["r"]["buckets"]),
                       key=lambda t: -t[2])[:12]
    r = search("topic09-events", {"size": 0, "query": q_window(since, {"term": {"source": "vault"}}),
                                  "aggs": {"c": {"terms": {"field": "kms_client", "size": 10, "missing": "—"},
                                                 "aggs": {"p": {"terms": {"field": "kms_policies", "size": 1}},
                                                          "d": {"terms": {"field": "decision", "size": 3}},
                                                          "t": {"sum": {"field": "kms_calls"}}}}}})
    d["kms"] = [(b["key"], (b["p"]["buckets"] or [{"key": "—"}])[0]["key"],
                 {x["key"]: x["doc_count"] for x in b["d"]["buckets"]}, int(b["t"]["value"])) for b in r["aggregations"]["c"]["buckets"]]
    r = search("topic09-digests", {"size": 10, "track_total_hits": True, "sort": [{"digest_seq": "desc"}],
                                   "_source": ["digest_seq", "chain_epoch", "first_seq", "last_seq", "gaps", "key_version", "created_at"]})
    d["digests_total"] = r["hits"]["total"]["value"]
    d["digests"] = [h["_source"] for h in r["hits"]["hits"]]
    return d


# ------------------------------------------------------------------ vẽ (SVG thuần)

def hbar_chart(rows, width=560, bar=18, gap=10, label_w=110, unit="sự kiện"):
    """Cột ngang một dãy số liệu: nhãn trái, giá trị ở đầu cột (nhãn trực tiếp chọn lọc)."""
    mx = max((v for _, v in rows), default=1) or 1
    plot = width - label_w - 60
    h = len(rows) * (bar + gap) + gap
    out = ['<svg class="chart" viewBox="0 0 %d %d" role="img" aria-label="cột ngang">' % (width, h)]
    out.append('<line class="axis" x1="%d" y1="0" x2="%d" y2="%d"/>' % (label_w, label_w, h))
    for i, (k, v) in enumerate(rows):
        y = gap + i * (bar + gap)
        w = max(2, plot * v / mx)
        out.append('<text class="lbl" x="%d" y="%d" text-anchor="end">%s</text>' % (label_w - 8, y + bar * 0.72, E(k)))
        out.append(bar_end(label_w, y, w, bar, "s1", "%s: %d %s" % (k, v, unit)))
        out.append('<text class="val" x="%d" y="%d">%d</text>' % (label_w + w + 6, y + bar * 0.72, v))
    out.append("</svg>")
    return "".join(out)


def bar_end(x, y, w, h, cls, tip):
    """Cột có đầu dữ liệu bo 4px, đầu gốc (sát trục) vuông."""
    r = min(4, w / 2)
    path = "M%.1f,%.1f h%.1f a%.1f,%.1f 0 0 1 %.1f,%.1f v%.1f a%.1f,%.1f 0 0 1 %.1f,%.1f h%.1f z" % (
        x, y, w - r, r, r, r, r, h - 2 * r, r, r, -r, r, -(w - r))
    return '<path class="%s mark" d="%s" data-tip="%s"/>' % (cls, path, E(tip))


def stacked_hbar(rows, series, width=560, bar=22, gap=14, label_w=110):
    """Cột ngang chồng 2 dãy (allow/deny), khe 2px màu nền giữa hai đoạn, đầu ngoài bo 4px."""
    mx = max((sum(v.get(s, 0) for s, _ in series) for _, v in rows), default=1) or 1
    plot = width - label_w - 60
    h = len(rows) * (bar + gap) + gap
    out = ['<svg class="chart" viewBox="0 0 %d %d" role="img" aria-label="cột chồng">' % (width, h)]
    out.append('<line class="axis" x1="%d" y1="0" x2="%d" y2="%d"/>' % (label_w, label_w, h))
    for i, (k, v) in enumerate(rows):
        y = gap + i * (bar + gap)
        x = label_w
        total = sum(v.get(s, 0) for s, _ in series)
        out.append('<text class="lbl" x="%d" y="%d" text-anchor="end">%s</text>' % (label_w - 8, y + bar * 0.7, E(k)))
        segs = [(s, cls, v.get(s, 0)) for s, cls in series if v.get(s, 0) > 0]
        for j, (s, cls, n) in enumerate(segs):
            w = max(2, plot * n / mx)
            last = j == len(segs) - 1
            tip = "%s — %s: %d / %d" % (k, s, n, total)
            if last:
                out.append(bar_end(x, y, w, bar, cls, tip))
            else:
                out.append('<rect class="%s mark" x="%.1f" y="%d" width="%.1f" height="%d" data-tip="%s"/>' % (cls, x, y, max(1, w - 2), bar, E(tip)))
            if w > 34:
                out.append('<text class="inlbl" x="%.1f" y="%d" text-anchor="middle">%d</text>' % (x + (w - 2) / 2, y + bar * 0.7, n))
            x += w
        out.append('<text class="val" x="%.1f" y="%d">%d</text>' % (x + 6, y + bar * 0.7, total))
    out.append("</svg>")
    return "".join(out)


def stacked_columns(buckets, series, width=760, height=200):
    """Cột đứng chồng theo thời gian (mỗi cột 5 phút), trục y một thang, lưới mờ."""
    left, bottom, top = 40, 24, 8
    n = max(1, len(buckets))
    plot_w, plot_h = width - left - 8, height - bottom - top
    mx = max((sum(v.get(s, 0) for s, _ in series) for _, v in buckets), default=1) or 1
    step = plot_w / n
    bw = max(3, min(18, step - 2))
    out = ['<svg class="chart" viewBox="0 0 %d %d" role="img" aria-label="cột theo thời gian">' % (width, height)]
    for frac in (0.5, 1.0):
        gy = top + plot_h * (1 - frac)
        out.append('<line class="grid" x1="%d" y1="%.1f" x2="%d" y2="%.1f"/>' % (left, gy, width - 8, gy))
        out.append('<text class="tick" x="%d" y="%.1f" text-anchor="end">%d</text>' % (left - 6, gy + 4, round(mx * frac)))
    base = top + plot_h
    out.append('<line class="axis" x1="%d" y1="%.1f" x2="%d" y2="%.1f"/>' % (left, base, width - 8, base))
    label_every = max(1, n // 6)
    for i, (t, v) in enumerate(buckets):
        x = left + i * step + (step - bw) / 2
        y = base
        segs = [(s, cls, v.get(s, 0)) for s, cls in series if v.get(s, 0) > 0]
        total = sum(c for _, _, c in segs)
        hhmm = t[11:16]
        for j, (s, cls, c) in enumerate(segs):
            hgt = plot_h * c / mx
            tip = "%s UTC — %s: %d (tổng %d)" % (hhmm, s, c, total)
            if j == len(segs) - 1:
                r = min(4, bw / 2, hgt / 2)
                path = "M%.1f,%.1f v%.1f a%.1f,%.1f 0 0 1 %.1f,%.1f h%.1f a%.1f,%.1f 0 0 1 %.1f,%.1f v%.1f z" % (
                    x, y, -(hgt - r), r, r, r, -r, bw - 2 * r, r, r, r, r, hgt - r)
                out.append('<path class="%s mark" d="%s" data-tip="%s"/>' % (cls, path, E(tip)))
            else:
                out.append('<rect class="%s mark" x="%.1f" y="%.1f" width="%.1f" height="%.1f" data-tip="%s"/>' % (cls, x, y - hgt + 2, bw, max(1, hgt - 2), E(tip)))
            y -= hgt
        if i % label_every == 0:
            out.append('<text class="tick" x="%.1f" y="%d" text-anchor="middle">%s</text>' % (x + bw / 2, height - 6, E(hhmm)))
    out.append("</svg>")
    return "".join(out)


def legend(series):
    return '<div class="legend">' + "".join('<span><i class="sw %s"></i>%s</span>' % (cls, E(name)) for name, cls in series) + "</div>"


def table(headers, rows, num_cols=()):
    h = "".join("<th%s>%s</th>" % (' class="num"' if i in num_cols else "", E(x)) for i, x in enumerate(headers))
    b = "".join("<tr>" + "".join("<td%s>%s</td>" % (' class="num"' if i in num_cols else "", c) for i, c in enumerate(r)) + "</tr>" for r in rows)
    return "<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>" % (h, b)


def ago(ts_str, now):
    s = (now - parse_ts(ts_str)).total_seconds()
    return "%d giây trước" % s if s < 90 else "%d phút trước" % (s // 60) if s < 5400 else "%.1f giờ trước" % (s / 3600)


CSS = """
.viz-root{color-scheme:light;--surface-1:#fcfcfb;--page:#f9f9f7;--text-primary:#0b0b0b;--text-secondary:#52514e;--muted:#898781;
--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);--series-1:#2a78d6;--series-2:#eb6834;--good:#0ca30c;--critical:#d03b3b}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])) .viz-root{color-scheme:dark;--surface-1:#1a1a19;--page:#0d0d0d;
--text-primary:#f0efec;--text-secondary:#c3c2b7;--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--series-1:#3987e5;--series-2:#d95926}}
:root[data-theme="dark"] .viz-root{color-scheme:dark;--surface-1:#1a1a19;--page:#0d0d0d;--text-primary:#f0efec;--text-secondary:#c3c2b7;
--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--series-1:#3987e5;--series-2:#d95926}
*{box-sizing:border-box}html,body{margin:0}
body.viz-root{background:var(--page);color:var(--text-primary);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;padding:24px 16px}
main{max-width:1080px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:0 0 10px}
.sub{color:var(--text-secondary);margin:0 0 20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.tile,.card{background:var(--surface-1);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.tile .k{color:var(--text-secondary);font-size:12px}.tile .v{font-size:26px;font-weight:600;margin-top:2px}
.tile .note{color:var(--muted);font-size:12px}
.status{display:inline-flex;align-items:center;gap:6px;font-weight:600}
.status .dot{width:16px;height:16px;border-radius:50%;display:inline-grid;place-items:center;color:#fff;font-size:11px}
.ok .dot{background:var(--good)}.bad .dot{background:var(--critical)}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,460px),1fr));gap:12px;margin-bottom:12px}
.card{margin-bottom:12px;overflow-x:auto}.chart{width:100%;height:auto;display:block}
.chart text{fill:var(--text-secondary);font-size:12px}.chart .tick{fill:var(--muted);font-size:11px;font-variant-numeric:tabular-nums}
.chart .val{fill:var(--text-primary);font-size:12px;font-variant-numeric:tabular-nums}.chart .inlbl{fill:#fff;font-size:11px;font-weight:600}
.chart .grid{stroke:var(--grid);stroke-width:1}.chart .axis{stroke:var(--axis);stroke-width:1}
.s1{fill:var(--series-1)}.s2{fill:var(--series-2)}.mark{cursor:default}.mark:hover{opacity:.85}
.legend{display:flex;gap:16px;color:var(--text-secondary);font-size:12px;margin:0 0 6px}
.sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px}
.sw.s1{background:var(--series-1)}.sw.s2{background:var(--series-2)}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--grid);vertical-align:top}
th{color:var(--text-secondary);font-weight:600}td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
code{font-size:12px;color:var(--text-secondary)}details{margin-top:8px;color:var(--text-secondary)}summary{cursor:pointer;font-size:12px}
#tip{position:fixed;pointer-events:none;background:var(--text-primary);color:var(--surface-1);padding:4px 8px;border-radius:6px;font-size:12px;display:none;z-index:9}
footer{color:var(--muted);font-size:12px;margin-top:16px}
"""

JS = """
const tip=document.getElementById('tip');
document.querySelectorAll('[data-tip]').forEach(m=>{
  m.addEventListener('mousemove',e=>{tip.textContent=m.dataset.tip;tip.style.display='block';
    tip.style.left=Math.min(e.clientX+12,innerWidth-tip.offsetWidth-8)+'px';tip.style.top=(e.clientY+12)+'px';});
  m.addEventListener('mouseleave',()=>{tip.style.display='none';});
});
"""


def render(d, hunts, since, now):
    series = [("allow", "s1"), ("deny", "s2")]
    h9 = hunts.get("results", {}).get("H9", {}).get("parts", {})
    integ_ok = not h9.get("băm lại + kiểm chữ ký digest (phần đã ký)") and not h9.get("thiếu chain_seq trong epoch")
    last = d["digests"][0] if d["digests"] else None
    tiles = [
        ("Sự kiện trong cửa sổ", "{:,}".format(d["total"]).replace(",", " "), "%d nguồn, %d epoch chuỗi" % (len(d["by_source"]), d["epochs"])),
        ("Toàn vẹn log (H9)", '<span class="status %s"><span class="dot">%s</span>%s</span>' % (
            ("ok", "✓", "Khớp") if integ_ok else ("bad", "✗", "Lệch")), "băm lại + chữ ký digest + seq liền mạch"),
        ("Digest đã ký", str(d["digests_total"]), ("mới nhất #%s, %s" % (last["digest_seq"], ago(last["created_at"], now))) if last else "chưa có"),
        ("Hunt có phát hiện", "%d / %d" % (sum(1 for r in hunts.get("results", {}).values() if r["findings"]), len(hunts.get("results", {}))),
         "trong cửa sổ"),
    ]
    tiles_html = "".join('<div class="tile"><div class="k">%s</div><div class="v">%s</div><div class="note">%s</div></div>' % (E(k), v, E(n)) for k, v, n in tiles)

    prof_rows = [(p.upper(), d["by_profile"].get(p, {})) for p in ("p0", "p1", "p2")]
    hunt_rows = []
    for hid, r in sorted(hunts.get("results", {}).items()):
        att = ", ".join("%s %s" % (a["id"], a["name"]) for a in r.get("attack", [])) or "— (không ánh xạ)"
        detail = "; ".join("%s: %d" % (k, len(v)) for k, v in r["parts"].items() if v) or "—"
        hunt_rows.append([E(hid), E(r["name"]), str(r["findings"]), E(att), "<code>%s</code>" % E(detail)])
    deny_rows = [[E(s), "<code>%s</code>" % E(rs), str(n)] for s, rs, n in d["deny"]]
    kms_rows = [[E(c), E(p), str(v.get("allow", 0)), str(v.get("deny", 0)), str(t)] for c, p, v, t in d["kms"]]
    dg_rows = [[str(x["digest_seq"]), "<code>%s</code>" % E(x["chain_epoch"]), "%s–%s" % (x["first_seq"], x["last_seq"]),
                E(", ".join(x.get("gaps") or []) or "—"), "v%s" % x["key_version"], E(x["created_at"][:19].replace("T", " "))] for x in d["digests"]]
    src_tbl = table(["Nguồn", "Sự kiện"], [[E(k), str(v)] for k, v in d["by_source"]], (1,))
    prof_tbl = table(["Profile", "allow", "deny"], [[p, str(v.get("allow", 0)), str(v.get("deny", 0))] for p, v in prof_rows], (1, 2))
    tl_tbl = table(["Khoảng 5 phút (UTC)", "allow", "deny"], [[E(t[11:16]), str(v.get("allow", 0)), str(v.get("deny", 0))] for t, v in d["timeline"]], (1, 2))

    return """<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIEM Topic 09</title><style>%s</style></head>
<body class="viz-root"><main>
<h1>SIEM Topic 09 — tổng quan</h1>
<p class="sub">Cửa sổ từ %s đến %s (UTC) · index <code>topic09-events</code>, <code>topic09-digests</code> · chỉ số đếm đã gom, không có sự kiện thô hay định danh</p>
<section class="tiles">%s</section>
<section class="grid2">
 <div class="card"><h2>Sự kiện theo nguồn</h2>%s<details><summary>Bảng số liệu</summary>%s</details></div>
 <div class="card"><h2>Quyết định ở gateway (Envoy) theo profile</h2>%s%s<details><summary>Bảng số liệu</summary>%s</details></div>
</section>
<section class="card"><h2>Sự kiện có quyết định theo thời gian (5 phút)</h2>%s%s<details><summary>Bảng số liệu</summary>%s</details></section>
<section class="card"><h2>Hunt (detections/H*.json)</h2>%s</section>
<section class="grid2">
 <div class="card"><h2>Lý do từ chối nhiều nhất</h2>%s</div>
 <div class="card"><h2>Thao tác Vault (audit device) theo token</h2>%s</div>
</section>
<section class="card"><h2>Digest gần nhất (ký bằng Vault Transit <code>siem-digest</code>)</h2>%s</section>
<footer>Sinh bởi <code>telemetry/dashboard.py</code> lúc %s UTC. Màu: bảng tham chiếu dataviz, đã kiểm CVD/độ tương phản cho chế độ sáng và tối.</footer>
</main><div id="tip" role="tooltip"></div><script>%s</script></body></html>
""" % (CSS, E(since), E(now.strftime("%Y-%m-%dT%H:%M:%SZ")), tiles_html,
       hbar_chart(d["by_source"]), src_tbl,
       legend(series), stacked_hbar(prof_rows, series), prof_tbl,
       legend(series), stacked_columns(d["timeline"], series), tl_tbl,
       table(["ID", "Hunt", "Phát hiện", "ATT&CK (có bằng chứng)", "Phần có phát hiện"], hunt_rows, (2,)),
       table(["Nguồn", "Lý do", "Số lần"], deny_rows, (2,)),
       table(["Token", "Policy", "allow", "deny", "Lời gọi Transit"], kms_rows, (2, 3, 4)),
       table(["#", "Epoch", "Seq", "Khoảng thiếu", "Khoá", "Lúc ký"], dg_rows, (0,)),
       E(now.strftime("%Y-%m-%d %H:%M:%S")), JS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", required=True)
    ap.add_argument("--hunts", help="file JSON của detections/hunt.py --json")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    now = dt.datetime.now(dt.timezone.utc)
    hunts = json.load(open(a.hunts, encoding="utf-8")) if a.hunts else {}
    page = render(collect(a.since), hunts, a.since, now)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(page)
    print("đã ghi %s (%d byte)" % (a.out, len(page)))


if __name__ == "__main__":
    main()
