#!/usr/bin/env python3
"""Đối chiếu sự kiện telemetry với telemetry/schema.json — chỉ dùng thư viện chuẩn của Python.

Ba chế độ:

  self    Kiểm chính file schema: đủ 27 trường của mục 13.1 đề bài (x-core = 1..27, không
          trùng, không thiếu), trường nào cũng có type và description.

  source  Đọc log THÔ của các service từ stdin (mỗi dòng một JSON, như đầu ra của
          `docker compose logs --no-log-prefix`). Kiểm "hợp đồng" giữa nơi sinh log và schema:
            - khoá nào cũng phải có trong schema, hoặc là khoá thô đã khai báo ở "x-raw-only"
              (principal, aud, service, msg… — Vector biến đổi hoặc bỏ);
            - giá trị đúng kiểu / enum / pattern của schema ("" và "-" được coi là null, vì
              Vector đổi chúng thành null);
            - không dòng nào chứa token, khoá hay mã uỷ quyền (SR-10).
          In bảng "trường nào do nguồn nào điền".

  siem    Đọc sự kiện ĐÃ QUA Vector từ stdin (mỗi dòng một JSON). Kiểm nghiêm: đúng schema,
          không khoá lạ (additionalProperties = false), không còn giá trị thô.

  mapping Sinh mapping của OpenSearch từ schema ("dynamic": "strict"). Thêm --write để ghi
          telemetry/opensearch/index-template.json và index-mapping.json.

  sync    Kiểm ba thứ khớp nhau: schema ↔ allow-list trong telemetry/vector/vector.yaml ↔
          hai file mapping đã commit.

Dùng:
  python3 telemetry/schema_check.py self
  docker compose logs --no-log-prefix envoy auth-svc opa orders-api profile-api | \\
      python3 telemetry/schema_check.py source --expect envoy,auth-svc,opa,orders-api,profile-api
  python3 telemetry/schema_check.py siem < events.ndjson

Mã thoát: 0 = đạt, 1 = có lỗi, 2 = dùng sai.
"""
import argparse
import json
import os
import re
import sys

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.json")

# Dấu hiệu bí mật lọt vào log (luật telemetry: scanner phải chạy tự động).
SECRET_PATTERNS = [
    ("JWT (eyJ….…)", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+")),
    ("khoá/chứng chỉ PEM", re.compile(r"-----BEGIN [A-Z0-9 ]*-----")),
    ("mã uỷ quyền (code=…)", re.compile(r"\bcode=[A-Za-z0-9._~-]{6,}")),
    ("header Authorization", re.compile(r"(?i)\b(?:bearer|dpop)\s+[A-Za-z0-9._~+/-]{20,}")),
]

# Trường của schema được SUY RA từ một khoá thô (Vector làm việc này ở tuần 8 T6).
DERIVED_FROM = {
    "principal_hash": "principal",
    "aud_hash": "aud",
    "authn_method": "client_id",
}


def load_schema(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ------------------------------------------------------------------ bộ kiểm JSON Schema tối giản
# Chỉ cài phần schema.json dùng: type, enum, pattern, maxLength, minimum, maximum.


def type_ok(t, v):
    if t == "null":
        return v is None
    if t == "string":
        return isinstance(v, str)
    if t == "boolean":
        return isinstance(v, bool)
    if t == "integer":
        return (isinstance(v, int) and not isinstance(v, bool)) or (isinstance(v, float) and v.is_integer())
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    return False


def check_value(spec, v):
    """Trả danh sách lỗi (rỗng = đúng) của giá trị v theo mô tả spec của một trường."""
    types = spec.get("type", [])
    types = [types] if isinstance(types, str) else types
    if types and not any(type_ok(t, v) for t in types):
        return ["kiểu %s, muốn %s" % (type(v).__name__, "/".join(types))]
    errs = []
    if "enum" in spec and v not in spec["enum"]:
        errs.append("giá trị %r không nằm trong enum" % (v,))
    if isinstance(v, str):
        if "pattern" in spec and not re.search(spec["pattern"], v):
            errs.append("giá trị %r không khớp pattern %s" % (v[:60], spec["pattern"]))
        if "maxLength" in spec and len(v) > spec["maxLength"]:
            errs.append("dài %d > maxLength %d" % (len(v), spec["maxLength"]))
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        if "minimum" in spec and v < spec["minimum"]:
            errs.append("%r < minimum %r" % (v, spec["minimum"]))
        if "maximum" in spec and v > spec["maximum"]:
            errs.append("%r > maximum %r" % (v, spec["maximum"]))
    return errs


def scan_secrets(line):
    return [name for name, rx in SECRET_PATTERNS if rx.search(line)]


# ------------------------------------------------------------------ chế độ self


def mode_self(schema):
    props = schema.get("properties", {})
    errs = []
    core = {}
    for name, spec in props.items():
        if "type" not in spec:
            errs.append("%s: thiếu type" % name)
        if not spec.get("description"):
            errs.append("%s: thiếu description" % name)
        if "pattern" in spec:
            try:
                re.compile(spec["pattern"])
            except re.error as e:
                errs.append("%s: pattern hỏng (%s)" % (name, e))
        if "x-core" in spec:
            if spec["x-core"] in core:
                errs.append("x-core %d bị trùng: %s và %s" % (spec["x-core"], core[spec["x-core"]], name))
            core[spec["x-core"]] = name
    missing = [i for i in range(1, 28) if i not in core]
    if missing or len(core) != 27:
        errs.append("phải có đúng 27 trường core (x-core 1..27); thiếu số %s, đang có %d" % (missing, len(core)))
    if schema.get("additionalProperties") is not False:
        errs.append("additionalProperties phải là false (schema là allow-list, SR-10)")
    for r in schema.get("required", []):
        if r not in props:
            errs.append("required %r không có trong properties" % r)

    print("Schema %s, phiên bản %s" % (schema.get("$id"), schema.get("x-schema-version")))
    print("  %d trường: %d core (mục 13.1 đề bài) + %d mở rộng" % (len(props), len(core), len(props) - len(core)))
    by_status = {}
    for i in sorted(core):
        by_status.setdefault(props[core[i]].get("x-status", "?"), []).append(core[i])
    for st in sorted(by_status):
        print("  core / %-12s %2d: %s" % (st, len(by_status[st]), ", ".join(by_status[st])))
    for e in errs:
        print("  [LỖI] " + e)
    print("Kết quả self: %s" % ("ĐẠT" if not errs else "%d lỗi" % len(errs)))
    return 1 if errs else 0


# ------------------------------------------------------------------ chế độ source


def flatten_opa(d):
    """Đổi một dòng decision log của OPA sang các trường phẳng của schema.

    Đây cũng là bảng ánh xạ mà Vector dùng (policy/README.md, mục "Decision log → SIEM").
    """
    inp = d.get("input") or {}
    sub = inp.get("subject") or {}
    res = d.get("result") or {}
    roles = sub.get("roles")
    ev = {
        "service": "opa",
        "event_time": d.get("timestamp"),
        "opa_decision_id": d.get("decision_id"),
        "decision": {True: "allow", False: "deny"}.get(res.get("allow")),
        "decision_reason": res.get("reason"),
        "policy_id": res.get("policy_id"),
        "policy_version": res.get("policy_version"),
        "policy_route": res.get("route"),
        "route_template": res.get("route_template"),
        "method": inp.get("method"),
        "principal": sub.get("sub"),
        "client_id": sub.get("client_id"),
        "subject_roles": ",".join(sorted(roles)) if isinstance(roles, list) else None,
        "subject_dept": sub.get("dept"),
        "subject_tier": sub.get("tier"),
    }
    ns = (d.get("metrics") or {}).get("timer_rego_query_eval_ns")
    ev["policy_eval_us"] = ns // 1000 if isinstance(ns, int) else None
    problems = []
    if "path" in inp:
        problems.append("input.path CÒN trong decision log (log_mask.rego không chạy?) — SR-10")
    if "/input/path" not in (d.get("erased") or []):
        problems.append('thiếu "/input/path" trong erased')
    return ev, problems


def classify(d):
    """Trả (nguồn, sự kiện phẳng, lỗi riêng) hoặc None nếu dòng không phải sự kiện bảo mật."""
    if "decision_id" in d and "result" in d:
        ev, problems = flatten_opa(d)
        return "opa", ev, problems
    svc = d.get("service")
    if svc == "envoy":
        return "envoy", d, []
    if svc == "auth-svc" and d.get("msg") == "authz_decision":
        return "auth-svc", d, []
    if svc in ("orders-api", "profile-api") and d.get("msg") == "request":
        return svc, d, []
    return None


def mode_source(schema, expect, show_max):
    props = schema["properties"]
    raw_only = set(schema.get("x-raw-only", {}).get("fields", {}))
    seen = {}  # nguồn → số sự kiện
    filled = {}  # trường → tập nguồn có giá trị khác null
    errors = []
    lines = events = skipped = 0
    secret_hits = bare_eyj = 0

    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        lines += 1
        hits = scan_secrets(raw)
        if hits:
            secret_hits += 1
            errors.append("dòng %d: có dấu hiệu bí mật — %s" % (lines, ", ".join(hits)))
        bare_eyj += raw.count("eyJ")
        if not raw.startswith("{"):
            skipped += 1
            continue
        try:
            d = json.loads(raw)
        except ValueError:
            skipped += 1
            continue
        c = classify(d)
        if c is None:
            skipped += 1
            continue
        src, ev, problems = c
        events += 1
        seen[src] = seen.get(src, 0) + 1
        for p in problems:
            errors.append("dòng %d (%s): %s" % (lines, src, p))
        if not ev.get("event_time"):
            errors.append("dòng %d (%s): thiếu event_time" % (lines, src))
        for k, v in ev.items():
            if v in ("", "-"):  # Vector đổi "" và "-" thành null
                v = None
            if k in raw_only:
                if v is not None and k in DERIVED_FROM.values():
                    for target, origin in DERIVED_FROM.items():
                        if origin == k:
                            filled.setdefault(target, set()).add(src)
                continue
            if k not in props:
                errors.append("dòng %d (%s): khoá %r không có trong schema" % (lines, src, k))
                continue
            if v is None:
                types = props[k].get("type", [])
                types = [types] if isinstance(types, str) else types
                if "null" not in types:
                    errors.append("dòng %d (%s): %s rỗng nhưng schema không cho null" % (lines, src, k))
                continue
            for e in check_value(props[k], v):
                errors.append("dòng %d (%s): %s — %s" % (lines, src, k, e))
            filled.setdefault(k, set()).add(src)
            if k in DERIVED_FROM.values():  # client_id vừa là trường, vừa là gốc của authn_method
                for target, origin in DERIVED_FROM.items():
                    if origin == k:
                        filled.setdefault(target, set()).add(src)

    for s in expect:
        if s not in seen:
            errors.append("không có sự kiện nào từ nguồn %r" % s)

    core = sorted((spec["x-core"], name, spec) for name, spec in props.items() if "x-core" in spec)
    print("Đã đọc %d dòng: %d sự kiện bảo mật, %d dòng khác (log vận hành, không vào SIEM)" % (lines, events, skipped))
    print("Sự kiện theo nguồn: " + ", ".join("%s=%d" % kv for kv in sorted(seen.items())))
    print()
    print("Trường core (mục 13.1 đề bài) — nguồn nào điền:")
    print("  %2s  %-22s %-13s %s" % ("#", "trường", "trạng thái", "nguồn có giá trị"))
    for n, name, spec in core:
        srcs = sorted(filled.get(name, ()))
        status = spec.get("x-status", "?")
        note = ", ".join(srcs) if srcs else "—"
        if name in DERIVED_FROM and srcs:
            note += "   (suy từ %s ở Vector)" % DERIVED_FROM[name]
        if status == "week8" and not srcs:
            errors.append("trường core %s (tuần 8) không được nguồn nào điền" % name)
            note = "KHÔNG CÓ NGUỒN NÀO"
        print("  %2d  %-22s %-13s %s" % (n, name, status, note))
    ext = sorted(name for name, spec in props.items() if "x-core" not in spec and filled.get(name))
    print()
    print("Trường mở rộng đã thấy: " + ", ".join("%s[%s]" % (n, ",".join(sorted(filled[n]))) for n in ext))
    print()
    print("Quét bí mật trên %d dòng thô: %d dòng có dấu hiệu token/khoá/mã uỷ quyền; chuỗi 'eyJ' xuất hiện %d lần" % (lines, secret_hits, bare_eyj))
    if bare_eyj and not secret_hits:
        errors.append("có chuỗi 'eyJ' trong log (%d lần) — kiểm bằng mắt xem có phải mảnh token" % bare_eyj)
    for e in errors[:show_max]:
        print("  [LỖI] " + e)
    if len(errors) > show_max:
        print("  … còn %d lỗi nữa" % (len(errors) - show_max))
    print("Kết quả source: %s" % ("ĐẠT" if not errors else "%d lỗi" % len(errors)))
    return 1 if errors else 0


# ------------------------------------------------------------------ chế độ siem


def mode_siem(schema, expect, show_max):
    props = schema["properties"]
    required = schema.get("required", [])
    raw_only = set(schema.get("x-raw-only", {}).get("fields", {}))
    errors = []
    seen = {}
    filled = {}
    n = 0
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        n += 1
        hits = scan_secrets(raw)
        if hits:
            errors.append("sự kiện %d: có dấu hiệu bí mật — %s" % (n, ", ".join(hits)))
        try:
            ev = json.loads(raw)
        except ValueError:
            errors.append("sự kiện %d: không phải JSON" % n)
            continue
        src = ev.get("source", "?")
        seen[src] = seen.get(src, 0) + 1
        for r in required:
            if ev.get(r) is None:
                errors.append("sự kiện %d (%s): thiếu trường bắt buộc %s" % (n, src, r))
        for k, v in ev.items():
            if k in raw_only:
                errors.append("sự kiện %d (%s): còn khoá thô %r — Vector phải bỏ/băm trước khi vào SIEM" % (n, src, k))
            elif k not in props:
                errors.append("sự kiện %d (%s): khoá %r không có trong schema" % (n, src, k))
            else:
                for e in check_value(props[k], v):
                    errors.append("sự kiện %d (%s): %s — %s" % (n, src, k, e))
                if v is not None:
                    filled.setdefault(k, set()).add(src)
    for s in expect:
        if s not in seen:
            errors.append("không có sự kiện nào từ nguồn %r" % s)

    print("Đã đọc %d sự kiện. Theo nguồn: %s" % (n, ", ".join("%s=%d" % kv for kv in sorted(seen.items())) or "(không có)"))
    print()
    print("Trường core (mục 13.1 đề bài) — nguồn nào có giá trị trong SIEM:")
    for num, name, spec in sorted((s["x-core"], k, s) for k, s in props.items() if "x-core" in s):
        srcs = sorted(filled.get(name, ()))
        status = spec.get("x-status", "?")
        if status == "week8" and not srcs:
            errors.append("trường core %s (tuần 8) không có giá trị ở sự kiện nào" % name)
        print("  %2d  %-22s %-13s %s" % (num, name, status, ", ".join(srcs) if srcs else "—"))
    for e in errors[:show_max]:
        print("  [LỖI] " + e)
    if len(errors) > show_max:
        print("  … còn %d lỗi nữa" % (len(errors) - show_max))
    print("Kết quả siem: %s" % ("ĐẠT" if not errors else "%d lỗi" % len(errors)))
    return 1 if errors else 0


# ------------------------------------------------------------------ chế độ mapping / sync

INDEX_NAME = "topic09-events"
TELEMETRY_DIR = os.path.dirname(os.path.abspath(__file__))


def build_mapping(schema):
    """Mapping của OpenSearch sinh từ schema — không viết tay, để hai bên không lệch nhau.

    "dynamic": "strict": OpenSearch TỪ CHỐI tài liệu có trường không khai báo. Đây là lớp chặn
    thứ hai sau allow-list của Vector (SR-10): kể cả khi cấu hình Vector bị sửa sai, một trường
    lạ kiểu "authorization" cũng không vào được index.
    """
    props = {}
    for name, spec in schema["properties"].items():
        types = spec.get("type", [])
        types = [types] if isinstance(types, str) else types
        if name == "event_time":
            # date_nanos giữ được 9 chữ số phần giây (log Go ghi tới nano giây).
            props[name] = {"type": "date_nanos", "format": "strict_date_optional_time_nanos"}
        elif "boolean" in types:
            props[name] = {"type": "boolean"}
        elif "integer" in types:
            props[name] = {"type": "long"}
        elif "number" in types:
            props[name] = {"type": "double"}
        else:
            # keyword: so khớp nguyên văn, đếm/gom nhóm được (hunt cần terms aggregation),
            # không tách từ như kiểu text.
            props[name] = {"type": "keyword", "ignore_above": 512}
    return {"dynamic": "strict", "properties": props}


def build_template(schema):
    return {
        "index_patterns": [INDEX_NAME + "*"],
        "priority": 100,
        "template": {
            # Một node: 1 shard, 0 bản sao (có bản sao thì cluster luôn "yellow").
            "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
            "mappings": build_mapping(schema),
        },
        "_meta": {
            "description": "Sinh tu telemetry/schema.json bang `make siem-mapping` - KHONG sua tay.",
            "schema_version": schema.get("x-schema-version"),
        },
    }


def dump(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def mode_mapping(schema, write):
    files = {
        os.path.join(TELEMETRY_DIR, "opensearch", "index-template.json"): dump(build_template(schema)),
        os.path.join(TELEMETRY_DIR, "opensearch", "index-mapping.json"): dump(build_mapping(schema)),
    }
    if not write:
        sys.stdout.write(dump(build_template(schema)))
        return 0
    for path, text in files.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print("đã ghi %s (%d trường)" % (os.path.relpath(path), len(schema["properties"])))
    return 0


def vrl_lists(text, var):
    """Trả mọi danh sách chuỗi gán cho biến `var` trong các chương trình VRL của vector.yaml."""
    out = []
    for m in re.finditer(r"\b%s\s*=\s*\[(.*?)\]" % re.escape(var), text, re.S):
        out.append(re.findall(r'"([^"]+)"', m.group(1)))
    return out


def mode_sync(schema):
    """Ba thứ phải khớp nhau: schema ↔ allow-list của Vector ↔ mapping của OpenSearch."""
    props = set(schema["properties"])
    raw_only = set(schema.get("x-raw-only", {}).get("fields", {}))
    errs = []

    vector_yaml = os.path.join(TELEMETRY_DIR, "vector", "vector.yaml")
    try:
        text = open(vector_yaml, encoding="utf-8").read()
    except OSError as e:
        errs.append("không đọc được %s: %s" % (vector_yaml, e))
        text = ""
    allowed = vrl_lists(text, "allowed")
    if len(allowed) != 1:
        errs.append("vector.yaml phải có đúng một danh sách `allowed = [...]` (bước seal), thấy %d" % len(allowed))
    else:
        a = set(allowed[0])
        if a - props:
            errs.append("allow-list của Vector có trường KHÔNG có trong schema: %s" % sorted(a - props))
        if props - a:
            errs.append("schema có trường mà allow-list của Vector thiếu (sẽ bị bỏ ở seal): %s" % sorted(props - a))
        if a & raw_only:
            errs.append("allow-list của Vector chứa khoá thô: %s" % sorted(a & raw_only))
        print("  allow-list của Vector (seal): %d trường, schema: %d trường" % (len(a), len(props)))
    keeps = vrl_lists(text, "keep")
    for k in keeps:
        bad = set(k) - props - raw_only
        if bad:
            errs.append("một danh sách `keep` trong vector.yaml có trường lạ: %s" % sorted(bad))
    print("  danh sách `keep` của các bước norm_*: %d danh sách, đều nằm trong schema ∪ khoá thô" % len(keeps))

    for fname, want in (("index-template.json", build_template(schema)), ("index-mapping.json", build_mapping(schema))):
        path = os.path.join(TELEMETRY_DIR, "opensearch", fname)
        try:
            have = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError) as e:
            errs.append("không đọc được %s (%s) — chạy `make siem-mapping`" % (fname, e))
            continue
        if have != want:
            errs.append("%s không khớp schema — chạy `make siem-mapping` để sinh lại" % fname)
        else:
            print("  %s khớp schema" % fname)
    m = build_mapping(schema)
    if m.get("dynamic") != "strict":
        errs.append('mapping phải có "dynamic": "strict"')
    for e in errs:
        print("  [LỖI] " + e)
    print("Kết quả sync: %s" % ("ĐẠT" if not errs else "%d lỗi" % len(errs)))
    return 1 if errs else 0


def main():
    ap = argparse.ArgumentParser(description="Đối chiếu telemetry với telemetry/schema.json")
    ap.add_argument("mode", choices=["self", "source", "siem", "mapping", "sync"])
    ap.add_argument("--write", action="store_true", help="mapping: ghi telemetry/opensearch/*.json thay vì in ra")
    ap.add_argument("--schema", default=SCHEMA_PATH)
    ap.add_argument("--expect", default="", help="danh sách nguồn bắt buộc phải có sự kiện, cách nhau bằng dấu phẩy")
    ap.add_argument("--show", type=int, default=30, help="số lỗi tối đa in ra")
    a = ap.parse_args()
    try:
        schema = load_schema(a.schema)
    except (OSError, ValueError) as e:
        print("không đọc được schema: %s" % e, file=sys.stderr)
        return 2
    expect = [s for s in a.expect.split(",") if s]
    if a.mode == "self":
        return mode_self(schema)
    if a.mode == "mapping":
        return mode_mapping(schema, a.write)
    if a.mode == "sync":
        return mode_sync(schema)
    if a.mode == "source":
        return mode_source(schema, expect, a.show)
    return mode_siem(schema, expect, a.show)


if __name__ == "__main__":
    sys.exit(main())
