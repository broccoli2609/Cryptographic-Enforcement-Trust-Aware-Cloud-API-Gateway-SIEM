#!/usr/bin/env python3
"""Scanner SR-10: tìm thứ KHÔNG ĐƯỢC có trong SIEM và dataset. Chỉ dùng thư viện chuẩn.

Đọc văn bản từ stdin (mỗi dòng một sự kiện JSON, hoặc văn bản bất kỳ) và tìm:

  1. token            chuỗi "eyJ" (mọi JWT đều bắt đầu bằng base64url của '{"')
  2. khoá / chứng chỉ "-----BEGIN"
  3. mã uỷ quyền      "code="
  4. header           "Bearer <chuỗi dài>" / "DPoP <chuỗi dài>"
  5. bí mật của lab   giá trị các biến *PASSWORD*, *KEY*, *SECRET*, *TOKEN* trong .env
                      (gồm khoá HMAC giả danh — lộ khoá này là đoán ngược được principal_hash)
  6. định danh thô    sub (id), username, email của user trong idp/realm-topic09.json —
                      SIEM chỉ được chứa principal_hash

Khi có phát hiện, chỉ in SỐ DÒNG, LOẠI và TÊN TRƯỜNG — không bao giờ in giá trị.

Dùng:
  ./scripts/siem-export.sh | python3 telemetry/secret_scan.py --env .env --realm idp/realm-topic09.json
Mã thoát: 0 = sạch, 1 = có phát hiện, 2 = dùng sai / không đọc được file cấu hình.
"""
import argparse
import json
import re
import sys

FIXED = [
    ("token (eyJ)", re.compile(r"eyJ")),
    ("khoá/chứng chỉ PEM (-----BEGIN)", re.compile(r"-----BEGIN")),
    ("mã uỷ quyền (code=)", re.compile(r"\bcode=")),
    ("header Authorization (Bearer/DPoP …)", re.compile(r"(?i)\b(?:bearer|dpop)\s+[A-Za-z0-9._~+/-]{20,}")),
]
SECRET_NAME = re.compile(r"PASSWORD|KEY|SECRET|TOKEN")


def env_secrets(path):
    """Giá trị các biến bí mật trong .env (bỏ giá trị quá ngắn để khỏi khớp nhầm)."""
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            if SECRET_NAME.search(name) and len(value) >= 8:
                out.append(("giá trị bí mật trong .env: " + name, re.compile(re.escape(value))))
    return out


def realm_identifiers(path):
    """sub, username, email của user trong realm. Username ngắn (bob, dave) phải đứng riêng
    thành từ, để không khớp nhầm một đoạn trong chuỗi base64url."""
    out = []
    with open(path, encoding="utf-8") as f:
        realm = json.load(f)
    for u in realm.get("users", []):
        if u.get("id"):
            out.append(("định danh thô (sub của user)", re.compile(re.escape(u["id"]))))
        for k in ("username", "email"):
            v = u.get(k)
            if v:
                out.append(("định danh thô (%s)" % k, re.compile(r"(?<![A-Za-z0-9_.@-])%s(?![A-Za-z0-9_.@-])" % re.escape(v))))
    return out


def fields_matching(line, rx):
    """Tên các trường (nếu dòng là JSON object) có giá trị khớp; không trả giá trị."""
    try:
        d = json.loads(line)
    except ValueError:
        return []
    if not isinstance(d, dict):
        return []
    return sorted(k for k, v in d.items() if rx.search(k) or rx.search(v if isinstance(v, str) else json.dumps(v)))


def main():
    ap = argparse.ArgumentParser(description="Tìm token, khoá, mã uỷ quyền, bí mật và định danh thô")
    ap.add_argument("--env", help="file .env: tìm cả giá trị các biến bí mật")
    ap.add_argument("--realm", help="realm JSON: tìm cả sub/username/email của user")
    ap.add_argument("--label", default="stdin", help="tên nguồn dữ liệu để in trong báo cáo")
    a = ap.parse_args()
    patterns = list(FIXED)
    try:
        if a.env:
            patterns += env_secrets(a.env)
        if a.realm:
            patterns += realm_identifiers(a.realm)
    except (OSError, ValueError) as e:
        print("không đọc được file cấu hình: %s" % e, file=sys.stderr)
        return 2

    counts = {}
    findings = []
    n = 0
    for line in sys.stdin:
        n += 1
        for name, rx in patterns:
            if rx.search(line):
                counts[name] = counts.get(name, 0) + 1
                if len(findings) < 20:
                    where = ", ".join(fields_matching(line.strip(), rx)) or "?"
                    findings.append("dòng %d: %s — ở trường: %s" % (n, name, where))

    kinds = sorted(set(name.split(":")[0] for name, _ in patterns))
    print("Quét %s: %d dòng, %d mẫu (%s)" % (a.label, n, len(patterns), "; ".join(kinds)))
    for name in sorted(counts):
        print("  [PHÁT HIỆN] %-46s %d dòng" % (name, counts[name]))
    for f in findings:
        print("    " + f)
    total = sum(counts.values())
    print("Kết quả quét: %s" % ("SẠCH — 0 phát hiện" if total == 0 else "%d phát hiện" % total))
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
