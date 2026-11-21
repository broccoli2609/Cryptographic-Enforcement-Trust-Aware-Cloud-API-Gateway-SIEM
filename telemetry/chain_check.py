#!/usr/bin/env python3
"""Kiểm hash chain + digest của SIEM từ bên ngoài (tuần 9) — chỉ thư viện chuẩn Python + openssl.

Bản cài THỨ HAI, độc lập với digester (Go): dùng cho scripts/chain-test.sh và hunt H9. Công cụ
chính thức là verify-chain (Go, tuần 10) — logic giống file này.

Kiểm gì (mỗi lỗi một dòng [LỖI], mã thoát = số lỗi, tối đa 100):
  1. event_hash của từng sự kiện = SHA-256(JSON chính tắc của sự kiện trừ event_hash) — JSON chính
     tắc giống VRL encode_json: khoá sắp xếp theo byte, không khoảng trắng, số giữ NGUYÊN VĂN như
     trong _source (không đổi 2.0 → 2), chuỗi thoát như serde_json.
  2. chain_seq trong mỗi epoch liền mạch; trùng / thiếu bị báo (thiếu mà digest không khai = bị xoá).
  3. (--chain-file) file chuỗi của Vector khớp OpenSearch: cùng seq → cùng event_hash.
  4. Mỗi digest: signed_payload = payload chính tắc; chữ ký Ed25519 hợp lệ với public key ĐÃ GHIM
     (--pubkey, file vault-init ghi) — không tin public key đi kèm digest; digest_seq liên tục;
     prev_signature = chữ ký digest trước; prev_head / head = H tính lại từ sự kiện; gaps khớp.
  5. Khoảng thời gian giữa hai digest liền nhau và tuổi digest mới nhất ≤ --max-gap (mặc định
     10 phút = 2 × 5 phút) — digest bị xoá ở cuối cũng lộ.

Dùng:
  python3 telemetry/chain_check.py --events ev.ndjson --digests dg.ndjson --pubkey pub.json \
      [--chain-file chain.jsonl] [--epoch E] [--now RFC3339] [--max-gap 600]
  python3 telemetry/chain_check.py selftest --events … --digests … --pubkey …
      (sửa thử 5 kiểu trên một BẢN SAO trong bộ nhớ, khẳng định lần nào cũng bị phát hiện)
"""
import argparse
import base64
import copy
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile

GENESIS_PREFIX = b"topic09/hash-chain/v1|"
PAYLOAD_ORDER = ["v", "digest_seq", "created_at", "key", "chain_epoch", "first_seq", "last_seq",
                 "prev_head", "head", "gaps", "prev_signature"]
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")  # RFC 8410 §4


class Num(str):
    """Số giữ nguyên văn như trong JSON gốc (để băm lại đúng từng byte)."""


def loads(s):
    return json.loads(s, parse_float=Num, parse_int=Num)


def canon(v):
    if isinstance(v, Num):
        return str.__str__(v)
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(canon(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-8"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canon(v[k]) for k in keys) + "}"
    if isinstance(v, int):
        return str(v)
    raise TypeError("kiểu không hỗ trợ: %r" % type(v))


def event_hash(ev):
    e = {k: x for k, x in ev.items() if k != "event_hash"}
    return hashlib.sha256(canon(e).encode("utf-8")).hexdigest()


def genesis(epoch):
    return hashlib.sha256(GENESIS_PREFIX + epoch.encode()).digest()


def parse_gaps(gaps):
    out = set()
    for g in gaps or []:
        a, b = (int(x) for x in g.split("-"))
        out.update(range(a, b + 1))
    return out


def ts(s):
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".")
        s = head + "." + frac[:6]
    return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)


def ed25519_verify(pub_b64, msg, sig_b64):
    with tempfile.TemporaryDirectory() as d:
        p, m, s = (os.path.join(d, n) for n in ("pub.der", "msg", "sig"))
        open(p, "wb").write(ED25519_SPKI_PREFIX + base64.b64decode(pub_b64))
        open(m, "wb").write(msg)
        open(s, "wb").write(base64.b64decode(sig_b64))
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", p, "-keyform", "DER",
                            "-rawin", "-in", m, "-sigfile", s], capture_output=True)
        return r.returncode == 0


def check(events, digests, pinned, chain_file=None, only_epoch=None, now=None, max_gap=600, quiet=False):
    errs = []
    info = []
    err = errs.append

    # --- 1–2. sự kiện theo epoch
    by_epoch = {}
    for ev in events:
        ep, seq = ev.get("chain_epoch"), ev.get("chain_seq")
        if ep is None or seq is None or "event_hash" not in ev:
            continue  # sự kiện trước tuần 9 (chưa có chuỗi)
        if only_epoch and ep != only_epoch:
            continue
        by_epoch.setdefault(ep, {}).setdefault(int(seq), []).append(ev)
    hashes = {}
    bad_hash = 0
    for ep, seqs in by_epoch.items():
        hashes[ep] = {}
        for seq, evs in seqs.items():
            if len(evs) > 1:
                err("epoch %s seq %d: %d sự kiện trùng số thứ tự" % (ep, seq, len(evs)))
            ev = evs[0]
            if event_hash(ev) != ev["event_hash"]:
                bad_hash += 1
                err("epoch %s seq %d (%s/%s): event_hash KHÔNG khớp nội dung — sự kiện bị sửa"
                    % (ep, seq, ev.get("source"), ev.get("event_type")))
            hashes[ep][seq] = ev["event_hash"]
        info.append("epoch %s: %d sự kiện, seq %d..%d, %d hash sai"
                    % (ep, len(seqs), min(seqs), max(seqs), sum(1 for s in seqs if event_hash(seqs[s][0]) != seqs[s][0]["event_hash"])))

    # --- 3. đối chiếu file chuỗi của Vector
    ref = {}
    if chain_file:
        for line in chain_file:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            ref.setdefault(r["chain_epoch"], {})[int(r["chain_seq"])] = r["event_hash"]
        for ep, m in ref.items():
            if only_epoch and ep != only_epoch:
                continue
            have = hashes.get(ep, {})
            for seq, h in sorted(m.items()):
                if seq not in have:
                    err("epoch %s seq %d: có trong file chuỗi của Vector nhưng KHÔNG có trong SIEM — bị xoá" % (ep, seq))
                elif have[seq] != h:
                    err("epoch %s seq %d: event_hash trong SIEM khác file chuỗi của Vector — bị thay" % (ep, seq))
            info.append("file chuỗi epoch %s: %d bản ghi đối chiếu" % (ep, len(m)))

    # --- 4–5. digest
    digests = sorted(digests, key=lambda d: int(d["digest_seq"]))
    prev = None
    heads = {}  # epoch -> (seq, H) đã đi tới
    for d in digests:
        ep = d["chain_epoch"]
        if only_epoch and ep != only_epoch:
            prev = d
            continue
        n = int(d["digest_seq"])
        if prev is not None:
            if n != int(prev["digest_seq"]) + 1:
                err("digest %d: digest_seq nhảy từ %s — mất digest ở giữa" % (n, prev["digest_seq"]))
            if d["prev_signature"] != prev["signature"]:
                err("digest %d: prev_signature ≠ chữ ký digest %s — đứt mắt xích" % (n, prev["digest_seq"]))
            gap = (ts(d["created_at"]) - ts(prev["created_at"])).total_seconds()
            if gap > max_gap:
                err("digest %d: cách digest trước %.0f s > %d s — có thể mất digest (hoặc digester/Vault ngừng)" % (n, gap, max_gap))
        elif n != 1 and not only_epoch:
            err("digest đầu tiên có digest_seq %d ≠ 1 — mất digest ở đầu" % n)
        # chữ ký: payload chính tắc + public key đã ghim
        # Thứ tự trường = thứ tự trong struct Payload của Go; số giữ nguyên văn (Num).
        payload = "{" + ",".join(json.dumps(k) + ":" + canon(d.get(k)) for k in PAYLOAD_ORDER) + "}"
        signed = base64.b64decode(d["signed_payload"])
        if signed != payload.encode():
            err("digest %d: signed_payload khác các trường của digest — trường bị sửa" % n)
        ver = str(d["key_version"])
        pk = d.get("public_key")
        if pk not in pinned:
            err("digest %d: public_key đi kèm KHÔNG nằm trong tập khoá vault-init đã công bố — chữ ký giả" % n)
        elif not d["signature"].startswith("vault:v%s:" % ver) or not ed25519_verify(pk, signed, d["signature"].split(":", 2)[2]):
            err("digest %d: chữ ký Ed25519 KHÔNG hợp lệ" % n)
        # đầu chuỗi
        first, last = int(d["first_seq"]), int(d["last_seq"])
        gaps = parse_gaps(d.get("gaps"))
        seq0, h = heads.get(ep, (0, genesis(ep)))
        if seq0 != first - 1:
            # digest đầu tiên của epoch này mà ta thấy không bắt đầu từ đầu: chỉ kiểm được từ prev_head
            h = bytes.fromhex(d["prev_head"])
        elif h.hex() != d["prev_head"]:
            err("digest %d: prev_head ≠ H(%d) tính lại" % (n, first - 1))
        src = ref.get(ep) if ref.get(ep) else hashes.get(ep, {})
        broken = False
        for s in range(first, last + 1):
            if s in gaps:
                continue
            eh = src.get(s)
            if eh is None:
                err("digest %d: thiếu sự kiện seq %d (digest không khai là khoảng thiếu) — bị xoá" % (n, s))
                broken = True
                break
            h = hashlib.sha256(h + bytes.fromhex(eh)).digest()
        if not broken:
            if h.hex() != d["head"]:
                err("digest %d: head đã ký ≠ H(%d) tính lại từ sự kiện — chuỗi bị sửa" % (n, last))
            heads[ep] = (last, h)
        prev = d
    if digests:
        latest = digests[-1]
        info.append("%d digest, mới nhất #%s lúc %s phủ %s..%s"
                    % (len(digests), latest["digest_seq"], latest["created_at"], latest["first_seq"], latest["last_seq"]))
        if now is not None:
            age = (now - ts(latest["created_at"])).total_seconds()
            if age > max_gap:
                err("digest mới nhất đã %.0f s tuổi > %d s — digest bị xoá ở cuối hoặc digester ngừng" % (age, max_gap))
    if not quiet:
        for i in info:
            print("  " + i)
        for e in errs[:100]:
            print("  [LỖI] " + e)
    return errs


def load_ndjson(path):
    with open(path, encoding="utf-8") as f:
        return [loads(line) for line in f if line.strip()]


def load_pinned(path, history=None):
    """Tập public key tin được: khoá hiện tại (file của `vault read transit/keys/siem-digest`) và
    mọi khoá vault-init từng công bố (siem-digest.history.jsonl) — Vault dev khởi động lại thì
    sinh khoá mới mà version vẫn là 1, nên ghim theo GIÁ TRỊ khoá, không theo số version."""
    d = json.load(open(path, encoding="utf-8"))["data"]
    if d.get("type") != "ed25519":
        raise SystemExit("file public key không phải ed25519")
    keys = {k["public_key"] for k in d["keys"].values()}
    if history:
        for line in open(history, encoding="utf-8"):
            if line.strip():
                keys.add(json.loads(line)["public_key"])
    return keys


def selftest(events, digests, pinned, chain_lines):
    """Sửa thử trên bản sao, mỗi kiểu một lần; trả số kiểu KHÔNG bị phát hiện."""
    signed_ev = [e for e in events if "event_hash" in e]
    covered = [e for e in signed_ev if any(int(d["first_seq"]) <= int(e["chain_seq"]) <= int(d["last_seq"])
                                           and d["chain_epoch"] == e["chain_epoch"] for d in digests)]
    if len(covered) < 3 or not digests:
        print("  selftest: cần ≥ 3 sự kiện đã được digest phủ")
        return 1
    tgt = covered[len(covered) // 2]
    ep = tgt["chain_epoch"]

    def sub(ev_list, d_list, chain=None):
        return check(ev_list, d_list, pinned, chain_file=chain, only_epoch=ep, quiet=True)

    cases = []
    ev1 = copy.deepcopy(events)
    for e in ev1:
        if e is not None and e.get("chain_seq") == tgt["chain_seq"] and e.get("chain_epoch") == ep:
            e["decision"] = "allow" if e.get("decision") != "allow" else "deny"
    cases.append(("sửa một trường của sự kiện (giữ event_hash cũ)", sub(ev1, digests)))
    ev2 = copy.deepcopy(events)
    for e in ev2:
        if e.get("chain_seq") == tgt["chain_seq"] and e.get("chain_epoch") == ep:
            e["decision"] = "allow" if e.get("decision") != "allow" else "deny"
            e["event_hash"] = event_hash(e)
    cases.append(("sửa sự kiện VÀ tính lại event_hash", sub(ev2, digests)))
    ev3 = [e for e in events if not (e.get("chain_seq") == tgt["chain_seq"] and e.get("chain_epoch") == ep)]
    cases.append(("xoá một sự kiện", sub(ev3, digests)))
    cases.append(("xoá một sự kiện (đối chiếu file chuỗi của Vector)", sub(ev3, digests, chain_lines) if chain_lines else ["bỏ qua"]))
    d4 = copy.deepcopy(digests)
    d4[-1]["head"] = "0" * 64
    cases.append(("sửa head của digest", sub(events, d4)))
    if len(digests) >= 2:
        d5 = copy.deepcopy(digests)
        del d5[0]
        cases.append(("xoá một digest", check(events, d5, pinned, quiet=True)))
    missed = 0
    for name, errs in cases:
        ok = len(errs) > 0
        missed += 0 if ok else 1
        print("  [%s] %s → %s" % ("PASS" if ok else "FAIL", name, ("phát hiện: " + errs[0][:90]) if ok else "KHÔNG phát hiện"))
    return missed


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mode", nargs="?", default="check", choices=["check", "selftest"])
    ap.add_argument("--events", required=True)
    ap.add_argument("--digests", required=True)
    ap.add_argument("--pubkey", required=True, help="file JSON của `vault read transit/keys/siem-digest` (khoá ghim)")
    ap.add_argument("--pubkey-history", help="siem-digest.history.jsonl do vault-init ghi thêm")
    ap.add_argument("--chain-file", help="file <epoch>.jsonl của Vector để đối chiếu")
    ap.add_argument("--epoch")
    ap.add_argument("--now", help="RFC 3339; có thì kiểm tuổi digest mới nhất")
    ap.add_argument("--max-gap", type=int, default=600)
    a = ap.parse_args()
    events, digests = load_ndjson(a.events), load_ndjson(a.digests)
    pinned = load_pinned(a.pubkey, a.pubkey_history)
    chain_lines = open(a.chain_file, encoding="utf-8").read().splitlines() if a.chain_file else None
    if a.mode == "selftest":
        return min(selftest(events, digests, pinned, chain_lines), 100)
    now = ts(a.now) if a.now else None
    errs = check(events, digests, pinned, chain_file=chain_lines, only_epoch=a.epoch, now=now, max_gap=a.max_gap)
    print("Kết quả chain_check: %s" % ("ĐẠT" if not errs else "%d lỗi" % len(errs)))
    return min(len(errs), 100)


if __name__ == "__main__":
    sys.exit(main())
