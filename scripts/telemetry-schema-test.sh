#!/usr/bin/env bash
# Tuần 8 T5 — log THÔ của Envoy, auth-svc, OPA, orders-api, profile-api có khớp telemetry/schema.json không?
#
#   ./scripts/telemetry-schema-test.sh | tee docs/evidence/telemetry-schema-$(date +%F).txt
#
# 1. Kiểm chính schema: đủ 27 trường của mục 13.1 đề bài.
# 2. Sinh một lượt request qua P0/P1/P2 (scripts/telemetry-traffic.sh).
# 3. Đọc log thô của 5 service từ lúc bắt đầu, đối chiếu từng khoá và giá trị với schema,
#    quét token/khoá/mã uỷ quyền (SR-10).
# 4. Nối log: một request_id phải thấy ở Envoy + auth-svc + backend; opa_decision_id của
#    auth-svc phải trùng decision_id trong decision log của OPA.
# Mã thoát = số bước FAIL. Cần lab đang chạy (make up).
set -uo pipefail
. "$(dirname "$0")/lib/common.sh"
cd "$ROOT" || exit 1

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
FAIL=0
step() { if [ "$2" = 0 ]; then echo "  [PASS] $1"; else echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); fi; }

echo "# Telemetry: log thô ↔ telemetry/schema.json — $(date -Iseconds)"
echo
echo "## 1. Schema"
python3 telemetry/schema_check.py self | sed 's/^/  /'
step "schema hợp lệ, đủ 27 trường mục 13.1" "${PIPESTATUS[0]}"

echo
echo "## 2. Request mẫu"
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
"$(dirname "$0")/telemetry-traffic.sh" "$TMP/cases.tsv" | sed 's/^/  /'
step "đã gửi $(wc -l <"$TMP/cases.tsv") request" "$([ -s "$TMP/cases.tsv" ] && echo 0 || echo 1)"
sleep 3 # Envoy đẩy access log mỗi 1 s

echo
echo "## 3. Log thô của 5 nguồn ↔ schema"
docker compose logs --no-log-prefix --since "$START" envoy auth-svc opa orders-api profile-api >"$TMP/raw.ndjson" 2>&1
python3 telemetry/schema_check.py source --expect envoy,auth-svc,opa,orders-api,profile-api <"$TMP/raw.ndjson" | sed 's/^/  /'
step "mọi khoá và giá trị trong log thô khớp schema; không có token/khoá trong log" "${PIPESTATUS[0]}"

echo
echo "## 4. Nối sự kiện giữa các nguồn (chỉ in request_id — UUID do Envoy sinh)"
python3 - "$TMP" >"$TMP/join.out" 2>&1 <<'PY'
import json, sys
tmp = sys.argv[1]
by_rid, opa_ids = {}, set()
for line in open(f"{tmp}/raw.ndjson", encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        d = json.loads(line)
    except ValueError:
        continue
    if "decision_id" in d and "result" in d:
        opa_ids.add(d["decision_id"])
        continue
    src = d.get("service")
    if src == "envoy" or d.get("msg") in ("authz_decision", "request"):
        if d.get("request_id"):
            by_rid.setdefault(d["request_id"], {}).setdefault(src, []).append(d)

fail = n = 0
def check(ok, text):
    global fail, n
    n += 1
    fail += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")

cases = [l.rstrip("\n").split("\t") for l in open(f"{tmp}/cases.tsv", encoding="utf-8")]
no_envoy = [c for c in cases if len(by_rid.get(c[0], {}).get("envoy", [])) != 1]
check(not no_envoy, f"mỗi request có đúng 1 dòng access log của Envoy ({len(cases) - len(no_envoy)}/{len(cases)})")

# PEP ↔ PDP: mọi opa_decision_id mà auth-svc ghi đều có trong decision log của OPA.
asked = [e["opa_decision_id"] for c in cases for e in by_rid.get(c[0], {}).get("auth-svc", []) if e.get("opa_decision_id")]
check(bool(asked) and all(i in opa_ids for i in asked), f"opa_decision_id của auth-svc khớp decision log của OPA ({sum(i in opa_ids for i in asked)}/{len(asked)})")

# P0 không qua auth-svc: danh tính chỉ có ở Envoy (principal từ token jwt_authn đã kiểm).
p0 = [c for c in cases if c[1] == "8444" and c[2] == "200"]
check(bool(p0) and all(by_rid[c[0]]["envoy"][0].get("principal") and not by_rid[c[0]].get("auth-svc") for c in p0),
      "P0: không có sự kiện auth-svc, Envoy vẫn ghi principal của token đã kiểm")
anon = [c for c in cases if c[3] == "không token"]
check(bool(anon) and all(by_rid[c[0]]["envoy"][0].get("principal") is None for c in anon),
      "không token: Envoy không ghi principal")

print()
print("  Ba ca tiêu biểu (nguồn → trường chính):")
def show(label_part, port):
    for rid, p, code, label in cases:
        if label_part in label and p == port:
            ev = by_rid.get(rid, {})
            print(f"  • {label}  [:{p} → {code}]  request_id={rid}")
            for e in ev.get("envoy", []):
                print(f"      envoy     status_code={e.get('status_code')} route_group={e.get('route_group')} details={e.get('response_code_details')} tls={e.get('tls_version')}")
            for e in ev.get("auth-svc", []):
                print(f"      auth-svc  decision={e.get('decision')} decision_reason={e.get('decision_reason')} route_template={e.get('route_template')} "
                      f"token_type={e.get('token_type')} proof_status={e.get('proof_status')} policy={e.get('policy_id')}@{e.get('policy_version')} policy_eval_us={e.get('policy_eval_us')}")
            for s in ("orders-api", "profile-api"):
                for e in ev.get(s, []):
                    print(f"      {s:<9} status_code={e.get('status_code')} route_template={e.get('route_template')} backend_object_authz={e.get('backend_object_authz')} "
                          f"backend_authz_reason={e.get('backend_authz_reason')} redacted={e.get('backend_redacted_fields') or '-'}")
            if not any(ev.get(s) for s in ("orders-api", "profile-api")):
                print("      backend   (không có dòng nào — request không tới backend)")
            return
show("BOLA: gateway cho qua", "8443")
show("BFLA", "8443")
show("replay", "8445")
print(f"__COUNT__ {n} {fail}")
PY
grep -v '^__COUNT__' "$TMP/join.out"
read -r _ jn jf < <(grep '^__COUNT__' "$TMP/join.out")
step "nối được sự kiện giữa các nguồn (${jn:-0} phép kiểm, ${jf:-?} lỗi)" "${jf:-1}"

echo
echo "Kết quả: $((4 - FAIL))/4 PASS"
exit $FAIL
