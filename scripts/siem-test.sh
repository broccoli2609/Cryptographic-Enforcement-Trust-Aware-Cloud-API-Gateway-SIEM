#!/usr/bin/env bash
# Tuần 8 T6 — đường ống telemetry từ đầu đến cuối: 5 nguồn → Vector → OpenSearch (SR-09, SR-10, T9).
#
#   ./scripts/siem-test.sh | tee docs/evidence/siem-pipeline-$(date +%F).txt
#
#   A. Hạ tầng     Vector + OpenSearch khoẻ, không port ra host, mạng kín, mapping strict
#   B. Luồng       request mẫu qua P0/P1/P2 → sự kiện của cả 5 nguồn tới SIEM, nối được bằng request_id
#   C. Schema      mọi sự kiện trong SIEM đúng telemetry/schema.json, không khoá lạ
#   D. Giả danh    principal_hash / aud_hash đúng là HMAC-SHA256 với khoá trong .env (tính lại độc lập)
#   E. Chèn token  gọi thẳng backend với X-Request-Id là một token giả (S8) → không vào được SIEM
#   F. Scanner     tự thử scanner (phải bắt được), rồi quét toàn bộ SIEM (phải sạch)
#   G. Lớp thứ hai OpenSearch tự từ chối tài liệu có trường lạ (dynamic: strict)
#
# Mã thoát = số mục FAIL. Cần lab đang chạy (make up) và đã chạy batch-worker-key.sh.
# Không in token, không in khoá, không in sub: chỉ in request_id (UUID của Envoy) và hash.
set -uo pipefail
. "$(dirname "$0")/lib/common.sh"
cd "$ROOT" || exit 1

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
FAIL=0
N=0
ok() { N=$((N + 1)); echo "  [PASS] $*"; }
bad() { N=$((N + 1)); FAIL=$((FAIL + 1)); echo "  [FAIL] $*"; }
check() { if [ "$1" = 0 ]; then ok "$2"; else bad "$2${3:+ — $3}"; fi; }
os() { docker compose exec -T opensearch curl -sS "$@"; }   # OpenSearch không có port → gọi từ trong container
health() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$(docker compose ps -q "$1")" 2>/dev/null; }

echo "# Đường ống telemetry: 5 nguồn → Vector → OpenSearch — $(date -Iseconds)"
echo "# Image: $(docker compose config --format json | python3 -c 'import json,sys; s=json.load(sys.stdin)["services"]; print(s["vector"]["image"], "·", s["opensearch"]["image"])')"

# ---------------------------------------------------------------------------------------------
echo
echo "## A. Hạ tầng"
for s in opensearch vector; do
  h=$(health "$s")
  [ "$h" = healthy ] && ok "$s: healthy" || bad "$s: ${h:-không chạy}"
done
# "docker port" chỉ in cổng ĐÃ publish ra host. (Không dùng "docker compose port": image
# OpenSearch có EXPOSE 9200 nên lệnh đó in ":0" dù không publish gì.)
for s in opensearch vector; do
  pub=$(docker port "$(docker compose ps -q "$s")" 2>/dev/null)
  [ -z "$pub" ] && ok "$s không publish cổng nào ra host" || bad "$s đang publish cổng ra host (T5): $pub"
done
members=$(docker network inspect topic09-telemetry -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | tr ' ' '\n' | sed -E 's/^topic09-lab-//; s/-[0-9]+$//' | grep . | sort | tr '\n' ' ')
internal=$(docker network inspect topic09-telemetry -f '{{.Internal}}' 2>/dev/null)
if [ "$members" = "opensearch vector " ] && [ "$internal" = true ]; then
  ok "mạng topic09-telemetry (internal) chỉ có opensearch + vector"
else
  bad "mạng topic09-telemetry: thành viên '$members', internal=$internal (muốn 'opensearch vector', true)"
fi
if curl -fsS --max-time 2 http://localhost:9200 >/dev/null 2>&1; then bad "OpenSearch gọi thẳng được từ host"; else ok "OpenSearch KHÔNG gọi thẳng được từ host"; fi
dyn=$(os 'http://127.0.0.1:9200/topic09-events/_mapping' | python3 -c 'import json,sys; m=json.load(sys.stdin)["topic09-events"]["mappings"]; print(m.get("dynamic"), len(m["properties"]))' 2>/dev/null)
[ "${dyn%% *}" = strict ] && ok "index topic09-events: mapping dynamic=strict, ${dyn##* } trường" || bad "mapping của index: '$dyn' (muốn strict)"
python3 telemetry/schema_check.py sync >"$TMP/sync.out" 2>&1
check $? "schema ↔ allow-list của Vector ↔ mapping OpenSearch khớp nhau" "$(grep 'LỖI' "$TMP/sync.out" | head -1)"
[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}}' "$(docker compose ps -q vector)")" = "true [ALL]" ] &&
  ok "vector: file hệ thống chỉ đọc, bỏ mọi capability" || bad "vector thiếu read_only / cap_drop ALL"

# ---------------------------------------------------------------------------------------------
echo
echo "## B. Luồng: request mẫu → sự kiện trong SIEM"
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
"$(dirname "$0")/telemetry-traffic.sh" "$TMP/cases.tsv" >"$TMP/traffic.out" 2>&1
[ -s "$TMP/cases.tsv" ] && ok "đã gửi $(wc -l <"$TMP/cases.tsv") request qua P0/P1/P2" || bad "không gửi được request mẫu: $(tail -1 "$TMP/traffic.out")"
sleep 7 # Envoy đẩy access log mỗi 1 s, Vector gom lô 2 s
"$(dirname "$0")/siem-export.sh" "$START" >"$TMP/events.ndjson" 2>"$TMP/export.err"
check $? "xuất sự kiện từ SIEM kể từ $START ($(cat "$TMP/export.err"))"

python3 - "$TMP" >"$TMP/b.out" 2>&1 <<'PY'
import json, sys
tmp = sys.argv[1]
events = [json.loads(l) for l in open(f"{tmp}/events.ndjson", encoding="utf-8") if l.strip()]
cases = [l.rstrip("\n").split("\t") for l in open(f"{tmp}/cases.tsv", encoding="utf-8")]
by_rid, by_opa = {}, {}
for e in events:
    if e.get("request_id"):
        by_rid.setdefault(e["request_id"], {}).setdefault(e["source"], []).append(e)
    if e["source"] == "opa" and e.get("opa_decision_id"):
        by_opa[e["opa_decision_id"]] = e
n = fail = 0
def check(cond, text):
    global n, fail
    n += 1
    fail += not cond
    print(f"  [{'PASS' if cond else 'FAIL'}] {text}")

src = {}
for e in events:
    src[e["source"]] = src.get(e["source"], 0) + 1
print("  sự kiện theo nguồn: " + ", ".join(f"{k}={v}" for k, v in sorted(src.items())))
for s in ("envoy", "auth-svc", "opa", "orders-api", "profile-api", "keycloak"):
    check(src.get(s, 0) > 0, f"nguồn {s}: có sự kiện trong SIEM")

# Mỗi request: Envoy luôn có đúng 1 sự kiện.
miss = [c for c in cases if len(by_rid.get(c[0], {}).get("envoy", [])) != 1]
check(not miss, f"mỗi request có đúng 1 sự kiện gateway_access của Envoy ({len(cases) - len(miss)}/{len(cases)})")

# Sự kiện của auth-svc / backend / OPA phải có đúng khi Envoy nói request đã đi tới đó.
want_auth = want_back = got_auth = got_back = want_opa = got_opa = 0
leaked = []
for rid, port, code, label in cases:
    ev = by_rid.get(rid, {})
    if not ev.get("envoy"):
        continue
    x = ev["envoy"][0]
    details = x.get("response_code_details") or ""
    # P1/P2: auth-svc được gọi khi jwt_authn cho qua và request khớp một route.
    if port in ("8443", "8445") and not details.startswith("jwt_authn_access_denied") and details != "route_not_found":
        want_auth += 1
        got_auth += len(ev.get("auth-svc", [])) == 1
        for a in ev.get("auth-svc", []):
            if a.get("opa_decision_id"):
                want_opa += 1
                got_opa += a["opa_decision_id"] in by_opa
    back = ev.get("orders-api", []) + ev.get("profile-api", [])
    if details == "via_upstream":
        want_back += 1
        got_back += len(back) == 1
    elif back:
        leaked.append(label)
check(not leaked, "request bị gateway chặn thì KHÔNG có sự kiện backend nào" + (f" — sai ở: {leaked}" if leaked else ""))
check(want_auth > 0 and got_auth == want_auth, f"request tới auth-svc đều có sự kiện authz_decision cùng request_id ({got_auth}/{want_auth})")
check(want_opa > 0 and got_opa == want_opa, f"mỗi opa_decision_id của auth-svc có sự kiện policy_decision của OPA ({got_opa}/{want_opa})")
check(want_back > 0 and got_back == want_back, f"request tới backend (via_upstream) đều có sự kiện backend_request ({got_back}/{want_back})")

def find(part, port):
    for rid, p, code, label in cases:
        if part in label and p == port:
            return by_rid.get(rid, {}), rid, label
    return {}, "", part

# BOLA: gateway cho qua, backend chặn — hai tầng, một request_id.
ev, rid, label = find("BOLA: gateway cho qua", "8443")
a = (ev.get("auth-svc") or [{}])[0]; b = (ev.get("orders-api") or [{}])[0]
check(a.get("decision") == "allow" and b.get("backend_object_authz") == "deny" and b.get("backend_authz_reason") == "not_owner",
      f"BOLA (P1): auth-svc decision=allow + orders-api backend_object_authz=deny/not_owner, request_id={rid}")
# BFLA: OPA chặn, không có sự kiện backend.
ev, rid, label = find("BFLA", "8443")
a = (ev.get("auth-svc") or [{}])[0]
check(a.get("decision") == "deny" and a.get("decision_reason") == "role_not_allowed" and a.get("route_template") == "/orders/{id}"
      and not ev.get("orders-api") and (ev.get("envoy") or [{}])[0].get("decision") == "deny",
      "BFLA (P1): auth-svc deny/role_not_allowed trên /orders/{id}, Envoy deny, không có sự kiện backend")
# DPoP replay.
ev, rid, label = find("replay", "8445")
a = (ev.get("auth-svc") or [{}])[0]
check(a.get("proof_status") == "replay" and a.get("decision_reason") == "dpop_replay" and a.get("token_type") == "DPoP",
      "DPoP replay (P2): proof_status=replay, decision_reason=dpop_replay, token_type=DPoP")
ev, rid, label = find("khoá khác", "8445")
a = (ev.get("auth-svc") or [{}])[0]
check(a.get("proof_status") == "key_mismatch" and a.get("cnf_jkt") and a.get("proof_jkt") and a["cnf_jkt"] != a["proof_jkt"],
      "token trộm + khoá khác (P2): proof_status=key_mismatch, cnf_jkt ≠ proof_jkt (bằng chứng cho hunt H2)")
# P0: không có auth-svc, danh tính đến từ Envoy.
ev, rid, label = find("alice GET /orders/whoami", "8444")
x = (ev.get("envoy") or [{}])[0]
check(x.get("profile") == "p0" and x.get("principal_hash") and not ev.get("auth-svc"),
      "P0: không có sự kiện auth-svc; Envoy vẫn cho principal_hash (từ token jwt_authn đã kiểm)")
# Property-level: salary_band bị ẩn với manager.
ev, rid, label = find("ẩn salary_band", "8443")
b = (ev.get("profile-api") or [{}])[0]
check(b.get("backend_redacted_fields") == "salary_band", "property-level: profile-api ghi backend_redacted_fields=salary_band cho manager")
# batch-worker.
ev, rid, label = find("batch-worker", "8443")
a = (ev.get("auth-svc") or [{}])[0]
check(a.get("client_id") == "batch-worker" and a.get("authn_method") == "private_key_jwt", "batch-worker: authn_method=private_key_jwt (suy từ client_id)")
# Keycloak.
kc = [e for e in events if e["source"] == "keycloak"]
types = sorted(set(e.get("idp_event") for e in kc))
check({"LOGIN", "CODE_TO_TOKEN", "CLIENT_LOGIN"} <= set(types), f"Keycloak: có LOGIN, CODE_TO_TOKEN, CLIENT_LOGIN (thấy: {', '.join(t or '?' for t in types)})")
check(any(e.get("grant_type") == "client_credentials" and e.get("client_id") == "batch-worker" for e in kc),
      "Keycloak: CLIENT_LOGIN của batch-worker có grant_type=client_credentials")
print(f"__COUNT__ {n} {fail}")
PY
grep -v '^__COUNT__' "$TMP/b.out"
read -r _ bn bf < <(grep '^__COUNT__' "$TMP/b.out")
N=$((N + ${bn:-0})); FAIL=$((FAIL + ${bf:-1}))

# ---------------------------------------------------------------------------------------------
echo
echo "## C. Sự kiện trong SIEM ↔ telemetry/schema.json (kiểm nghiêm, không cho khoá lạ)"
python3 telemetry/schema_check.py siem --expect envoy,auth-svc,opa,orders-api,profile-api,keycloak <"$TMP/events.ndjson" >"$TMP/c.out" 2>&1
rc=$?
sed 's/^/  /' "$TMP/c.out"
check $rc "$(wc -l <"$TMP/events.ndjson") sự kiện đều đúng schema; 20 trường core của tuần 8 đều có nguồn điền"

# ---------------------------------------------------------------------------------------------
echo
echo "## D. Giả danh: principal_hash và aud_hash có đúng là HMAC-SHA256 với khoá trong .env không?"
# Tính lại ĐỘC LẬP bằng Python (hmac + hashlib), đọc khoá từ .env; không in khoá, không in sub.
python3 - "$TMP" >"$TMP/d.out" 2>&1 <<'PY'
import hashlib, hmac, json, sys
tmp = sys.argv[1]
key = [l.split("=", 1)[1].strip() for l in open(".env", encoding="utf-8") if l.startswith("SIEM_HMAC_KEY=")][-1].encode()
users = {u["username"]: u["id"] for u in json.load(open("idp/realm-topic09.json", encoding="utf-8"))["users"] if u.get("id")}
events = [json.loads(l) for l in open(f"{tmp}/events.ndjson", encoding="utf-8") if l.strip()]
cases = [l.rstrip("\n").split("\t") for l in open(f"{tmp}/cases.tsv", encoding="utf-8")]
n = fail = 0
def check(cond, text):
    global n, fail
    n += 1
    fail += not cond
    print(f"  [{'PASS' if cond else 'FAIL'}] {text}")
mac = lambda msg: hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()

sub = users["alice"]
want = mac("principal:" + sub)
rid = next(c[0] for c in cases if c[3] == "alice GET /orders/whoami" and c[1] == "8443")
mine = [e for e in events if e.get("request_id") == rid]
for s in ("envoy", "auth-svc"):
    got = [e.get("principal_hash") for e in mine if e["source"] == s]
    check(got == [want], f"{s}: principal_hash của alice = HMAC-SHA256(khoá, \"principal:\" + sub)  [{want[:12]}…]")
opa_id = next((e.get("opa_decision_id") for e in mine if e["source"] == "auth-svc"), None)
check(any(e["source"] == "opa" and e.get("opa_decision_id") == opa_id and e.get("principal_hash") == want for e in events),
      "opa: sự kiện policy_decision của cùng quyết định mang cùng principal_hash")
check(any(e["source"] == "keycloak" and e.get("idp_event") == "LOGIN" and e.get("principal_hash") == want for e in events),
      "keycloak: sự kiện LOGIN của alice mang cùng principal_hash → nối được IdP ↔ gateway ↔ PDP")
check(want != hashlib.sha256(sub.encode()).hexdigest() and want != mac(sub),
      "giá trị trong SIEM KHÁC SHA-256(sub) (hash trần) và khác HMAC không có tiền tố tách miền")
others = {u: mac("principal:" + i) for u, i in users.items() if u != "alice"}
seen = {e.get("principal_hash") for e in events if e.get("principal_hash")}
known = sorted(u for u, h in others.items() if h in seen)
check(len(set(others.values()) | {want}) == len(others) + 1 and len(known) >= 3,
      f"mỗi user một hash khác nhau; thấy trong SIEM hash của: alice, {', '.join(known)}")
aud = [e.get("aud_hash") for e in mine if e["source"] == "auth-svc"]
check(aud == [mac("aud:topic09-api")], "auth-svc: aud_hash = HMAC-SHA256(khoá, \"aud:topic09-api\")")
raw = open(f"{tmp}/events.ndjson", encoding="utf-8").read()
leaked = [u for u, i in users.items() if i in raw]
check(not leaked and '"principal"' not in raw and '"aud"' not in raw and '"sub"' not in raw,
      f"không sub nào của {len(users)} user xuất hiện trong SIEM; không còn khoá principal / aud / sub")
print(f"__COUNT__ {n} {fail}")
PY
grep -v '^__COUNT__' "$TMP/d.out"
read -r _ dn df < <(grep '^__COUNT__' "$TMP/d.out")
N=$((N + ${dn:-0})); FAIL=$((FAIL + ${df:-1}))

# ---------------------------------------------------------------------------------------------
echo
echo "## E. Chèn token vào log (kịch bản S8: gọi thẳng backend, vòng qua gateway)"
# Token GIẢ dựng tại chỗ (file này không chứa chuỗi dạng JWT viết sẵn).
FAKE="$(printf '{"alg":"RS256"}' | b64url).$(printf '{"sub":"s8-probe"}' | b64url).$(printf 'fakesig' | b64url)"
T_E=$(date -u +%Y-%m-%dT%H:%M:%SZ)
body=$(docker run --rm --network topic09-backend busybox:1.37 wget -qO- \
  --header "X-Request-Id: $FAKE" --header "X-User: s8-probe" http://orders-api:8081/orders/whoami 2>/dev/null)
echo "$body" | grep -q '"user":"s8-probe"' &&
  ok "từ trong mạng backend gọi thẳng orders-api được, tự xưng X-User (điểm yếu TB3 đã ghi trong threat model)" ||
  bad "không gọi thẳng được orders-api từ mạng backend: $body"
sleep 5
rawhits=$(docker compose logs orders-api --no-log-prefix --since "$T_E" 2>&1 | grep -cF "$FAKE")
[ "$rawhits" -ge 1 ] && ok "log THÔ của orders-api có token giả trong request_id ($rawhits dòng) — mối nguy là thật" || bad "log thô không có token giả (kịch bản không chạy đúng)"
"$(dirname "$0")/siem-export.sh" "$T_E" >"$TMP/e.ndjson" 2>/dev/null
python3 - "$TMP/e.ndjson" "$FAKE" >"$TMP/e.out" 2>&1 <<'PY'
import json, sys
raw = open(sys.argv[1], encoding="utf-8").read()
ev = [json.loads(l) for l in raw.splitlines() if l.strip()]
hit = [e for e in ev if e["source"] == "orders-api" and e.get("route_template") == "/orders/whoami" and "request_id" not in e]
n = fail = 0
def check(cond, text):
    global n, fail
    n += 1
    fail += not cond
    print(f"  [{'PASS' if cond else 'FAIL'}] {text}")
check(len(hit) >= 1, f"SIEM có sự kiện backend_request tương ứng, request_id đã bị BỎ ({len(hit)} sự kiện)")
check(bool(hit) and all(e.get("pipeline_redacted") is True for e in hit), "sự kiện đó mang cờ pipeline_redacted=true (dấu hiệu để điều tra)")
check(sys.argv[2] not in raw and "eyJ" not in raw, "token giả KHÔNG có trong SIEM; không còn chuỗi 'eyJ' nào")
gw = [e for e in ev if e["source"] in ("envoy", "auth-svc")]
check(not gw, "không có sự kiện Envoy/auth-svc nào đi kèm → backend_request mồ côi = dấu hiệu vòng qua gateway (S8)")
print(f"__COUNT__ {n} {fail}")
PY
grep -v '^__COUNT__' "$TMP/e.out"
read -r _ en ef < <(grep '^__COUNT__' "$TMP/e.out")
N=$((N + ${en:-0})); FAIL=$((FAIL + ${ef:-1}))

# ---------------------------------------------------------------------------------------------
echo
echo "## F. Scanner (scripts/siem-scan.sh)"
# F1 — tự thử: scanner phải BẮT được từng loại. Dữ liệu thử dựng tại chỗ, không nằm sẵn trong file.
selftest() { # MÔ_TẢ  DÒNG_DỮ_LIỆU  → scanner phải thoát mã 1
  if printf '%s\n' "$2" | "$(dirname "$0")/siem-scan.sh" --stdin >/dev/null 2>&1; then
    bad "scanner KHÔNG bắt được: $1"
  else
    ok "scanner bắt được: $1"
  fi
}
selftest "JWT trong một trường" "{\"kid\":\"$FAKE\"}"
selftest "khoá PEM" "{\"iss\":\"$(printf -- '-----%s PRIVATE KEY-----' BEGIN)\"}"
selftest "mã uỷ quyền" '{"decision_reason":"redirect?code'"="'abcdef123456"}'
selftest "giá trị khoá HMAC trong .env" "{\"x\":\"$(env_get SIEM_HMAC_KEY)\"}"
selftest "sub thật của một user" "{\"x\":\"$(python3 -c 'import json; print(json.load(open("idp/realm-topic09.json"))["users"][0]["id"])')\"}"
selftest "username của một user" '{"username":"alice"}'
if printf '%s\n' '{"source":"envoy","kid":"Plx0cWlevKnBlzy5dCcf7M0PMzmzLi2Bfmfrtlx-3FA","decision_reason":"ok"}' | "$(dirname "$0")/siem-scan.sh" --stdin >/dev/null 2>&1; then
  ok "scanner KHÔNG báo nhầm sự kiện sạch"
else
  bad "scanner báo nhầm một sự kiện sạch"
fi
# F2 — quét thật: toàn bộ index (cả sự kiện của mục E) + dataset/.
"$(dirname "$0")/siem-scan.sh" >"$TMP/scan.out" 2>&1
rc=$?
sed 's/^/  /' "$TMP/scan.out"
check $rc "toàn bộ SIEM sạch: không token, khoá, mã uỷ quyền, bí mật của lab hay định danh thô"

# ---------------------------------------------------------------------------------------------
echo
echo "## G. Lớp chặn thứ hai: OpenSearch từ chối tài liệu có trường ngoài schema"
resp=$(os -X POST -H 'Content-Type: application/json' 'http://127.0.0.1:9200/topic09-events/_doc' \
  -d '{"event_time":"2026-11-13T00:00:00Z","source":"envoy","event_type":"gateway_access","authorization":"x"}' -w '\n%{http_code}')
code=$(printf '%s' "$resp" | tail -1)
etype=$(printf '%s' "$resp" | head -1 | python3 -c 'import json,sys; print(json.load(sys.stdin).get("error",{}).get("type","?"))' 2>/dev/null)
[ "$code" = 400 ] && [ "$etype" = strict_dynamic_mapping_exception ] &&
  ok "ghi tài liệu có trường \"authorization\" → HTTP 400 $etype (không được lưu)" ||
  bad "tài liệu có trường lạ: HTTP $code $etype (muốn 400 strict_dynamic_mapping_exception)"

echo
echo "Kết quả: $((N - FAIL))/$N PASS"
exit $FAIL
