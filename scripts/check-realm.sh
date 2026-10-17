#!/usr/bin/env bash
# Tuần 3 T5 — in cấu hình realm topic09 ĐANG CHẠY (đọc qua Admin REST API) để đối chiếu
# với idp/realm-topic09.json: thiết lập bảo mật của realm, 2 client, 4 user + role + dept/tier.
# Chạy:  ./scripts/check-realm.sh | tee docs/evidence/realm-topic09-$(date +%F).txt
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

ADM=$(kc_admin_token) || die "không lấy được token admin — Keycloak đã chạy chưa?"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

kc_api "$ADM" "" >"$TMP/realm.json"
kc_api "$ADM" "clients?briefRepresentation=false" >"$TMP/clients.json"
kc_api "$ADM" "users?briefRepresentation=false&max=50" >"$TMP/users.json"
for id in $(python3 -c 'import json,sys; [print(u["id"]) for u in json.load(open(sys.argv[1]))]' "$TMP/users.json"); do
  kc_api "$ADM" "users/$id/role-mappings/realm" >"$TMP/roles-$id.json"
done
curl -fsS "$OIDC/certs" >"$TMP/jwks.json"

echo "# Realm $REALM — cấu hình đang chạy ($(date -Iseconds))"
python3 - "$TMP" <<'PY'
import json, os, sys
d = sys.argv[1]
load = lambda n: json.load(open(os.path.join(d, n)))
r = load("realm.json")

print("\n## Realm")
for k in ["realm", "sslRequired", "registrationAllowed", "bruteForceProtected", "failureFactor",
          "passwordPolicy", "defaultSignatureAlgorithm", "accessTokenLifespan",
          "accessCodeLifespan", "revokeRefreshToken", "refreshTokenMaxReuse",
          "eventsEnabled", "adminEventsEnabled"]:
    print(f"  {k:28} = {r.get(k)}")

print("\n## Client")
for c in load("clients.json"):
    if c["clientId"] not in ("web-app", "batch-worker"):
        continue
    a = c.get("attributes", {})
    print(f"  {c['clientId']}:")
    print(f"    publicClient={c.get('publicClient')} clientAuthenticator={c.get('clientAuthenticatorType')}"
          f" fullScopeAllowed={c.get('fullScopeAllowed')}")
    print(f"    standardFlow={c.get('standardFlowEnabled')} implicit={c.get('implicitFlowEnabled')}"
          f" directAccessGrants(ROPC)={c.get('directAccessGrantsEnabled')}"
          f" serviceAccounts={c.get('serviceAccountsEnabled')}")
    print(f"    redirectUris={c.get('redirectUris')}")
    for k in ["pkce.code.challenge.method", "token.endpoint.auth.signing.alg", "use.jwks.url"]:
        if k in a:
            print(f"    {k} = {a[k]}")
    cert = a.get("jwt.credential.certificate")
    if c["clientId"] == "batch-worker":
        print(f"    jwt.credential.certificate = {'ĐÃ ĐĂNG KÝ' if cert else 'CHƯA đăng ký (chạy scripts/batch-worker-key.sh)'}")
    print(f"    protocolMappers = {[m['name'] for m in c.get('protocolMappers', [])]}")

print("\n## User")
print(f"  {'username':30} {'dept':12} {'tier':9} realm roles")
for u in sorted(load("users.json"), key=lambda u: u["username"]):
    at = u.get("attributes", {})
    roles = sorted(x["name"] for x in load(f"roles-{u['id']}.json")
                   if not x["name"].startswith("default-roles"))
    print(f"  {u['username']:30} {','.join(at.get('dept', ['-'])):12} {','.join(at.get('tier', ['-'])):9} {roles}")

print("\n## JWKS công khai (" + "kid rút gọn, kty, alg, use)")
for k in load("jwks.json")["keys"]:
    print(f"  {k['kid'][:16]:16} {k['kty']:4} {k.get('alg'):9} {k.get('use')}")
PY
