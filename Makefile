COMPOSE ?= docker compose

.PHONY: up down ps logs smoke test env-check perf-check certs batch-key realm pkce pkce-negative cc tls gateway-test failclosed evidence policy-test authz-test dpop-client dpop-login dpop-test object-authz-test schema-test vector-validate siem-mapping siem-test siem-scan siem-search

OPA_IMAGE ?= openpolicyagent/opa:1.21.4-static
VECTOR_IMAGE ?= timberio/vector:0.60.0-alpine
# Khoá GIẢ, chỉ dùng cho unit test của đường ống Vector (telemetry/vector/tests.yaml có một
# known-answer test tính sẵn theo khoá này). Khoá thật là SIEM_HMAC_KEY trong .env.
VECTOR_TEST_KEY ?= unit-test-key-not-a-secret-0123456789abcdef

up:            ## Build và chạy lab nền (cần đã chạy `make certs` một lần)
	$(COMPOSE) up -d --build

down:          ## Dừng lab (giữ dữ liệu Keycloak)
	$(COMPOSE) down

ps:            ## Trạng thái các container
	$(COMPOSE) ps

logs:          ## Xem log liên tục
	$(COMPOSE) logs -f --tail=50

smoke:         ## Kiểm nhanh lab sau khi up (26 PASS là đạt — tuần 8)
	./scripts/smoke-test.sh

test:          ## Unit test của backend và auth-svc
	cd workloads && go test ./...
	cd gateway/auth-svc && go test ./...

env-check:     ## Kiểm Docker, Go, perf trên máy
	./scripts/check-env.sh

perf-check:    ## Kiểm perf đếm được cycles không, lưu bằng chứng
	./scripts/check-perf.sh

# --- Tuần 3–4: IdP, gateway ---

certs:         ## Sinh CA nội bộ + cert TLS cho Envoy vào secrets/tls/ (chạy trước `make up` lần đầu)
	./scripts/gen-certs.sh

batch-key:     ## Sinh khoá batch-worker + đăng ký chứng chỉ vào Keycloak (sau `make up`)
	./scripts/batch-worker-key.sh

realm:         ## In cấu hình realm topic09 đang chạy
	./scripts/check-realm.sh

pkce:          ## Chạy Authorization Code + PKCE cho alice, in trace
	./scripts/pkce-login.sh alice

pkce-negative: ## 7 ca PKCE sai phải bị từ chối
	./scripts/pkce-negative.sh

cc:            ## Client Credentials + private_key_jwt + 5 ca sai
	./scripts/client-credentials.sh

tls:           ## Kiểm gateway chỉ nói TLS 1.3
	./scripts/check-tls.sh

gateway-test:  ## Kiểm đầu-cuối P1 (:8443) và P0 (:8444)
	./scripts/gateway-test.sh 8443
	./scripts/gateway-test.sh 8444

failclosed:    ## Dừng auth-svc → P1/P2 403; dừng/treo OPA → P1 503 (SR-11), rồi bật lại
	./scripts/failclosed-test.sh

# --- Tuần 5: OPA (PDP) ---

policy-test:   ## opa fmt + opa check --strict + opa test (chạy bằng image OPA, không cần cài opa)
	@test -z "$$(docker run --rm -v $(CURDIR)/policy:/policy:ro $(OPA_IMAGE) fmt --list /policy)" || { echo "opa fmt: file chưa đúng định dạng"; exit 1; }
	docker run --rm -v $(CURDIR)/policy:/policy:ro $(OPA_IMAGE) check --strict /policy
	docker run --rm -v $(CURDIR)/policy:/policy:ro $(OPA_IMAGE) test /policy -v

authz-test:    ## RBAC/ABAC đầu-cuối qua P1 bằng token thật của 4 user + batch-worker
	./scripts/authz-test.sh

# --- Tuần 6: DPoP (P2 :8445) ---

dpop-client:   ## Áp client web-app-dpop từ idp/realm-topic09.json vào Keycloak đang chạy (không xoá realm)
	./scripts/kc-apply-client.sh web-app-dpop

dpop-login:    ## Auth Code + PKCE + DPoP cho alice, in trace + 7 ca ở token endpoint
	@mkdir -p -m 700 secrets/dpop
	./scripts/dpop-login.sh alice secrets/dpop/alice.pem

dpop-test:     ## P2 đầu-cuối: replay, token bị trộm, 14 ca proof sai, hạ cấp sang Bearer
	./scripts/dpop-test.sh

# --- Tuần 7: object-level / property-level ở backend ---

object-authz-test: ## BOLA/BFLA/property-level đầu-cuối (P1 + P0), log 2 tầng gateway ↔ backend
	./scripts/object-authz-test.sh

# --- Tuần 8: telemetry → SIEM (Vector → OpenSearch) ---

schema-test:   ## Log THÔ của 5 nguồn ↔ telemetry/schema.json (27 trường mục 13.1 đề bài)
	./scripts/telemetry-schema-test.sh

vector-validate: ## Kiểm vector.yaml + unit test đường ống + schema/allow-list/mapping khớp nhau (không cần lab chạy)
	docker run --rm --network none -e SIEM_HMAC_KEY=$(VECTOR_TEST_KEY) -v $(CURDIR)/telemetry/vector:/etc/vector:ro $(VECTOR_IMAGE) validate --no-environment /etc/vector/vector.yaml
	docker run --rm --network none -e SIEM_HMAC_KEY=$(VECTOR_TEST_KEY) -v $(CURDIR)/telemetry/vector:/etc/vector:ro $(VECTOR_IMAGE) test /etc/vector/vector.yaml /etc/vector/tests.yaml
	python3 telemetry/schema_check.py self
	python3 telemetry/schema_check.py sync

siem-mapping:  ## Sinh lại mapping OpenSearch từ telemetry/schema.json (chạy sau khi sửa schema, rồi `make up`)
	python3 telemetry/schema_check.py mapping --write

siem-test:     ## Đường ống đầu-cuối: 5 nguồn → Vector → OpenSearch, HMAC, chèn token, scanner, mapping strict
	./scripts/siem-test.sh

siem-scan:     ## Scanner SR-10: tìm token/khoá/mã uỷ quyền/bí mật/định danh thô trong SIEM và dataset/
	./scripts/siem-scan.sh

siem-search:   ## In 20 sự kiện mới nhất trong SIEM (OpenSearch không có port → gọi từ trong container)
	@$(COMPOSE) exec -T opensearch curl -s -H 'Content-Type: application/json' 'http://127.0.0.1:9200/topic09-events/_search?size=20' \
	  -d '{"sort":[{"event_time":"desc"}]}' | python3 -c 'import json,sys; [print(json.dumps(h["_source"], ensure_ascii=False, sort_keys=True)) for h in json.load(sys.stdin)["hits"]["hits"]]'

evidence:      ## Chạy lại mọi kiểm tra tuần 3–8 và lưu vào docs/evidence, docs/traces
	./scripts/check-realm.sh > docs/evidence/realm-topic09-$$(date +%F).txt
	./scripts/token-claims.sh > docs/evidence/token-claims-$$(date +%F).txt
	./scripts/pkce-login.sh alice > docs/traces/pkce-auth-code-$$(date +%F).txt
	./scripts/pkce-negative.sh > docs/evidence/pkce-negative-$$(date +%F).txt
	./scripts/client-credentials.sh > docs/traces/client-credentials-$$(date +%F).txt
	./scripts/check-tls.sh > docs/evidence/tls13-$$(date +%F).txt
	./scripts/gateway-test.sh 8443 > docs/evidence/gateway-p1-$$(date +%F).txt
	./scripts/gateway-test.sh 8444 > docs/evidence/gateway-p0-$$(date +%F).txt
	./scripts/failclosed-test.sh > docs/evidence/failclosed-$$(date +%F).txt
	./scripts/authz-test.sh > docs/evidence/authz-opa-p1-$$(date +%F).txt
	@mkdir -p -m 700 secrets/dpop
	./scripts/dpop-login.sh alice secrets/dpop/alice.pem > docs/traces/dpop-token-$$(date +%F).txt
	./scripts/dpop-test.sh > docs/evidence/dpop-p2-$$(date +%F).txt
	./scripts/object-authz-test.sh > docs/evidence/object-authz-$$(date +%F).txt
	./scripts/telemetry-schema-test.sh > docs/evidence/telemetry-schema-$$(date +%F).txt
	./scripts/siem-test.sh > docs/evidence/siem-pipeline-$$(date +%F).txt
	./scripts/smoke-test.sh > docs/evidence/smoke-test-$$(date +%F).txt
