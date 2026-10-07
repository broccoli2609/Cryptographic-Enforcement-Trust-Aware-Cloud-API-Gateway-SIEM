COMPOSE ?= docker compose

.PHONY: up down ps logs smoke test env-check perf-check

up:            ## Build và chạy lab nền
	$(COMPOSE) up -d --build

down:          ## Dừng lab (giữ dữ liệu Keycloak)
	$(COMPOSE) down

ps:            ## Trạng thái các container
	$(COMPOSE) ps

logs:          ## Xem log liên tục
	$(COMPOSE) logs -f --tail=50

smoke:         ## Kiểm nhanh lab sau khi up
	./scripts/smoke-test.sh

test:          ## Unit test của backend
	cd workloads && go test ./...

env-check:     ## Kiểm Docker, Go, perf trên máy
	./scripts/check-env.sh

perf-check:    ## Kiểm perf đếm được cycles không, lưu bằng chứng
	./scripts/check-perf.sh
