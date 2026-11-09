// Lệnh orders-api: backend đơn hàng của lab Topic 09 (kiểm quyền mức đối tượng từ tuần 7).
//
// Chạy server:          orders-api
// Kiểm sức khoẻ (Docker): orders-api -healthcheck
package main

import (
	"flag"
	"os"

	"topic09-lab/workloads/fixtures"
	"topic09-lab/workloads/internal/orders"
	"topic09-lab/workloads/internal/service"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "gọi /healthz rồi thoát với mã 0 (khoẻ) hoặc 1")
	flag.Parse()

	cfg := service.ConfigFromEnv("orders-api", ":8081")
	if *healthcheck {
		os.Exit(service.Healthcheck(cfg.Addr))
	}

	logger := service.NewLogger(os.Stdout, cfg.Name)
	store, err := orders.NewStore(fixtures.Orders)
	if err != nil {
		logger.Error("fixture invalid", "error", err.Error())
		os.Exit(1)
	}
	if err := service.Run(cfg, service.NewHandler(cfg.Name, "/orders", logger, store.Register), logger); err != nil {
		logger.Error("server stopped", "error", err.Error())
		os.Exit(1)
	}
}
