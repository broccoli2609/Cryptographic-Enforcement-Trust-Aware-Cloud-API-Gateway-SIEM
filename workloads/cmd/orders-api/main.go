// Lệnh orders-api: backend rỗng của lab Topic 09.
//
// Chạy server:          orders-api
// Kiểm sức khoẻ (Docker): orders-api -healthcheck
package main

import (
	"flag"
	"os"

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
	if err := service.Run(cfg, service.NewHandler(cfg.Name, logger), logger); err != nil {
		logger.Error("server stopped", "error", err.Error())
		os.Exit(1)
	}
}
