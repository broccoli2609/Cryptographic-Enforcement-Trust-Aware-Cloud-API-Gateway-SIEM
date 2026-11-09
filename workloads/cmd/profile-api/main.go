// Lệnh profile-api: backend hồ sơ nhân viên của lab Topic 09 (kiểm quyền mức thuộc tính từ tuần 7).
//
// Chạy server:          profile-api
// Kiểm sức khoẻ (Docker): profile-api -healthcheck
package main

import (
	"flag"
	"os"

	"topic09-lab/workloads/fixtures"
	"topic09-lab/workloads/internal/profiles"
	"topic09-lab/workloads/internal/service"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "gọi /healthz rồi thoát với mã 0 (khoẻ) hoặc 1")
	flag.Parse()

	cfg := service.ConfigFromEnv("profile-api", ":8082")
	if *healthcheck {
		os.Exit(service.Healthcheck(cfg.Addr))
	}

	logger := service.NewLogger(os.Stdout, cfg.Name)
	store, err := profiles.NewStore(fixtures.Profiles)
	if err != nil {
		logger.Error("fixture invalid", "error", err.Error())
		os.Exit(1)
	}
	if err := service.Run(cfg, service.NewHandler(cfg.Name, "/profile", logger, store.Register), logger); err != nil {
		logger.Error("server stopped", "error", err.Error())
		os.Exit(1)
	}
}
