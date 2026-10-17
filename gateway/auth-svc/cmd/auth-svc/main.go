// Lệnh auth-svc: server gRPC ext_authz của gateway (profile P1, tuần 4).
//
// Chạy server:            auth-svc
// Kiểm sức khoẻ (Docker): auth-svc -healthcheck
//
// Cấu hình qua biến môi trường. Bốn biến bảo mật BẮT BUỘC, không có giá trị mặc định —
// thiếu là dừng ngay (fail fast) thay vì chạy với cấu hình đoán:
//
//	OIDC_ISSUER   iss phải khớp chính xác, ví dụ http://localhost:8080/realms/topic09
//	JWKS_URL      URL JWKS ghim cứng (không lấy từ token), ví dụ http://keycloak:8080/realms/topic09/protocol/openid-connect/certs
//	AUDIENCE      aud bắt buộc, ví dụ topic09-api
//	ALLOWED_ALGS  allow-list alg, phân cách bằng dấu phẩy, ví dụ RS256
//
// Tuỳ chọn: LISTEN_ADDR (:9191), TOKEN_TYPE (Bearer), CLOCK_SKEW (30s), JWKS_TTL (5m).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"topic09-lab/gateway/auth-svc/internal/authz"
	"topic09-lab/gateway/auth-svc/internal/jwtverify"
)

type config struct {
	Addr        string
	Issuer      string
	JWKSURL     string
	Audience    string
	AllowedAlgs []string
	TokenType   string
	ClockSkew   time.Duration
	JWKSTTL     time.Duration
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "gọi gRPC health check rồi thoát với mã 0 (khoẻ) hoặc 1")
	flag.Parse()

	addr := envOr("LISTEN_ADDR", ":9191")
	if *healthcheck {
		os.Exit(runHealthcheck(addr))
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "auth-svc")
	cfg, err := loadConfig(addr)
	if err != nil {
		logger.Error("invalid config", "error", err.Error())
		os.Exit(1)
	}
	if err := run(cfg, logger); err != nil {
		logger.Error("server stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(cfg config, logger *slog.Logger) error {
	cache := jwtverify.NewJWKSCache(jwtverify.JWKSConfig{
		URL:        cfg.JWKSURL,
		TTL:        cfg.JWKSTTL,
		MinRefetch: 10 * time.Second,
		StaleGrace: 10 * time.Minute,
	})
	verifier, err := jwtverify.New(jwtverify.Config{
		Issuer:      cfg.Issuer,
		Audience:    cfg.Audience,
		AllowedAlgs: cfg.AllowedAlgs,
		TokenType:   cfg.TokenType,
		ClockSkew:   cfg.ClockSkew,
	}, cache)
	if err != nil {
		return err
	}

	// Làm nóng JWKS cache. Lỗi chỉ ghi log: auth-svc vẫn chạy, nhưng mọi request bị từ chối
	// cho tới khi tải được JWKS (fail closed), và cache sẽ tự thử lại.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := cache.Refresh(ctx); err != nil {
			logger.Warn("jwks_prefetch_failed", "error", err.Error())
		}
	}()

	lis, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return err
	}
	// Giới hạn kích thước message: CheckRequest chứa header của request (Envoy giới hạn 16 KiB).
	gs := grpc.NewServer(grpc.MaxRecvMsgSize(64<<10), grpc.ConnectionTimeout(5*time.Second))
	authv3.RegisterAuthorizationServer(gs, &authz.Server{Verifier: verifier, Logger: logger})
	hs := health.NewServer()
	healthpb.RegisterHealthServer(gs, hs)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		hs.Shutdown()
		done := make(chan struct{})
		go func() { gs.GracefulStop(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			gs.Stop()
		}
	}()

	logger.Info("listening", "addr", cfg.Addr, "issuer", cfg.Issuer, "audience", cfg.Audience,
		"allowed_algs", strings.Join(cfg.AllowedAlgs, ","), "token_type", cfg.TokenType,
		"clock_skew", cfg.ClockSkew.String(), "jwks_ttl", cfg.JWKSTTL.String())
	if err := gs.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

func loadConfig(addr string) (config, error) {
	cfg := config{
		Addr:      addr,
		Issuer:    os.Getenv("OIDC_ISSUER"),
		JWKSURL:   os.Getenv("JWKS_URL"),
		Audience:  os.Getenv("AUDIENCE"),
		TokenType: envOr("TOKEN_TYPE", "Bearer"),
	}
	for _, a := range strings.Split(os.Getenv("ALLOWED_ALGS"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			cfg.AllowedAlgs = append(cfg.AllowedAlgs, a)
		}
	}
	var missing []string
	for name, v := range map[string]string{"OIDC_ISSUER": cfg.Issuer, "JWKS_URL": cfg.JWKSURL, "AUDIENCE": cfg.Audience} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(cfg.AllowedAlgs) == 0 {
		missing = append(missing, "ALLOWED_ALGS")
	}
	if len(missing) > 0 {
		return cfg, fmt.Errorf("missing required env: %s", strings.Join(missing, ", "))
	}
	var err error
	if cfg.ClockSkew, err = time.ParseDuration(envOr("CLOCK_SKEW", "30s")); err != nil || cfg.ClockSkew < 0 || cfg.ClockSkew > 2*time.Minute {
		return cfg, errors.New("CLOCK_SKEW must be a duration between 0 and 2m")
	}
	if cfg.JWKSTTL, err = time.ParseDuration(envOr("JWKS_TTL", "5m")); err != nil || cfg.JWKSTTL < 10*time.Second {
		return cfg, errors.New("JWKS_TTL must be a duration >= 10s")
	}
	return cfg, nil
}

// runHealthcheck gọi gRPC health service trên chính container. Image distroless không có
// shell hay grpc_health_probe, nên Docker gọi "/app -healthcheck" thay thế.
func runHealthcheck(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "địa chỉ không hợp lệ:", addr)
		return 1
	}
	conn, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		fmt.Fprintln(os.Stderr, "not serving:", err)
		return 1
	}
	return 0
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
