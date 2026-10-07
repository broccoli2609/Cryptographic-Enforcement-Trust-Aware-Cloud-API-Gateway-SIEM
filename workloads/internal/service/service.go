// Package service là phần khung dùng chung cho các backend của lab:
// health check, log JSON, timeout chống request treo và tắt máy êm.
//
// Hiện tại backend chưa có nghiệp vụ: mọi route ngoài /healthz trả 501.
// Tuần 7 sẽ thêm kiểm tra object-level (orders-api) và property-level (profile-api).
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Config là cấu hình tối thiểu của một backend.
type Config struct {
	Name string // tên service, ghi vào mọi dòng log
	Addr string // địa chỉ lắng nghe, ví dụ ":8081"
}

// ConfigFromEnv đọc LISTEN_ADDR từ biến môi trường, không có thì dùng giá trị mặc định.
func ConfigFromEnv(name, defaultAddr string) Config {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = defaultAddr
	}
	return Config{Name: name, Addr: addr}
}

// NewLogger tạo logger JSON ghi ra stdout. Docker gom stdout của container,
// tuần 8 Vector sẽ đọc từ đó và đẩy về SIEM.
func NewLogger(w io.Writer, service string) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, nil)).With("service", service)
}

// NewHandler dựng router: GET /healthz trả 200, mọi route khác trả 501.
func NewHandler(service string, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": service})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not_implemented"})
	})
	return logRequests(logger, mux)
}

// statusRecorder ghi lại mã HTTP mà handler đã trả để đưa vào log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// logRequests ghi một dòng log cho mỗi request.
//
// Hai quyết định bảo mật (SR-10 trong threat model):
//   - KHÔNG ghi header nào, đặc biệt là Authorization và DPoP: token thô không được vào log.
//   - Ghi route theo mẫu (r.Pattern, ví dụ "GET /healthz") thay vì đường dẫn thật,
//     để ID đơn hàng hay ID người dùng không lọt vào SIEM.
func logRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		logger.Info("request",
			"event_time", start.UTC().Format(time.RFC3339Nano),
			"request_id", requestID(r),
			"method", r.Method,
			"route_template", r.Pattern,
			"status_code", rec.status,
			"duration_ms", float64(time.Since(start).Microseconds())/1000,
		)
	})
}

// requestID lấy X-Request-Id do Envoy gắn (từ tuần 4), cắt tối đa 64 ký tự
// để kẻ tấn công không nhồi được chuỗi dài vào log.
func requestID(r *http.Request) string {
	id := r.Header.Get("X-Request-Id")
	if len(id) > 64 {
		id = id[:64]
	}
	return id
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Run chạy HTTP server cho đến khi nhận SIGINT/SIGTERM, rồi tắt êm trong tối đa 10 giây.
// Các timeout và MaxHeaderBytes giới hạn tài nguyên một client có thể giữ (liên quan T10).
func Run(cfg Config, handler http.Handler, logger *slog.Logger) error {
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10, // 16 KiB
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// Healthcheck gọi GET /healthz trên chính container và trả mã thoát 0 (khoẻ) hoặc 1.
// Image distroless không có curl hay shell, nên Docker gọi "/app -healthcheck" thay thế.
func Healthcheck(addr string) int {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "địa chỉ không hợp lệ:", addr)
		return 1
	}
	if host == "" || host == "0.0.0.0" || strings.HasPrefix(host, "::") {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
