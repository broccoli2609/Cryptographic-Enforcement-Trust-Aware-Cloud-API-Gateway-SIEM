// Package service là phần khung dùng chung cho các backend của lab:
// health check, log JSON, danh tính do gateway gắn, timeout chống request treo và tắt máy êm.
//
// Nghiệp vụ (tuần 7) nằm ở package orders và profiles; mỗi backend đăng ký route của mình qua
// tham số register của NewHandler. Kiểm quyền mức đối tượng/thuộc tính nằm ở đó (SR-06).
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
	"slices"
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

// ---------------------------------------------------------------- Danh tính từ gateway

// maxIdentityLen giới hạn độ dài X-User (sub của Keycloak là UUID 36 ký tự).
const maxIdentityLen = 128

// maxRoles: số role tối đa đọc từ X-User-Roles (auth-svc gửi tối đa 8).
const maxRoles = 8

// Identity là danh tính mà gateway đã kiểm và gắn vào request.
//
// Backend tin các header này chỉ vì vị trí mạng (TB3 — yếu, đã ghi trong threat model): backend
// không có "ports:", chỉ Envoy gọi được, và Envoy xoá mọi header X-User* client tự gửi.
//
//	X-User        sub                     — P0, P1, P2 đều có
//	X-User-Roles  role nối bằng ","        — chỉ P1/P2 (auth-svc gửi). P0 không có → không role
//	X-User-Dept   phòng ban                — chỉ P1/P2
//
// Thiếu role hay dept thì người gọi có ÍT quyền hơn, không bao giờ nhiều hơn (an toàn khi lỗi).
type Identity struct {
	Subject string
	Roles   []string
	Dept    string
}

// Has cho biết người gọi có role r không.
func (id Identity) Has(r string) bool { return slices.Contains(id.Roles, r) }

// Lỗi khi đọc danh tính. Hai lỗi khác mã HTTP: thiếu → 401, sai → 400.
var (
	ErrMissingIdentity = errors.New("missing_identity")
	ErrInvalidIdentity = errors.New("invalid_identity")
)

// IdentityFrom đọc danh tính do gateway gắn. Không có X-User nghĩa là request không đi qua
// gateway (T5) → lỗi, không bao giờ đoán danh tính.
func IdentityFrom(r *http.Request) (Identity, error) {
	sub := r.Header.Get("X-User")
	switch {
	case sub == "":
		return Identity{}, ErrMissingIdentity
	case len(sub) > maxIdentityLen:
		return Identity{}, ErrInvalidIdentity
	}
	id := Identity{Subject: sub}
	for _, role := range strings.Split(r.Header.Get("X-User-Roles"), ",") {
		role = strings.TrimSpace(role)
		// Role lạ bị bỏ qua (không báo lỗi): bỏ một role chỉ làm người gọi ít quyền hơn.
		if SafeAttr(role) && !id.Has(role) && len(id.Roles) < maxRoles {
			id.Roles = append(id.Roles, role)
		}
	}
	if d := r.Header.Get("X-User-Dept"); SafeAttr(d) {
		id.Dept = d
	}
	return id, nil
}

// SafeAttr: 1–32 ký tự, bắt đầu bằng chữ thường, chỉ gồm a-z 0-9 "-" "_" (cùng luật với auth-svc).
func SafeAttr(s string) bool {
	if len(s) == 0 || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- Quyết định của backend → log

// authzNote là chỗ handler ghi lại quyết định phân quyền của BACKEND để middleware log ra
// cùng dòng với route và mã HTTP. Nhờ vậy một dòng log trả lời được: request này gateway đã cho
// qua (có trong log auth-svc với cùng request_id), backend có chặn không, vì sao.
type authzNote struct {
	object   string // "allow" | "deny"; rỗng = route không kiểm đối tượng (healthz, whoami)
	reason   string // mã lý do cố định, ví dụ "owner", "not_owner", "dept_manager"
	redacted string // property-level: tên trường đã bị ẩn khỏi response, ví dụ "salary_band"
}

type noteKey struct{}

func noteFrom(r *http.Request) *authzNote {
	n, _ := r.Context().Value(noteKey{}).(*authzNote)
	return n
}

// Allow / Deny ghi quyết định object-level của backend (trường backend_object_authz trong log).
// reason phải là mã cố định — KHÔNG đưa ID đối tượng hay danh tính vào (SR-10).
func Allow(r *http.Request, reason string) { record(r, "allow", reason) }

// Deny: xem Allow.
func Deny(r *http.Request, reason string) { record(r, "deny", reason) }

func record(r *http.Request, decision, reason string) {
	if n := noteFrom(r); n != nil {
		n.object, n.reason = decision, reason
	}
}

// Redacted ghi tên trường đã bị ẩn khỏi response vì người gọi không đủ quyền (property-level).
func Redacted(r *http.Request, field string) {
	if n := noteFrom(r); n != nil {
		n.redacted = field
	}
}

// ---------------------------------------------------------------- Router

// NewHandler dựng router của một backend. prefix là đường dẫn gốc mà gateway chuyển vào
// service này (orders-api: "/orders", profile-api: "/profile"). register thêm route nghiệp vụ
// (nil = không có):
//
//	GET /healthz          200 — cho Docker healthcheck, không đi qua gateway
//	GET <prefix>/whoami   200 + danh tính gateway đã đặt trong X-User (tuần 4)
//	route của register    nghiệp vụ + kiểm object/property (tuần 7)
//	mọi route khác        404
func NewHandler(service, prefix string, logger *slog.Logger, register func(mux *http.ServeMux)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": service})
	})
	// whoami trả lại danh tính mà gateway gắn vào request. Hai mục đích:
	//   - chứng minh request có token hợp lệ đi qua gateway tới được backend (mốc M1);
	//   - kiểm Envoy đã xoá X-User do client tự gửi (luật 5): client gửi "X-User: admin"
	//     thì ở đây phải thấy sub thật trong token, không phải "admin".
	// Giá trị X-User KHÔNG được ghi vào log (log chỉ có route, mã HTTP, thời gian).
	mux.HandleFunc("GET "+prefix+"/whoami", func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequireIdentity(w, r)
		if !ok {
			return
		}
		WriteJSON(w, http.StatusOK, map[string]string{"service": service, "user": id.Subject})
	})
	if register != nil {
		register(mux)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, http.StatusNotFound, "not_found")
	})
	return logRequests(logger, mux)
}

// RequireIdentity đọc danh tính; thiếu/sai thì tự trả 401/400 và trả ok = false.
// Ghi luôn quyết định deny vào log: request tới backend mà không có X-User là dấu hiệu
// có ai đó gọi vòng qua gateway (T5, kịch bản S8).
func RequireIdentity(w http.ResponseWriter, r *http.Request) (Identity, bool) {
	id, err := IdentityFrom(r)
	switch {
	case errors.Is(err, ErrMissingIdentity):
		Deny(r, "missing_identity")
		WriteError(w, http.StatusUnauthorized, "missing_identity")
	case err != nil:
		Deny(r, "invalid_identity")
		WriteError(w, http.StatusBadRequest, "invalid_identity")
	default:
		return id, true
	}
	return Identity{}, false
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
//   - KHÔNG ghi header nào, đặc biệt là Authorization, DPoP, X-User: token thô và danh tính
//     không vào log của backend (danh tính nằm ở log auth-svc, nối bằng request_id).
//   - Ghi route theo mẫu (r.Pattern, ví dụ "GET /orders/{id}") thay vì đường dẫn thật,
//     để ID đơn hàng hay ID người dùng không lọt vào SIEM.
//
// Tuần 7 thêm 3 trường: backend_object_authz (allow/deny/not_applicable), backend_authz_reason,
// backend_redacted_fields — bằng chứng "gateway cho qua, backend chặn" (BOLA) và property-level.
//
// Tuần 8: tên trường theo telemetry/schema.json — mọi khoá ở đây đều có trong schema (trừ
// service/msg/time/level mà Vector đổi thành source/event_type hoặc bỏ). route_template chỉ còn
// đường dẫn mẫu ("/orders/{id}"), method nằm ở trường method.
func logRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		note := &authzNote{}
		r = r.WithContext(context.WithValue(r.Context(), noteKey{}, note))
		next.ServeHTTP(rec, r)
		object := note.object
		if object == "" {
			object = "not_applicable"
		}
		logger.Info("request",
			"event_time", start.UTC().Format(time.RFC3339Nano),
			"request_id", requestID(r),
			"method", r.Method,
			"route_template", routeTemplate(r.Pattern),
			"status_code", rec.status,
			"backend_object_authz", object,
			"backend_authz_reason", note.reason,
			"backend_redacted_fields", note.redacted,
			"duration_ms", float64(time.Since(start).Microseconds())/1000,
		)
	})
}

// routeTemplate bỏ method khỏi mẫu của http.ServeMux: "GET /orders/{id}" → "/orders/{id}".
// Mẫu không có method (route bắt-tất-cả "/") giữ nguyên. Kết quả luôn là mẫu đã đăng ký trong
// code, không bao giờ là đường dẫn client gửi.
func routeTemplate(pattern string) string {
	if _, path, ok := strings.Cut(pattern, " "); ok {
		return path
	}
	return pattern
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

// ---------------------------------------------------------------- JSON vào/ra

// WriteJSON ghi body JSON với mã HTTP cho trước.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // dữ liệu theo người gọi: proxy/trình duyệt không được lưu
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// WriteError ghi {"error": code}. code là mã cố định, không chứa dữ liệu của request.
func WriteError(w http.ResponseWriter, status int, code string) {
	WriteJSON(w, status, map[string]string{"error": code})
}

// MaxBodyBytes: body JSON tối đa 4 KiB — đủ cho một đơn hàng/hồ sơ, chặn body khổng lồ (T10).
const MaxBodyBytes = 4 << 10

// ErrUnknownField: body có trường không nằm trong allow-list (mass assignment, OWASP API3).
var ErrUnknownField = errors.New("unknown_field")

// ReadJSON đọc đúng một object JSON vào dst. Trường lạ → ErrUnknownField: client không gán
// được những trường server không mời (owner_id, dept, salary_band…) — chống mass assignment.
func ReadJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field") {
			return ErrUnknownField
		}
		return errors.New("invalid_body")
	}
	if dec.More() { // hai object liền nhau: không đoán ý client
		return errors.New("invalid_body")
	}
	return nil
}

// ---------------------------------------------------------------- Chạy server

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
