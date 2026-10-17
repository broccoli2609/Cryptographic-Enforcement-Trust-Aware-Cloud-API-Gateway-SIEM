// Package authz là server gRPC ext_authz mà Envoy gọi cho MỖI request (profile P1).
//
// Envoy gửi CheckRequest (method, path, header…); server trả OkResponse (cho qua, kèm header
// danh tính) hoặc DeniedResponse (từ chối). Envoy đặt failure_mode_allow: false, nên auth-svc
// lỗi, timeout hay sập đều thành 403 — không bao giờ thành "cho qua" (SR-11).
//
// Tuần 5: sau bước kiểm token, server gọi OPA để quyết định theo role/route/ABAC.
package authz

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"topic09-lab/gateway/auth-svc/internal/jwtverify"
)

// TokenVerifier là phần kiểm token mà server cần (jwtverify.Verifier thoả interface này).
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (*jwtverify.Claims, error)
}

// Server cài đặt envoy.service.auth.v3.Authorization.
type Server struct {
	authv3.UnimplementedAuthorizationServer
	Verifier TokenVerifier
	Logger   *slog.Logger
}

// decision gom thông tin của một quyết định để ghi đúng một dòng log.
type decision struct {
	requestID, method, route string
	allow                    bool
	reason                   string
	principal, clientID      string
	alg, kid                 string
}

// Check được Envoy gọi cho mỗi request. Không bao giờ trả error gRPC cho các ca từ chối:
// luôn trả DeniedResponse tường minh để mã HTTP và header WWW-Authenticate đúng chuẩn.
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	start := time.Now()
	h := req.GetAttributes().GetRequest().GetHttp()
	hdr := h.GetHeaders() // Envoy đưa tên header về chữ thường
	d := decision{
		requestID: clip(hdr["x-request-id"], 64),
		method:    clip(h.GetMethod(), 16),
		route:     routeGroup(h.GetPath()),
	}

	token, ok := bearerToken(hdr["authorization"])
	if !ok {
		d.reason = "missing_token"
		return s.deny(d, start, typev3.StatusCode_Unauthorized, `Bearer realm="topic09"`, "unauthorized"), nil
	}

	claims, err := s.Verifier.Verify(ctx, token)
	if err != nil {
		d.reason = "invalid_token"
		var e *jwtverify.Error
		if errors.As(err, &e) {
			d.reason, d.alg, d.kid = string(e.Reason), e.Alg, e.Kid
		}
		if d.reason == string(jwtverify.ReasonJWKS) {
			// Lỗi phía server (không tải được khoá) — vẫn từ chối, nhưng báo 503 cho đúng bản chất.
			return s.deny(d, start, typev3.StatusCode_ServiceUnavailable, "", "temporarily_unavailable"), nil
		}
		// Client chỉ biết "invalid_token"; lý do chi tiết chỉ nằm trong log (không giúp kẻ tấn công dò).
		return s.deny(d, start, typev3.StatusCode_Unauthorized,
			`Bearer realm="topic09", error="invalid_token"`, "invalid_token"), nil
	}

	d.allow, d.reason = true, "ok"
	d.principal, d.clientID, d.alg, d.kid = claims.Subject, claims.ClientID, claims.Alg, claims.Kid
	s.log(d, start)
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{
			// Danh tính đã kiểm, ghi đè mọi giá trị có sẵn (Envoy cũng đã xoá X-User của client).
			Headers: []*corev3.HeaderValueOption{header("x-user", claims.Subject)},
			// Backend không cần token → không chuyển token vào vùng backend (giảm chỗ lộ token).
			HeadersToRemove: []string{"authorization"},
		}},
	}, nil
}

func (s *Server) deny(d decision, start time.Time, code typev3.StatusCode, wwwAuth, errCode string) *authv3.CheckResponse {
	s.log(d, start)
	headers := []*corev3.HeaderValueOption{header("content-type", "application/json")}
	if wwwAuth != "" {
		headers = append(headers, header("www-authenticate", wwwAuth)) // RFC 6750 §3
	}
	grpcCode := codes.Unauthenticated
	if code == typev3.StatusCode_ServiceUnavailable {
		grpcCode = codes.Unavailable
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(grpcCode)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
			Status:  &typev3.HttpStatus{Code: code},
			Headers: headers,
			Body:    `{"error":"` + errCode + `"}`,
		}},
	}
}

// log ghi một dòng JSON cho mỗi quyết định. SR-10: không ghi token, header, path thật hay
// query string; route ghi theo nhóm (/orders, /profile). principal là sub — tuần 8 Vector
// sẽ băm HMAC trước khi vào SIEM.
func (s *Server) log(d decision, start time.Time) {
	result := "deny"
	if d.allow {
		result = "allow"
	}
	s.Logger.Info("authz_decision",
		"event_time", start.UTC().Format(time.RFC3339Nano),
		"request_id", d.requestID,
		"method", d.method,
		"route_group", d.route,
		"decision", result,
		"reason", d.reason,
		"principal", d.principal,
		"client_id", d.clientID,
		"token_alg", d.alg,
		"token_kid", d.kid,
		"duration_ms", float64(time.Since(start).Microseconds())/1000,
	)
}

// bearerToken tách token khỏi "Authorization: Bearer <token>" (RFC 6750 §2.1; tên scheme
// không phân biệt hoa thường). Token phải liền, không khoảng trắng, không dấu phẩy (dấu phẩy
// xuất hiện khi client gửi nhiều header Authorization và Envoy gộp lại).
func bearerToken(v string) (string, bool) {
	scheme, tok, found := strings.Cut(v, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || tok == "" || strings.ContainsAny(tok, " ,\t") {
		return "", false
	}
	return tok, true
}

// routeGroup đổi path thật thành nhóm route cố định để ghi log — không lọt ID đơn hàng,
// ID người dùng hay query string (có thể chứa code=...) vào SIEM.
func routeGroup(path string) string {
	p, _, _ := strings.Cut(path, "?")
	for _, g := range []string{"/orders", "/profile"} {
		if p == g || strings.HasPrefix(p, g+"/") {
			return g
		}
	}
	return "other"
}

func header(k, v string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: k, Value: v},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
