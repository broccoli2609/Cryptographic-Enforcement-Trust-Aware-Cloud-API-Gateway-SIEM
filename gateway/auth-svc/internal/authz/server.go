// Package authz là server gRPC ext_authz mà Envoy gọi cho MỖI request (profile P1 và P2).
//
// Envoy gửi CheckRequest (method, path, header…); server trả OkResponse (cho qua, kèm header
// danh tính) hoặc DeniedResponse (từ chối). Envoy đặt failure_mode_allow: false, nên auth-svc
// lỗi, timeout hay sập đều thành 403 — không bao giờ thành "cho qua" (SR-11).
//
// Thứ tự trong Check — bước nào hỏng cũng dừng ngay và từ chối:
//
//	P1 (:8443): "Authorization: Bearer" → kiểm JWT (typ=Bearer) → token KHÔNG được gắn DPoP → OPA
//	P2 (:8445): "Authorization: DPoP"   → kiểm JWT (typ=DPoP) → có cnf.jkt → kiểm DPoP proof → OPA
//
// Profile do Envoy ghi vào context_extensions["profile"] theo listener — client không đặt được.
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

	"topic09-lab/gateway/auth-svc/internal/dpop"
	"topic09-lab/gateway/auth-svc/internal/jwtverify"
	"topic09-lab/gateway/auth-svc/internal/policy"
)

// Tên profile trong context_extensions của Envoy (gateway/envoy.yaml).
const (
	ProfileP1 = "p1" // bearer JWT chặt + OPA
	ProfileP2 = "p2" // P1 + DPoP (sender-constrained token, RFC 9449)
)

// TokenVerifier là phần kiểm token mà server cần (jwtverify.Verifier thoả interface này).
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (*jwtverify.Claims, error)
}

// ProofVerifier là phần kiểm DPoP proof mà server cần (dpop.Verifier thoả interface này).
type ProofVerifier interface {
	Verify(r dpop.Request) (*dpop.Result, error)
	AllowedAlgs() []string
}

// PolicyDecider là phần hỏi PDP mà server cần (policy.Client thoả interface này).
type PolicyDecider interface {
	Decide(ctx context.Context, in policy.Input) (policy.Decision, error)
}

// Server cài đặt envoy.service.auth.v3.Authorization.
type Server struct {
	authv3.UnimplementedAuthorizationServer
	Verifier     TokenVerifier // P1: access token có typ = "Bearer"
	DPoPVerifier TokenVerifier // P2: access token có typ = "DPoP" (cùng issuer, cùng JWKS)
	Proofs       ProofVerifier // P2: DPoP proof
	Policy       PolicyDecider
	Logger       *slog.Logger
}

// decision gom thông tin của một quyết định để ghi đúng một dòng log.
type decision struct {
	requestID, method, route string
	profile                  string
	allow                    bool
	reason                   string
	principal, clientID      string
	alg, kid                 string
	// Từ OPA (tuần 5): bản policy nào ra quyết định, theo route mẫu nào.
	policyID, policyVersion, policyRoute, opaDecisionID string
	// DPoP (tuần 6): thumbprint khoá CÔNG KHAI trong token (cnf.jkt) và trong proof — cho hunt H2.
	cnfJKT, proofJKT string
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
		profile:   clip(req.GetAttributes().GetContextExtensions()["profile"], 8),
	}

	var (
		claims *jwtverify.Claims
		denied *authv3.CheckResponse
	)
	switch d.profile {
	case ProfileP1:
		claims, denied = s.authenticateBearer(ctx, &d, start, hdr)
	case ProfileP2:
		claims, denied = s.authenticateDPoP(ctx, &d, start, h, hdr)
	default:
		// Envoy không gắn profile (cấu hình sai) → không đoán, từ chối.
		d.reason = "unknown_profile"
		return s.deny(d, start, typev3.StatusCode_ServiceUnavailable, "", "temporarily_unavailable"), nil
	}
	if denied != nil {
		return denied, nil
	}

	// --- Hỏi OPA (tuần 5, SR-06). Input chỉ gồm claim ĐÃ KIỂM + method + đường dẫn: header
	// client tự gửi (x-user-roles, x-user-dept…) không bao giờ vào input.
	if s.Policy == nil { // cấu hình thiếu PDP → không bao giờ cho qua
		d.reason = "policy_not_configured"
		return s.deny(d, start, typev3.StatusCode_ServiceUnavailable, "", "temporarily_unavailable"), nil
	}
	dec, err := s.Policy.Decide(ctx, policy.Input{
		Method: h.GetMethod(),
		Path:   pathOnly(h.GetPath()),
		Subject: policy.Subject{
			Sub: claims.Subject, ClientID: claims.ClientID,
			Roles: claims.Roles, Dept: claims.Dept, Tier: claims.Tier,
		},
	})
	if err != nil {
		// SR-11: OPA sập / timeout / trả bậy → TỪ CHỐI. 503 vì lỗi nằm ở phía server.
		d.reason = policyErrorReason(err)
		return s.deny(d, start, typev3.StatusCode_ServiceUnavailable, "", "temporarily_unavailable"), nil
	}
	d.policyID, d.policyVersion, d.policyRoute, d.opaDecisionID = dec.PolicyID, dec.PolicyVersion, dec.Route, dec.DecisionID
	if !dec.Allow {
		// Token hợp lệ nhưng không đủ quyền → 403. Lý do (role_not_allowed, abac_dept…) chỉ ở log.
		d.reason = dec.Reason
		return s.deny(d, start, typev3.StatusCode_Forbidden, "", "forbidden"), nil
	}

	d.allow, d.reason = true, "ok"
	s.log(d, start)
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{
			// Danh tính đã kiểm, ghi đè mọi giá trị có sẵn (Envoy cũng đã xoá X-User của client).
			Headers: []*corev3.HeaderValueOption{header("x-user", claims.Subject)},
			// Backend không cần token hay proof → không chuyển vào vùng backend (giảm chỗ lộ token).
			HeadersToRemove: []string{"authorization", "dpop"},
		}},
	}, nil
}

// authenticateBearer: P1. Trả claims, hoặc DeniedResponse nếu phải từ chối.
func (s *Server) authenticateBearer(ctx context.Context, d *decision, start time.Time, hdr map[string]string) (*jwtverify.Claims, *authv3.CheckResponse) {
	const challenge = `Bearer realm="topic09"`
	token, ok := schemeToken(hdr["authorization"], "Bearer")
	if !ok {
		d.reason = "missing_token"
		return nil, s.deny(*d, start, typev3.StatusCode_Unauthorized, challenge, "unauthorized")
	}
	claims, denied := s.verifyToken(ctx, d, start, s.Verifier, token, challenge)
	if denied != nil {
		return nil, denied
	}
	// RFC 9449 §7.2: resource server nhận cả Bearer lẫn DPoP PHẢI từ chối token đã gắn DPoP mà
	// được gửi như bearer — nếu không, kẻ trộm token DPoP chỉ cần đổi scheme là vượt được P2.
	// (Keycloak còn đặt typ=DPoP nên bước kiểm typ đã chặn trước; kiểm thêm ở đây để không phụ
	// thuộc vào một chi tiết riêng của Keycloak.)
	if claims.CnfJKT != "" {
		d.reason, d.cnfJKT = "dpop_bound_token_as_bearer", claims.CnfJKT
		return nil, s.deny(*d, start, typev3.StatusCode_Unauthorized, challenge+`, error="invalid_token"`, "invalid_token")
	}
	return claims, nil
}

// authenticateDPoP: P2 (tuần 6, SR-04). Token phải được gắn khoá, và request phải kèm proof hợp lệ.
func (s *Server) authenticateDPoP(ctx context.Context, d *decision, start time.Time, h *authv3.AttributeContext_HttpRequest, hdr map[string]string) (*jwtverify.Claims, *authv3.CheckResponse) {
	if s.DPoPVerifier == nil || s.Proofs == nil { // cấu hình thiếu → không bao giờ cho qua
		d.reason = "dpop_not_configured"
		return nil, s.deny(*d, start, typev3.StatusCode_ServiceUnavailable, "", "temporarily_unavailable")
	}
	// RFC 9449 §7.1: báo client những alg proof mà server nhận.
	challenge := `DPoP algs="` + strings.Join(s.Proofs.AllowedAlgs(), " ") + `"`
	token, ok := schemeToken(hdr["authorization"], "DPoP")
	if !ok {
		// Gồm cả ca kẻ trộm gửi token DPoP với scheme Bearer tới P2.
		d.reason = "missing_token"
		return nil, s.deny(*d, start, typev3.StatusCode_Unauthorized, challenge, "unauthorized")
	}
	claims, denied := s.verifyToken(ctx, d, start, s.DPoPVerifier, token, challenge)
	if denied != nil {
		return nil, denied
	}
	if claims.CnfJKT == "" {
		d.reason = "token_not_dpop_bound"
		return nil, s.deny(*d, start, typev3.StatusCode_Unauthorized, challenge+`, error="invalid_token"`, "invalid_token")
	}
	d.cnfJKT = claims.CnfJKT

	res, err := s.Proofs.Verify(dpop.Request{
		Proof:       hdr["dpop"],
		Method:      h.GetMethod(),
		URL:         requestURL(h),
		AccessToken: token,
		BoundJKT:    claims.CnfJKT,
	})
	if err != nil {
		d.reason = "dpop_invalid"
		var e *dpop.Error
		if errors.As(err, &e) {
			d.reason, d.proofJKT = string(e.Reason), e.ProofJKT
		}
		if d.reason == string(dpop.ReasonCacheFull) {
			// Trần bộ nhớ chống replay đã chạm (T10): từ chối, không xoá mục còn hạn.
			return nil, s.deny(*d, start, typev3.StatusCode_ServiceUnavailable, "", "temporarily_unavailable")
		}
		return nil, s.deny(*d, start, typev3.StatusCode_Unauthorized, challenge+`, error="invalid_dpop_proof"`, "invalid_dpop_proof")
	}
	d.proofJKT = res.JKT
	return claims, nil
}

// verifyToken kiểm access token bằng verifier của profile; lỗi thì trả DeniedResponse.
func (s *Server) verifyToken(ctx context.Context, d *decision, start time.Time, v TokenVerifier, token, challenge string) (*jwtverify.Claims, *authv3.CheckResponse) {
	claims, err := v.Verify(ctx, token)
	if err != nil {
		d.reason = "invalid_token"
		var e *jwtverify.Error
		if errors.As(err, &e) {
			d.reason, d.alg, d.kid = string(e.Reason), e.Alg, e.Kid
		}
		if d.reason == string(jwtverify.ReasonJWKS) {
			// Lỗi phía server (không tải được khoá) — vẫn từ chối, nhưng báo 503 cho đúng bản chất.
			return nil, s.deny(*d, start, typev3.StatusCode_ServiceUnavailable, "", "temporarily_unavailable")
		}
		// Client chỉ biết "invalid_token"; lý do chi tiết chỉ nằm trong log (không giúp kẻ tấn công dò).
		return nil, s.deny(*d, start, typev3.StatusCode_Unauthorized, challenge+`, error="invalid_token"`, "invalid_token")
	}
	d.principal, d.clientID, d.alg, d.kid = claims.Subject, claims.ClientID, claims.Alg, claims.Kid
	return claims, nil
}

// requestURL dựng URI của request để so với htu: scheme + authority + path, không query.
// Host chỉ có thể là tên đã khai trong virtual host của Envoy (Host lạ → Envoy trả 404 trước).
func requestURL(h *authv3.AttributeContext_HttpRequest) string {
	scheme := h.GetScheme()
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + h.GetHost() + pathOnly(h.GetPath())
}

func (s *Server) deny(d decision, start time.Time, code typev3.StatusCode, wwwAuth, errCode string) *authv3.CheckResponse {
	s.log(d, start)
	headers := []*corev3.HeaderValueOption{header("content-type", "application/json")}
	// Envoy không tự gắn X-Request-Id vào response do ext_authz từ chối. Gắn lại để client báo
	// lỗi kèm mã này và người vận hành tìm đúng dòng log (UUID do Envoy sinh, không phải của client).
	if d.requestID != "" {
		headers = append(headers, header("x-request-id", d.requestID))
	}
	if wwwAuth != "" {
		headers = append(headers, header("www-authenticate", wwwAuth)) // RFC 6750 §3
	}
	grpcCode := codes.Unauthenticated
	switch code {
	case typev3.StatusCode_ServiceUnavailable:
		grpcCode = codes.Unavailable
	case typev3.StatusCode_Forbidden:
		grpcCode = codes.PermissionDenied
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
		"profile", d.profile,
		"method", d.method,
		"route_group", d.route,
		"decision", result,
		"reason", d.reason,
		"principal", d.principal,
		"client_id", d.clientID,
		"token_alg", d.alg,
		"token_kid", d.kid,
		"policy_id", d.policyID,
		"policy_version", d.policyVersion,
		"policy_route", d.policyRoute,
		"opa_decision_id", d.opaDecisionID,
		"cnf_jkt", d.cnfJKT,
		"proof_jkt", d.proofJKT,
		"duration_ms", float64(time.Since(start).Microseconds())/1000,
	)
}

// policyErrorReason đổi lỗi khi hỏi OPA thành mã lý do cố định cho log (không ghi chi tiết
// lỗi mạng — có thể chứa địa chỉ nội bộ, và không giúp gì cho hunt).
func policyErrorReason(err error) string {
	for _, e := range []error{policy.ErrUnavailable, policy.ErrBadResponse, policy.ErrUndefined} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return "policy_error"
}

// pathOnly bỏ query string và fragment: OPA quyết định theo đường dẫn, còn query có thể
// chứa dữ liệu nhạy cảm (code=…) mà PDP không cần thấy.
func pathOnly(p string) string {
	p, _, _ = strings.Cut(p, "?")
	p, _, _ = strings.Cut(p, "#")
	return p
}

// schemeToken tách token khỏi "Authorization: <scheme> <token>" — scheme "Bearer" (RFC 6750
// §2.1) hoặc "DPoP" (RFC 9449 §7.1); tên scheme không phân biệt hoa thường. Token phải liền,
// không khoảng trắng, không dấu phẩy (dấu phẩy xuất hiện khi client gửi nhiều header
// Authorization và Envoy gộp lại).
func schemeToken(v, want string) (string, bool) {
	scheme, tok, found := strings.Cut(v, " ")
	if !found || !strings.EqualFold(scheme, want) || tok == "" || strings.ContainsAny(tok, " ,\t") {
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
