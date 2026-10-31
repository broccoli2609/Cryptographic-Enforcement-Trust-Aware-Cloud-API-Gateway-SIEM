package authz

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"topic09-lab/gateway/auth-svc/internal/jwtverify"
	"topic09-lab/gateway/auth-svc/internal/policy"
)

const goodToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"

// fakeVerifier: token goodToken hợp lệ, mọi token khác bị từ chối với lý do cho sẵn.
type fakeVerifier struct{ reason jwtverify.Reason }

func (f fakeVerifier) Verify(_ context.Context, tok string) (*jwtverify.Claims, error) {
	if tok == goodToken {
		return &jwtverify.Claims{Subject: "a6dd1608-sub", ClientID: "web-app", Alg: "RS256", Kid: "kid-1",
			Roles: []string{"employee"}, Dept: "sales", Tier: "standard"}, nil
	}
	return nil, &jwtverify.Error{Reason: f.reason, Alg: "HS256", Kid: "kid-1"}
}

// fakePolicy thay OPA: ghi lại input nhận được, trả quyết định / lỗi cho sẵn.
type fakePolicy struct {
	dec   policy.Decision
	err   error
	calls int
	got   policy.Input
}

func (f *fakePolicy) Decide(_ context.Context, in policy.Input) (policy.Decision, error) {
	f.calls++
	f.got = in
	return f.dec, f.err
}

var opaAllow = policy.Decision{Allow: true, PolicyID: "topic09.authz", PolicyVersion: "1.0.0", Route: "orders.whoami", Reason: "ok", DecisionID: "opa-1"}

func newServer(reason jwtverify.Reason, logs *bytes.Buffer) *Server {
	return newServerWithPolicy(reason, logs, &fakePolicy{dec: opaAllow})
}

func newServerWithPolicy(reason jwtverify.Reason, logs *bytes.Buffer, p PolicyDecider) *Server {
	return &Server{Verifier: fakeVerifier{reason: reason}, Policy: p, Logger: slog.New(slog.NewJSONHandler(logs, nil))}
}

// checkReq: request tới listener P1 (Envoy gắn context_extensions profile=p1).
func checkReq(path string, headers map[string]string) *authv3.CheckRequest {
	return checkReqProfile(ProfileP1, "GET", path, headers)
}

func checkReqProfile(profile, method, path string, headers map[string]string) *authv3.CheckRequest {
	ext := map[string]string{}
	if profile != "" {
		ext["profile"] = profile
	}
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		ContextExtensions: ext,
		Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
			Method: method, Scheme: "https", Host: "localhost:8445", Path: path, Headers: headers,
		}},
	}}
}

func TestCheckAllowsValidTokenAndSetsIdentity(t *testing.T) {
	var logs bytes.Buffer
	resp, err := newServer(jwtverify.ReasonBadSignature, &logs).Check(context.Background(),
		checkReq("/orders/whoami", map[string]string{"authorization": "Bearer " + goodToken}))
	if err != nil {
		t.Fatal(err)
	}
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatalf("token hợp lệ phải được cho qua, nhận %v", resp)
	}
	if len(ok.GetHeaders()) != 1 || ok.GetHeaders()[0].GetHeader().GetKey() != "x-user" ||
		ok.GetHeaders()[0].GetHeader().GetValue() != "a6dd1608-sub" {
		t.Fatalf("phải đặt x-user = sub, nhận %v", ok.GetHeaders())
	}
	if rm := ok.GetHeadersToRemove(); len(rm) != 2 || rm[0] != "authorization" || rm[1] != "dpop" {
		t.Fatalf("phải xoá Authorization và DPoP trước khi vào backend, nhận %v", rm)
	}
}

func TestCheckDeniesWhenNoBearerToken(t *testing.T) {
	for name, hdr := range map[string]map[string]string{
		"không có Authorization":       {},
		"scheme Basic":                 {"authorization": "Basic YWxpY2U6cHc="},
		"Bearer rỗng":                  {"authorization": "Bearer "},
		"hai header Authorization gộp": {"authorization": "Bearer " + goodToken + ", Bearer other"},
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			resp, _ := newServer(jwtverify.ReasonBadSignature, &logs).Check(context.Background(), checkReq("/orders/whoami", hdr))
			d := resp.GetDeniedResponse()
			if d == nil || d.GetStatus().GetCode() != typev3.StatusCode_Unauthorized {
				t.Fatalf("muốn 401, nhận %v", resp)
			}
		})
	}
}

func TestCheckDeniesInvalidTokenWith401AndWWWAuthenticate(t *testing.T) {
	var logs bytes.Buffer
	resp, _ := newServer(jwtverify.ReasonAlgNotAllowed, &logs).Check(context.Background(),
		checkReq("/orders/whoami", map[string]string{"authorization": "Bearer forged.token.sig"}))
	d := resp.GetDeniedResponse()
	if d == nil || d.GetStatus().GetCode() != typev3.StatusCode_Unauthorized {
		t.Fatalf("muốn 401, nhận %v", resp)
	}
	var www string
	for _, h := range d.GetHeaders() {
		if h.GetHeader().GetKey() == "www-authenticate" {
			www = h.GetHeader().GetValue()
		}
	}
	if !strings.Contains(www, `error="invalid_token"`) {
		t.Fatalf(`thiếu WWW-Authenticate: Bearer error="invalid_token" (RFC 6750), nhận %q`, www)
	}
	// Client chỉ nhận mã chung; lý do chi tiết chỉ có trong log.
	if strings.Contains(d.GetBody(), "alg") || !strings.Contains(logs.String(), `"reason":"alg_not_allowed"`) {
		t.Fatalf("body = %q, log = %s", d.GetBody(), logs.String())
	}
}

// SR-11: không tải được JWKS → vẫn từ chối (503), không bao giờ cho qua.
func TestCheckFailsClosedWhenJWKSUnavailable(t *testing.T) {
	var logs bytes.Buffer
	resp, _ := newServer(jwtverify.ReasonJWKS, &logs).Check(context.Background(),
		checkReq("/orders/whoami", map[string]string{"authorization": "Bearer some.other.token"}))
	if resp.GetOkResponse() != nil {
		t.Fatal("JWKS không có mà vẫn cho qua")
	}
	if d := resp.GetDeniedResponse(); d == nil || d.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
		t.Fatalf("muốn 503, nhận %v", resp)
	}
}

// SR-10: log quyết định không chứa token, path thật hay query string.
func TestDecisionLogNeverContainsTokenOrRealPath(t *testing.T) {
	var logs bytes.Buffer
	s := newServer(jwtverify.ReasonExpired, &logs)
	_, _ = s.Check(context.Background(), checkReq("/orders/12345?code=SECRETCODE",
		map[string]string{"authorization": "Bearer " + goodToken, "x-request-id": strings.Repeat("r", 300)}))
	_, _ = s.Check(context.Background(), checkReq("/profile/777",
		map[string]string{"authorization": "Bearer eyJleHBpcmVk.eyJwYXlsb2Fk.c2ln"}))

	out := logs.String()
	for _, leak := range []string{"eyJ", "12345", "SECRETCODE", "777", strings.Repeat("r", 65)} {
		if strings.Contains(out, leak) {
			t.Fatalf("log chứa %q:\n%s", leak, out)
		}
	}
	for _, want := range []string{`"route_group":"/orders"`, `"route_group":"/profile"`, `"decision":"allow"`, `"decision":"deny"`, `"reason":"expired"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("log thiếu %s:\n%s", want, out)
		}
	}
}

func TestRouteGroup(t *testing.T) {
	for in, want := range map[string]string{
		"/orders": "/orders", "/orders/7": "/orders", "/orders?x=1": "/orders",
		"/profile/me": "/profile", "/ordersX": "other", "/admin": "other", "": "other",
	} {
		if got := routeGroup(in); got != want {
			t.Errorf("routeGroup(%q) = %q, muốn %q", in, got, want)
		}
	}
}
