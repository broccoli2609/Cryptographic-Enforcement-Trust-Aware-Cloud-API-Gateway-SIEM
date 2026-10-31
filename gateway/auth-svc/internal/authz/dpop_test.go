package authz

// Test cho profile P2 (tuần 6, SR-04) và chống hạ cấp DPoP → Bearer ở P1 (RFC 9449 §7.2).
// Bộ kiểm proof thật đã có test riêng trong internal/dpop; ở đây dùng bản giả để kiểm cách
// Server nối các bước: scheme, loại token, cnf.jkt, proof, mã HTTP, header, log.

import (
	"bytes"
	"context"
	"strings"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"topic09-lab/gateway/auth-svc/internal/dpop"
	"topic09-lab/gateway/auth-svc/internal/jwtverify"
)

const (
	dpopToken = "eyJkcG9w.eyJib3VuZA.c2ln"
	goodJKT   = "HqrvtgmxPP60WHHV98ypg5V2l8rNrDMol6TW80JDLXM"
)

// fakeDPoPTokens: dpopToken là token typ=DPoP có cnf.jkt; goodToken (bearer) bị verifier P2 từ chối wrong_typ.
type fakeDPoPTokens struct{ noCnf bool }

func (f fakeDPoPTokens) Verify(_ context.Context, tok string) (*jwtverify.Claims, error) {
	if tok == dpopToken {
		c := &jwtverify.Claims{Subject: "a6dd1608-sub", ClientID: "web-app-dpop", Roles: []string{"employee"}, Dept: "sales", Alg: "RS256", Kid: "kid-1", CnfJKT: goodJKT}
		if f.noCnf {
			c.CnfJKT = ""
		}
		return c, nil
	}
	return nil, &jwtverify.Error{Reason: jwtverify.ReasonWrongType}
}

// fakeProofs ghi lại request nhận được; trả lỗi cho sẵn.
type fakeProofs struct {
	err   error
	calls int
	got   dpop.Request
}

func (f *fakeProofs) Verify(r dpop.Request) (*dpop.Result, error) {
	f.calls++
	f.got = r
	if f.err != nil {
		return nil, f.err
	}
	return &dpop.Result{JKT: r.BoundJKT, Alg: "ES256"}, nil
}
func (f *fakeProofs) AllowedAlgs() []string { return []string{"ES256"} }

func newP2Server(logs *bytes.Buffer, p *fakeProofs, tokens TokenVerifier) *Server {
	s := newServer(jwtverify.ReasonBadSignature, logs)
	s.DPoPVerifier, s.Proofs = tokens, p
	return s
}

func p2Req(method, path string, hdr map[string]string) *authv3.CheckRequest {
	return checkReqProfile(ProfileP2, method, path, hdr)
}

func wwwAuth(t *testing.T, r *authv3.CheckResponse) string {
	t.Helper()
	for _, h := range r.GetDeniedResponse().GetHeaders() {
		if h.GetHeader().GetKey() == "www-authenticate" {
			return h.GetHeader().GetValue()
		}
	}
	return ""
}

func TestP2AllowsBoundTokenWithValidProof(t *testing.T) {
	var logs bytes.Buffer
	p := &fakeProofs{}
	resp, _ := newP2Server(&logs, p, fakeDPoPTokens{}).Check(context.Background(),
		p2Req("POST", "/orders?x=1", map[string]string{"authorization": "DPoP " + dpopToken, "dpop": "proof.jwt.sig"}))
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatalf("token gắn khoá + proof hợp lệ phải qua, nhận %v", resp)
	}
	// Server phải đưa cho bộ kiểm proof đúng các giá trị lấy từ request và từ token ĐÃ KIỂM.
	want := dpop.Request{Proof: "proof.jwt.sig", Method: "POST", URL: "https://localhost:8445/orders", AccessToken: dpopToken, BoundJKT: goodJKT}
	if p.got != want {
		t.Fatalf("dpop.Request:\n nhận %+v\n muốn %+v", p.got, want)
	}
	rm := strings.Join(ok.GetHeadersToRemove(), ",")
	if rm != "authorization,dpop" {
		t.Fatalf("phải xoá cả Authorization lẫn DPoP trước khi vào backend, nhận %q", rm)
	}
	for _, want := range []string{`"profile":"p2"`, `"decision":"allow"`, `"cnf_jkt":"` + goodJKT, `"proof_jkt":"` + goodJKT} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log thiếu %s:\n%s", want, logs.String())
		}
	}
}

// Mỗi ca sai của P2 một test con: mã 401, WWW-Authenticate: DPoP, lý do trong log.
func TestP2Rejects(t *testing.T) {
	cases := []struct {
		name     string
		hdr      map[string]string
		tokens   TokenVerifier
		proofErr error
		reason   string
		www      string
	}{
		{"token DPoP gửi bằng scheme Bearer", map[string]string{"authorization": "Bearer " + dpopToken, "dpop": "p"}, fakeDPoPTokens{}, nil, "missing_token", `DPoP algs="ES256"`},
		{"không có Authorization", map[string]string{"dpop": "p"}, fakeDPoPTokens{}, nil, "missing_token", `DPoP algs="ES256"`},
		{"token bearer thường (typ=Bearer) với scheme DPoP", map[string]string{"authorization": "DPoP " + goodToken, "dpop": "p"}, fakeDPoPTokens{}, nil, "wrong_typ", `error="invalid_token"`},
		{"token typ=DPoP nhưng không có cnf.jkt", map[string]string{"authorization": "DPoP " + dpopToken, "dpop": "p"}, fakeDPoPTokens{noCnf: true}, nil, "token_not_dpop_bound", `error="invalid_token"`},
		{"proof replay", map[string]string{"authorization": "DPoP " + dpopToken, "dpop": "p"}, fakeDPoPTokens{}, &dpop.Error{Reason: dpop.ReasonReplay, ProofJKT: goodJKT}, "dpop_replay", `error="invalid_dpop_proof"`},
		{"proof ký bằng khoá khác", map[string]string{"authorization": "DPoP " + dpopToken, "dpop": "p"}, fakeDPoPTokens{}, &dpop.Error{Reason: dpop.ReasonKeyMismatch, ProofJKT: "attacker-jkt"}, "dpop_key_mismatch", `error="invalid_dpop_proof"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			resp, _ := newP2Server(&logs, &fakeProofs{err: tc.proofErr}, tc.tokens).Check(context.Background(), p2Req("GET", "/orders/whoami", tc.hdr))
			d := resp.GetDeniedResponse()
			if d == nil || d.GetStatus().GetCode() != typev3.StatusCode_Unauthorized {
				t.Fatalf("muốn 401, nhận %v", resp)
			}
			if w := wwwAuth(t, resp); !strings.HasPrefix(w, "DPoP ") || !strings.Contains(w, tc.www) {
				t.Fatalf("WWW-Authenticate = %q, muốn chứa %q (RFC 9449 §7.1)", w, tc.www)
			}
			if !strings.Contains(logs.String(), `"reason":"`+tc.reason+`"`) {
				t.Fatalf("log thiếu reason %s:\n%s", tc.reason, logs.String())
			}
		})
	}
}

// Hunt H2: log ghi cả khoá trong token lẫn khoá trong proof khi lệch.
func TestP2LogsBothThumbprintsOnKeyMismatch(t *testing.T) {
	var logs bytes.Buffer
	s := newP2Server(&logs, &fakeProofs{err: &dpop.Error{Reason: dpop.ReasonKeyMismatch, ProofJKT: "attacker-jkt"}}, fakeDPoPTokens{})
	_, _ = s.Check(context.Background(), p2Req("GET", "/orders/whoami", map[string]string{"authorization": "DPoP " + dpopToken, "dpop": "p"}))
	if !strings.Contains(logs.String(), `"cnf_jkt":"`+goodJKT+`"`) || !strings.Contains(logs.String(), `"proof_jkt":"attacker-jkt"`) {
		t.Fatalf("log thiếu cnf_jkt/proof_jkt:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), dpopToken) {
		t.Fatal("log chứa access token")
	}
}

func TestP2CacheFullIs503(t *testing.T) {
	var logs bytes.Buffer
	s := newP2Server(&logs, &fakeProofs{err: &dpop.Error{Reason: dpop.ReasonCacheFull}}, fakeDPoPTokens{})
	resp, _ := s.Check(context.Background(), p2Req("GET", "/orders/whoami", map[string]string{"authorization": "DPoP " + dpopToken, "dpop": "p"}))
	if d := resp.GetDeniedResponse(); d == nil || d.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
		t.Fatalf("cache đầy phải 503 (từ chối, không cho qua), nhận %v", resp)
	}
}

// Proof hỏng thì không tốn một lần gọi OPA.
func TestP2DoesNotCallPolicyWhenProofInvalid(t *testing.T) {
	var logs bytes.Buffer
	pol := &fakePolicy{dec: opaAllow}
	s := newP2Server(&logs, &fakeProofs{err: &dpop.Error{Reason: dpop.ReasonHTUMismatch}}, fakeDPoPTokens{})
	s.Policy = pol
	_, _ = s.Check(context.Background(), p2Req("GET", "/orders/whoami", map[string]string{"authorization": "DPoP " + dpopToken, "dpop": "p"}))
	if pol.calls != 0 {
		t.Fatal("proof hỏng mà vẫn hỏi OPA")
	}
}

func TestP2FailsClosedWhenDPoPNotConfigured(t *testing.T) {
	var logs bytes.Buffer
	resp, _ := newServer(jwtverify.ReasonBadSignature, &logs).Check(context.Background(),
		p2Req("GET", "/orders/whoami", map[string]string{"authorization": "DPoP " + dpopToken, "dpop": "p"}))
	if resp.GetOkResponse() != nil || !strings.Contains(logs.String(), `"reason":"dpop_not_configured"`) {
		t.Fatalf("P2 thiếu bộ kiểm DPoP mà vẫn cho qua: %v", resp)
	}
}

// RFC 9449 §7.2: ở P1, token đã gắn DPoP gửi như bearer phải bị từ chối (chống hạ cấp).
func TestP1RejectsDPoPBoundTokenAsBearer(t *testing.T) {
	var logs bytes.Buffer
	s := newServer(jwtverify.ReasonBadSignature, &logs)
	s.Verifier = fakeDPoPTokens{} // giả sử issuer khác đặt typ=Bearer nhưng có cnf
	resp, _ := s.Check(context.Background(), checkReq("/orders/whoami", map[string]string{"authorization": "Bearer " + dpopToken}))
	if d := resp.GetDeniedResponse(); d == nil || d.GetStatus().GetCode() != typev3.StatusCode_Unauthorized {
		t.Fatalf("muốn 401, nhận %v", resp)
	}
	if !strings.Contains(logs.String(), `"reason":"dpop_bound_token_as_bearer"`) {
		t.Fatalf("log thiếu lý do:\n%s", logs.String())
	}
}

// P1 không nhận scheme DPoP (P1 không biết kiểm proof).
func TestP1RejectsDPoPScheme(t *testing.T) {
	var logs bytes.Buffer
	resp, _ := newServer(jwtverify.ReasonBadSignature, &logs).Check(context.Background(),
		checkReq("/orders/whoami", map[string]string{"authorization": "DPoP " + goodToken}))
	if resp.GetOkResponse() != nil {
		t.Fatal("P1 nhận scheme DPoP")
	}
}

// Envoy không gắn profile (cấu hình sai) hoặc profile lạ → từ chối, không đoán là P1.
func TestCheckFailsClosedOnMissingOrUnknownProfile(t *testing.T) {
	for _, p := range []string{"", "p0", "P1", "p2 "} {
		var logs bytes.Buffer
		resp, _ := newServer(jwtverify.ReasonBadSignature, &logs).Check(context.Background(),
			checkReqProfile(p, "GET", "/orders/whoami", map[string]string{"authorization": "Bearer " + goodToken}))
		if d := resp.GetDeniedResponse(); d == nil || d.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
			t.Fatalf("profile %q: muốn 503, nhận %v", p, resp)
		}
	}
}

func TestRequestURL(t *testing.T) {
	h := checkReqProfile(ProfileP2, "GET", "/orders/1?code=x#f", nil).GetAttributes().GetRequest().GetHttp()
	if got := requestURL(h); got != "https://localhost:8445/orders/1" {
		t.Fatalf("requestURL = %q", got)
	}
}
