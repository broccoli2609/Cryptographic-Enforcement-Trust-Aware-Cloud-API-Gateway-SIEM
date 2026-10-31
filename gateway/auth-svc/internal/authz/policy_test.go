package authz

// Test cho bước hỏi OPA (tuần 5): SR-06 (PEP làm theo PDP), SR-11 (OPA lỗi → từ chối),
// luật policy.md (input chỉ từ claim đã kiểm), SR-10 (log có policy_version, không có path thật).

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"topic09-lab/gateway/auth-svc/internal/jwtverify"
	"topic09-lab/gateway/auth-svc/internal/policy"
)

func TestCheckSendsVerifiedClaimsToPolicy(t *testing.T) {
	var logs bytes.Buffer
	p := &fakePolicy{dec: opaAllow}
	resp, _ := newServerWithPolicy(jwtverify.ReasonBadSignature, &logs, p).Check(context.Background(),
		checkReq("/orders/42?code=SECRET#frag", map[string]string{"authorization": "Bearer " + goodToken}))
	if resp.GetOkResponse() == nil {
		t.Fatalf("OPA cho qua thì phải OkResponse, nhận %v", resp)
	}
	want := policy.Input{Method: "GET", Path: "/orders/42", Subject: policy.Subject{
		Sub: "a6dd1608-sub", ClientID: "web-app", Roles: []string{"employee"}, Dept: "sales", Tier: "standard"}}
	if fmt.Sprint(p.got) != fmt.Sprint(want) {
		t.Fatalf("input gửi OPA:\n nhận %+v\n muốn %+v", p.got, want)
	}
}

// Kẻ tấn công tự gửi header "danh tính" để nâng quyền — input của OPA không được đổi.
func TestCheckIgnoresClientIdentityHeadersForPolicy(t *testing.T) {
	var logs bytes.Buffer
	p := &fakePolicy{dec: opaAllow}
	_, _ = newServerWithPolicy(jwtverify.ReasonBadSignature, &logs, p).Check(context.Background(),
		checkReq("/orders/1", map[string]string{
			"authorization": "Bearer " + goodToken,
			"x-user":        "admin", "x-user-roles": "manager,hr", "x-user-dept": "hr", "x-user-tier": "premium",
		}))
	s := p.got.Subject
	if s.Sub != "a6dd1608-sub" || fmt.Sprint(s.Roles) != "[employee]" || s.Dept != "sales" || s.Tier != "standard" {
		t.Fatalf("header client lọt vào input của OPA: %+v", s)
	}
}

func TestCheckDeniesWith403WhenPolicyDenies(t *testing.T) {
	var logs bytes.Buffer
	p := &fakePolicy{dec: policy.Decision{Allow: false, PolicyID: "topic09.authz", PolicyVersion: "1.0.0", Route: "orders.delete", Reason: "role_not_allowed", DecisionID: "opa-9"}}
	resp, _ := newServerWithPolicy(jwtverify.ReasonBadSignature, &logs, p).Check(context.Background(),
		checkReq("/orders/1", map[string]string{"authorization": "Bearer " + goodToken}))
	d := resp.GetDeniedResponse()
	if d == nil || d.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("OPA từ chối thì phải 403, nhận %v", resp)
	}
	if d.GetBody() != `{"error":"forbidden"}` {
		t.Fatalf("body chỉ được có mã chung, nhận %q", d.GetBody())
	}
	for _, want := range []string{`"decision":"deny"`, `"reason":"role_not_allowed"`, `"policy_id":"topic09.authz"`,
		`"policy_version":"1.0.0"`, `"policy_route":"orders.delete"`, `"opa_decision_id":"opa-9"`} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log thiếu %s:\n%s", want, logs.String())
		}
	}
}

// SR-11: mọi kiểu lỗi khi hỏi OPA → 503, KHÔNG BAO GIỜ cho qua. Mỗi lỗi một test con.
func TestCheckFailsClosedWhenPolicyErrors(t *testing.T) {
	for _, e := range []error{policy.ErrUnavailable, policy.ErrBadResponse, policy.ErrUndefined, fmt.Errorf("lạ")} {
		t.Run(e.Error(), func(t *testing.T) {
			var logs bytes.Buffer
			// Cố ý để dec.Allow = true đi kèm lỗi: server phải tin lỗi, không tin decision.
			p := &fakePolicy{dec: opaAllow, err: fmt.Errorf("wrap: %w", e)}
			resp, _ := newServerWithPolicy(jwtverify.ReasonBadSignature, &logs, p).Check(context.Background(),
				checkReq("/orders/1", map[string]string{"authorization": "Bearer " + goodToken}))
			if resp.GetOkResponse() != nil {
				t.Fatal("OPA lỗi mà vẫn cho qua (fail open)")
			}
			if d := resp.GetDeniedResponse(); d == nil || d.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
				t.Fatalf("muốn 503, nhận %v", resp)
			}
		})
	}
}

func TestCheckFailsClosedWhenPolicyNotConfigured(t *testing.T) {
	var logs bytes.Buffer
	s := &Server{Verifier: fakeVerifier{}, Logger: newServer("", &logs).Logger}
	resp, _ := s.Check(context.Background(), checkReq("/orders/1", map[string]string{"authorization": "Bearer " + goodToken}))
	if resp.GetOkResponse() != nil || !strings.Contains(logs.String(), `"reason":"policy_not_configured"`) {
		t.Fatalf("thiếu PDP mà vẫn cho qua: %v\n%s", resp, logs.String())
	}
}

// Token hỏng thì dừng ở bước kiểm token: không tốn một lần gọi OPA (kiểm rẻ trước, T10).
func TestCheckDoesNotCallPolicyForInvalidToken(t *testing.T) {
	var logs bytes.Buffer
	p := &fakePolicy{dec: opaAllow}
	_, _ = newServerWithPolicy(jwtverify.ReasonBadSignature, &logs, p).Check(context.Background(),
		checkReq("/orders/1", map[string]string{"authorization": "Bearer forged.token.sig"}))
	_, _ = newServerWithPolicy(jwtverify.ReasonBadSignature, &logs, p).Check(context.Background(),
		checkReq("/orders/1", map[string]string{}))
	if p.calls != 0 {
		t.Fatalf("OPA bị gọi %d lần cho token không hợp lệ", p.calls)
	}
}

func TestPathOnly(t *testing.T) {
	for in, want := range map[string]string{
		"/orders/1": "/orders/1", "/orders/1?code=x": "/orders/1", "/orders#f": "/orders", "/a?b#c": "/a", "": "",
	} {
		if got := pathOnly(in); got != want {
			t.Errorf("pathOnly(%q) = %q, muốn %q", in, got, want)
		}
	}
}
