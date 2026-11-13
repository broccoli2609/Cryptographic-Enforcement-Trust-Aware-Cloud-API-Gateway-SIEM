package authz

// Test cho tuần 8: dòng log authz_decision phải khớp telemetry/schema.json.
//
//   - Tên trường: mọi khoá trong log phải có trong schema, trừ vài khoá "thô" mà Vector biến
//     đổi hoặc bỏ (principal → principal_hash, aud → aud_hash, service → source…).
//   - Giá trị: token_type, iss, aud, scope_set chỉ có khi token ĐÃ KIỂM; proof_status đúng theo
//     từng ca của P1/P2; policy_eval_us chỉ có khi thật sự gọi OPA.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"topic09-lab/gateway/auth-svc/internal/dpop"
	"topic09-lab/gateway/auth-svc/internal/jwtverify"
	"topic09-lab/gateway/auth-svc/internal/policy"
)

// schemaPath: từ gateway/auth-svc/internal/authz lên gốc repo.
const schemaPath = "../../../../telemetry/schema.json"

// rawOnlyKeys: khoá chỉ có trong log thô, không có trong SIEM (xem "x-raw-only" của schema).
var rawOnlyKeys = []string{"time", "level", "msg", "service", "principal", "aud"}

// fullVerifier trả claims đầy đủ như một access token Keycloak thật (typ, iss, aud, scope).
type fullVerifier struct{ typ, jkt string }

func (f fullVerifier) Verify(_ context.Context, tok string) (*jwtverify.Claims, error) {
	if tok != goodToken && tok != dpopToken {
		return nil, &jwtverify.Error{Reason: jwtverify.ReasonExpired, Alg: "RS256", Kid: "kid-1"}
	}
	return &jwtverify.Claims{
		Subject: "a6dd1608-sub", ClientID: "web-app", Alg: "RS256", Kid: "kid-1",
		Type: f.typ, Issuer: "http://localhost:8080/realms/topic09",
		Audience: []string{"topic09-api", "account"}, Scopes: []string{"email", "openid", "profile"},
		Roles: []string{"employee"}, Dept: "sales", CnfJKT: f.jkt,
	}, nil
}

var opaAllowWithTemplate = policy.Decision{
	Allow: true, PolicyID: "topic09.authz", PolicyVersion: "1.1.0",
	Route: "orders.read", RouteTemplate: "/orders/{id}", Reason: "ok", DecisionID: "0b9f2c1e-opa",
}

// logLines đọc mọi dòng log JSON trong buf.
func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("dòng log không phải JSON: %v\n%s", err, line)
		}
		out = append(out, m)
	}
	return out
}

func lastLog(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	l := logLines(t, buf)
	if len(l) == 0 {
		t.Fatal("không có dòng log nào")
	}
	return l[len(l)-1]
}

// wantFields so từng trường; giá trị nil nghĩa là JSON null.
func wantFields(t *testing.T, log map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		got, ok := log[k]
		if !ok {
			t.Errorf("log thiếu khoá %q", k)
			continue
		}
		if got != v {
			t.Errorf("%s = %#v, muốn %#v", k, got, v)
		}
	}
	if t.Failed() {
		b, _ := json.Marshal(log)
		t.Fatalf("dòng log: %s", b)
	}
}

func p1Server(logs *bytes.Buffer, p PolicyDecider) *Server {
	s := newServerWithPolicy("", logs, p)
	s.Verifier = fullVerifier{typ: "Bearer"}
	return s
}

func p2Server(logs *bytes.Buffer, proofs *fakeProofs) *Server {
	s := newServerWithPolicy("", logs, &fakePolicy{dec: opaAllowWithTemplate})
	s.DPoPVerifier, s.Proofs = fullVerifier{typ: "DPoP", jkt: goodJKT}, proofs
	return s
}

// Mọi khoá của dòng log phải có trong telemetry/schema.json (hoặc là khoá thô đã khai báo),
// và mọi dòng — allow hay deny, P1 hay P2 — có CÙNG một bộ khoá.
func TestDecisionLogKeysAreInTelemetrySchema(t *testing.T) {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("không đọc được schema (test phải chạy trong repo): %v", err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil || len(schema.Properties) == 0 {
		t.Fatalf("schema hỏng: %v", err)
	}

	var logs bytes.Buffer
	bearer := map[string]string{"authorization": "Bearer " + goodToken, "x-request-id": "5f0c7b1e-2a51-4f0e-9a43-0f3f2b6f9c11"}
	dp := map[string]string{"authorization": "DPoP " + dpopToken, "dpop": "p"}
	ctx := context.Background()
	_, _ = p1Server(&logs, &fakePolicy{dec: opaAllowWithTemplate}).Check(ctx, checkReq("/orders/7", bearer))                   // P1 cho qua
	_, _ = p1Server(&logs, &fakePolicy{dec: opaAllowWithTemplate}).Check(ctx, checkReq("/orders/7", map[string]string{}))      // P1 không token
	_, _ = p1Server(&logs, &fakePolicy{err: policy.ErrUnavailable}).Check(ctx, checkReq("/orders/7", bearer))                  // OPA sập
	_, _ = p2Server(&logs, &fakeProofs{}).Check(ctx, p2Req("GET", "/orders/7", dp))                                            // P2 cho qua
	_, _ = p2Server(&logs, &fakeProofs{err: &dpop.Error{Reason: dpop.ReasonReplay}}).Check(ctx, p2Req("GET", "/orders/7", dp)) // P2 replay
	_, _ = p1Server(&logs, &fakePolicy{dec: opaAllowWithTemplate}).Check(ctx, checkReqProfile("", "GET", "/orders/7", bearer)) // thiếu profile

	lines := logLines(t, &logs)
	if len(lines) != 6 {
		t.Fatalf("muốn 6 dòng log, có %d", len(lines))
	}
	var first []string
	for i, l := range lines {
		var keys []string
		for k := range l {
			keys = append(keys, k)
			if _, ok := schema.Properties[k]; !ok && !slices.Contains(rawOnlyKeys, k) {
				t.Errorf("dòng %d: khoá %q không có trong telemetry/schema.json", i, k)
			}
		}
		slices.Sort(keys)
		if i == 0 {
			first = keys
		} else if !slices.Equal(keys, first) {
			t.Errorf("dòng %d có bộ khoá khác dòng 0:\n %v\n %v", i, keys, first)
		}
	}
	// Tên cũ (trước tuần 8) không được còn: hunt query viết theo tên trong schema.
	for _, old := range []string{"reason", "token_alg", "token_kid"} {
		if slices.Contains(first, old) {
			t.Errorf("log còn khoá cũ %q", old)
		}
	}
}

func TestDecisionLogP1AllowHasVerifiedTokenMetadata(t *testing.T) {
	var logs bytes.Buffer
	_, _ = p1Server(&logs, &fakePolicy{dec: opaAllowWithTemplate}).Check(context.Background(),
		checkReq("/orders/7?code=SECRET", map[string]string{"authorization": "Bearer " + goodToken}))
	l := lastLog(t, &logs)
	wantFields(t, l, map[string]any{
		"decision": "allow", "decision_reason": "ok", "profile": "p1",
		"token_type": "bearer", "alg": "RS256", "kid": "kid-1",
		"iss":             "http://localhost:8080/realms/topic09",
		"aud":             "account topic09-api", // sắp xếp → cùng tập audience luôn cho cùng aud_hash
		"scope_set":       "email openid profile",
		"proof_status":    "not_applicable",
		"route_group":     "/orders",
		"route_template":  "/orders/{id}",
		"policy_route":    "orders.read",
		"policy_version":  "1.1.0",
		"opa_decision_id": "0b9f2c1e-opa",
		"cnf_jkt":         "", "proof_jkt": "",
	})
	if us, ok := l["policy_eval_us"].(float64); !ok || us < 0 {
		t.Fatalf("policy_eval_us phải là số ≥ 0 khi đã gọi OPA, nhận %#v", l["policy_eval_us"])
	}
}

// Token không qua bước kiểm: KHÔNG ghi claim nào của nó (typ, iss, aud, scope, sub), chỉ ghi
// alg/kid đọc từ header (đã cắt ngắn) cho hunt H3. Không gọi OPA → policy_eval_us là null.
func TestDecisionLogInvalidTokenHasNoClaims(t *testing.T) {
	var logs bytes.Buffer
	_, _ = p1Server(&logs, &fakePolicy{dec: opaAllowWithTemplate}).Check(context.Background(),
		checkReq("/profile/777", map[string]string{"authorization": "Bearer eyJleHBpcmVk.eyJwYXlsb2Fk.c2ln"}))
	wantFields(t, lastLog(t, &logs), map[string]any{
		"decision": "deny", "decision_reason": "expired",
		"alg": "RS256", "kid": "kid-1",
		"principal": "", "client_id": "", "token_type": "", "iss": "", "aud": "", "scope_set": "",
		"proof_status": "not_applicable", "route_group": "/profile", "route_template": "",
		"policy_id": "", "policy_version": "", "policy_eval_us": nil,
	})
}

// OPA lỗi: vẫn ghi thời gian đã chờ (bằng chứng cho failure injection), route_template rỗng.
func TestDecisionLogPolicyErrorStillHasEvalTime(t *testing.T) {
	var logs bytes.Buffer
	_, _ = p1Server(&logs, &fakePolicy{err: policy.ErrUnavailable}).Check(context.Background(),
		checkReq("/orders/7", map[string]string{"authorization": "Bearer " + goodToken}))
	l := lastLog(t, &logs)
	wantFields(t, l, map[string]any{
		"decision": "deny", "decision_reason": "policy_unavailable",
		"token_type": "bearer", "route_template": "", "policy_id": "",
	})
	if _, ok := l["policy_eval_us"].(float64); !ok {
		t.Fatalf("OPA lỗi vẫn phải ghi policy_eval_us, nhận %#v", l["policy_eval_us"])
	}
}

// proof_status của P2 — mỗi ca một test con.
func TestDecisionLogProofStatus(t *testing.T) {
	bound := map[string]string{"authorization": "DPoP " + dpopToken, "dpop": "p"}
	cases := []struct {
		name     string
		hdr      map[string]string
		proofErr error
		status   string
		decision string
	}{
		{"proof hợp lệ", bound, nil, "valid", "allow"},
		{"proof dùng lại (H1)", bound, &dpop.Error{Reason: dpop.ReasonReplay, ProofJKT: goodJKT}, "replay", "deny"},
		{"proof ký bằng khoá khác (H2)", bound, &dpop.Error{Reason: dpop.ReasonKeyMismatch, ProofJKT: "attacker-jkt"}, "key_mismatch", "deny"},
		{"không có header DPoP", bound, &dpop.Error{Reason: dpop.ReasonMissing}, "missing", "deny"},
		{"htu sai", bound, &dpop.Error{Reason: dpop.ReasonHTUMismatch}, "invalid", "deny"},
		{"chữ ký proof sai", bound, &dpop.Error{Reason: dpop.ReasonBadSignature}, "invalid", "deny"},
		{"lỗi không rõ loại", bound, context.DeadlineExceeded, "invalid", "deny"},
		{"cache jti đầy — chưa khẳng định được", bound, &dpop.Error{Reason: dpop.ReasonCacheFull}, "not_checked", "deny"},
		{"token hỏng — chưa tới bước proof", map[string]string{"authorization": "DPoP forged.token.sig", "dpop": "p"}, nil, "not_checked", "deny"},
		{"không có token — chưa tới bước proof", map[string]string{"dpop": "p"}, nil, "not_checked", "deny"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			_, _ = p2Server(&logs, &fakeProofs{err: tc.proofErr}).Check(context.Background(), p2Req("GET", "/orders/whoami", tc.hdr))
			wantFields(t, lastLog(t, &logs), map[string]any{"profile": "p2", "proof_status": tc.status, "decision": tc.decision})
		})
	}
}

func TestDecisionLogP2AllowIsDPoPToken(t *testing.T) {
	var logs bytes.Buffer
	_, _ = p2Server(&logs, &fakeProofs{}).Check(context.Background(),
		p2Req("GET", "/orders/7", map[string]string{"authorization": "DPoP " + dpopToken, "dpop": "p"}))
	wantFields(t, lastLog(t, &logs), map[string]any{
		"token_type": "DPoP", "proof_status": "valid", "cnf_jkt": goodJKT, "proof_jkt": goodJKT,
		"route_template": "/orders/{id}",
	})
}

// P1 nhận token đã gắn DPoP gửi như bearer: bị từ chối, và proof_status vẫn là not_applicable
// (P1 không kiểm proof) — lý do nằm ở decision_reason.
func TestDecisionLogP1BoundTokenAsBearer(t *testing.T) {
	var logs bytes.Buffer
	s := newServerWithPolicy("", &logs, &fakePolicy{dec: opaAllowWithTemplate})
	s.Verifier = fullVerifier{typ: "Bearer", jkt: goodJKT}
	_, _ = s.Check(context.Background(), checkReq("/orders/7", map[string]string{"authorization": "Bearer " + goodToken}))
	wantFields(t, lastLog(t, &logs), map[string]any{
		"decision": "deny", "decision_reason": "dpop_bound_token_as_bearer",
		"proof_status": "not_applicable", "cnf_jkt": goodJKT,
	})
}

// multiRoleVerifier: token có nhiều role theo thứ tự KHÔNG sắp xếp (như Keycloak có thể trả).
type multiRoleVerifier struct{ claims *jwtverify.Claims }

func (m multiRoleVerifier) Verify(context.Context, string) (*jwtverify.Claims, error) {
	return m.claims, nil
}

// Tuần 8: roles gửi OPA được sắp xếp (decision log của OPA → subject_roles trong SIEM có thứ tự
// cố định). Bản gốc trong claims không bị đổi, và tập role không thêm bớt gì.
func TestCheckSendsSortedRolesToPolicy(t *testing.T) {
	var logs bytes.Buffer
	claims := &jwtverify.Claims{Subject: "sub-dave", ClientID: "web-app", Roles: []string{"manager", "employee", "hr"}, Dept: "sales"}
	p := &fakePolicy{dec: opaAllowWithTemplate}
	s := newServerWithPolicy("", &logs, p)
	s.Verifier = multiRoleVerifier{claims}
	_, _ = s.Check(context.Background(), checkReq("/orders/7", map[string]string{"authorization": "Bearer " + goodToken}))
	if got := strings.Join(p.got.Subject.Roles, ","); got != "employee,hr,manager" {
		t.Fatalf("roles gửi OPA = %q, muốn \"employee,hr,manager\"", got)
	}
	if got := strings.Join(claims.Roles, ","); got != "manager,employee,hr" {
		t.Fatalf("claims gốc bị sắp xếp lại: %q", got)
	}
}

func TestTokenTypeLabel(t *testing.T) {
	for in, want := range map[string]string{"Bearer": "bearer", "bearer": "bearer", "DPoP": "DPoP", "dpop": "DPoP", "ID": "", "Refresh": "", "": ""} {
		if got := tokenTypeLabel(in); got != want {
			t.Errorf("tokenTypeLabel(%q) = %q, muốn %q", in, got, want)
		}
	}
}

func TestAudienceLabelIsOrderIndependent(t *testing.T) {
	a := audienceLabel([]string{"topic09-api", "account"})
	b := audienceLabel([]string{"account", "topic09-api"})
	if a != b || a != "account topic09-api" {
		t.Fatalf("audienceLabel phải không phụ thuộc thứ tự: %q / %q", a, b)
	}
	in := []string{"b", "a"}
	_ = audienceLabel(in)
	if in[0] != "b" {
		t.Fatal("audienceLabel không được sắp xếp lại slice của người gọi")
	}
}
