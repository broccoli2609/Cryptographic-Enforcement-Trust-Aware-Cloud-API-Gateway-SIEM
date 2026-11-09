// Package fixtures chứa dữ liệu mẫu của lab (tuần 7), nhúng vào binary bằng go:embed — container
// chạy read_only, không cần mount file.
//
//	orders.json    15 đơn = 3 chủ (alice, bob, dave) × 5 đơn. ID tăng dần và XEN KẼ chủ
//	               (1001 alice, 1002 bob, 1003 dave, 1004 alice…): ID của người khác chỉ cách
//	               ID của mình 1 đơn vị — đúng bối cảnh tấn công BOLA dò ID (OWASP API1).
//	profiles.json  4 hồ sơ nhân viên (alice, bob, carol, dave), có salary_band (tài sản #18, Mật).
//
// owner_id / user_id là claim sub của Keycloak. sub cố định vì idp/realm-topic09.json ghim "id"
// của từng user — realm import trên máy sạch cho ra đúng các sub này.
//
// Dữ liệu chỉ nằm trong bộ nhớ: restart container là về lại trạng thái fixture.
package fixtures

import _ "embed"

// Orders là nội dung orders.json.
//
//go:embed orders.json
var Orders []byte

// Profiles là nội dung profiles.json.
//
//go:embed profiles.json
var Profiles []byte
