// Package profiles là nghiệp vụ của profile-api (tuần 7) và là nơi kiểm quyền MỨC THUỘC TÍNH
// (property-level, OWASP API3:2023 Broken Object Property Level Authorization).
//
// API3 có hai mặt, cả hai đều phải kiểm ở backend vì gateway chỉ thấy route, không thấy field:
//   - Đọc  (excessive data exposure): salary_band (tài sản #18, Mật) chỉ trả cho role hr. Manager
//     được xem hồ sơ nhân viên phòng mình (OPA cho qua) nhưng KHÔNG thấy salary_band.
//   - Ghi  (mass assignment): PATCH chỉ nhận các trường trong allow-list; user_id, dept,
//     display_name không sửa được qua API. salary_band chỉ hr ghi được, và hr không tự sửa
//     salary_band của chính mình (tách nhiệm vụ).
package profiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"topic09-lab/workloads/internal/service"
)

// Profile là hồ sơ đầy đủ trong kho — KHÔNG BAO GIỜ trả thẳng ra ngoài; luôn đi qua view().
type Profile struct {
	UserID      string `json:"user_id"` // = claim sub
	DisplayName string `json:"display_name"`
	Dept        string `json:"dept"`
	Title       string `json:"title"`
	SalaryBand  string `json:"salary_band"`
}

// salaryBands là các giá trị hợp lệ của salary_band.
var salaryBands = []string{"B1", "B2", "B3", "B4", "B5"}

// Store giữ hồ sơ trong bộ nhớ, khoá theo user_id.
type Store struct {
	mu       sync.RWMutex
	profiles map[string]Profile
}

// NewStore nạp fixture (JSON mảng Profile); fixture sai → lỗi khi khởi động.
func NewStore(seed []byte) (*Store, error) {
	var list []Profile
	dec := json.NewDecoder(bytes.NewReader(seed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("profiles: fixture: %w", err)
	}
	s := &Store{profiles: make(map[string]Profile, len(list))}
	for _, p := range list {
		switch {
		case p.UserID == "", !service.SafeAttr(p.Dept), !validText(p.DisplayName), !validText(p.Title),
			!slices.Contains(salaryBands, p.SalaryBand):
			return nil, fmt.Errorf("profiles: fixture: hồ sơ %q không hợp lệ", p.UserID)
		case s.profiles[p.UserID].UserID != "":
			return nil, fmt.Errorf("profiles: fixture: trùng user_id %q", p.UserID)
		}
		s.profiles[p.UserID] = p
	}
	return s, nil
}

// Register gắn route nghiệp vụ (bảng quyền ở gateway: policy/authz.rego).
//
//	GET   /profile/me     hồ sơ của chính người gọi   (OPA: employee)
//	GET   /profile/{id}   hồ sơ theo user_id          (OPA: hr, manager)
//	PATCH /profile/{id}   sửa title / salary_band     (OPA: hr)
func (s *Store) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /profile/me", s.me)
	mux.HandleFunc("GET /profile/{id}", s.read)
	mux.HandleFunc("PATCH /profile/{id}", s.update)
}

// ---------------------------------------------------------------- Luật

// canRead — mức đối tượng: ai được xem hồ sơ nào.
//
//	chính mình  ·  hr: mọi hồ sơ  ·  manager: hồ sơ cùng phòng ban (dept rỗng không bao giờ khớp)
func canRead(caller service.Identity, p Profile) (bool, string) {
	switch {
	case p.UserID == caller.Subject:
		return true, "self"
	case caller.Has("hr"):
		return true, "hr"
	case caller.Has("manager") && caller.Dept != "" && caller.Dept == p.Dept:
		return true, "dept_manager"
	}
	return false, "not_allowed"
}

// writableBy — mức thuộc tính khi GHI: trường nào cần role nào. Trường không có trong bảng
// (user_id, dept, display_name) không ai sửa được qua API — body chứa chúng bị ReadJSON từ chối.
var writableBy = map[string]string{
	"title":       "hr",
	"salary_band": "hr",
}

// publicView là allow-list ĐẦU RA cho người không phải hr: không có trường salary_band, nên
// không có cách nào vô tình serialize nó ra (khác với "lấy cả struct rồi xoá trường").
type publicView struct {
	UserID      string `json:"user_id"`
	DisplayName string `json:"display_name"`
	Dept        string `json:"dept"`
	Title       string `json:"title"`
}

// hrView = publicView + salary_band, chỉ dùng khi người gọi có role hr.
type hrView struct {
	publicView
	SalaryBand string `json:"salary_band"`
}

// view chọn allow-list đầu ra theo role — mức thuộc tính khi ĐỌC.
func view(r *http.Request, caller service.Identity, p Profile) any {
	pub := publicView{UserID: p.UserID, DisplayName: p.DisplayName, Dept: p.Dept, Title: p.Title}
	if caller.Has("hr") {
		return hrView{publicView: pub, SalaryBand: p.SalaryBand}
	}
	service.Redacted(r, "salary_band") // log: trường đã bị ẩn (bằng chứng property-level)
	return pub
}

// ---------------------------------------------------------------- Handler

func notFound(w http.ResponseWriter) { service.WriteError(w, http.StatusNotFound, "not_found") }

func (s *Store) get(id string) (Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[id]
	return p, ok
}

func (s *Store) me(w http.ResponseWriter, r *http.Request) {
	caller, ok := service.RequireIdentity(w, r)
	if !ok {
		return
	}
	p, found := s.get(caller.Subject)
	if !found {
		service.Deny(r, "not_found")
		notFound(w)
		return
	}
	service.Allow(r, "self")
	service.WriteJSON(w, http.StatusOK, view(r, caller, p))
}

func (s *Store) read(w http.ResponseWriter, r *http.Request) {
	caller, ok := service.RequireIdentity(w, r)
	if !ok {
		return
	}
	p, found := s.get(r.PathValue("id"))
	if !found {
		service.Deny(r, "not_found")
		notFound(w)
		return
	}
	allowed, why := canRead(caller, p)
	if !allowed {
		service.Deny(r, why) // manager phòng khác: OPA cho qua, backend chặn — cùng 404 với "không có"
		notFound(w)
		return
	}
	service.Allow(r, why)
	service.WriteJSON(w, http.StatusOK, view(r, caller, p))
}

// updateRequest: allow-list trường được GỬI khi sửa. Con trỏ để phân biệt "không gửi" với "gửi rỗng".
type updateRequest struct {
	Title      *string `json:"title"`
	SalaryBand *string `json:"salary_band"`
}

func (s *Store) update(w http.ResponseWriter, r *http.Request) {
	caller, ok := service.RequireIdentity(w, r)
	if !ok {
		return
	}
	// 1. Mức đối tượng TRƯỚC khi đọc body: hồ sơ không xem được thì coi như không tồn tại —
	//    kẻ tấn công không dò được gì qua thông báo lỗi của body.
	p, found := s.get(r.PathValue("id"))
	if !found {
		service.Deny(r, "not_found")
		notFound(w)
		return
	}
	if allowed, why := canRead(caller, p); !allowed {
		service.Deny(r, why)
		notFound(w)
		return
	}
	// 2. Mass assignment: chỉ trường trong allow-list.
	var in updateRequest
	if err := service.ReadJSON(w, r, &in); err != nil {
		if errors.Is(err, service.ErrUnknownField) {
			service.Deny(r, "unknown_field")
			service.WriteError(w, http.StatusBadRequest, "unknown_field")
			return
		}
		service.WriteError(w, http.StatusBadRequest, "invalid_body")
		return
	}
	var fields []string
	if in.Title != nil {
		fields = append(fields, "title")
	}
	if in.SalaryBand != nil {
		fields = append(fields, "salary_band")
	}
	if len(fields) == 0 {
		service.WriteError(w, http.StatusBadRequest, "empty_patch")
		return
	}
	// 3. Mức thuộc tính khi ghi: mỗi trường cần đúng role của nó.
	for _, f := range fields {
		if !caller.Has(writableBy[f]) {
			service.Deny(r, "forbidden_property")
			service.WriteError(w, http.StatusForbidden, "forbidden_property")
			return
		}
	}
	// 4. Tách nhiệm vụ: hr không tự đổi salary_band của mình. Gateway không thấy được điều này
	//    (OPA không so {id} trong URL với sub), chỉ backend biết hồ sơ là của ai.
	if in.SalaryBand != nil && p.UserID == caller.Subject {
		service.Deny(r, "self_salary_change")
		service.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	// 5. Giá trị hợp lệ.
	if (in.Title != nil && !validText(*in.Title)) || (in.SalaryBand != nil && !slices.Contains(salaryBands, *in.SalaryBand)) {
		service.WriteError(w, http.StatusBadRequest, "invalid_value")
		return
	}
	s.mu.Lock()
	p, found = s.profiles[p.UserID] // đọc lại dưới khoá ghi: có thể vừa bị sửa
	if found {
		if in.Title != nil {
			p.Title = *in.Title
		}
		if in.SalaryBand != nil {
			p.SalaryBand = *in.SalaryBand
		}
		s.profiles[p.UserID] = p
	}
	s.mu.Unlock()
	if !found {
		service.Deny(r, "not_found")
		notFound(w)
		return
	}
	service.Allow(r, "hr_update")
	service.WriteJSON(w, http.StatusOK, view(r, caller, p))
}

// validText: 1–100 ký tự UTF-8, không ký tự điều khiển.
func validText(s string) bool {
	if !utf8.ValidString(s) || strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > 100 {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}
