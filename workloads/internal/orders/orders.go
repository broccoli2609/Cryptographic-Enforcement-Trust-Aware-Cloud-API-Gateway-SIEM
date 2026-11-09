// Package orders là nghiệp vụ của orders-api (tuần 7) và là nơi kiểm quyền MỨC ĐỐI TƯỢNG
// (object-level authorization, OWASP API1:2023 BOLA).
//
// Vì sao kiểm ở backend chứ không ở gateway: OPA chỉ thấy "employee gọi GET /orders/{id}" — hợp
// lệ. OPA không biết đơn ord-1002 thuộc về ai; chỉ orders-api có dữ liệu đó (SR-06). Nếu backend
// không kiểm, alice đổi ID trong URL là đọc được đơn của bob — gateway vẫn cho qua.
package orders

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"topic09-lab/workloads/internal/service"
)

// Order là một đơn hàng (tài sản #17). OwnerID = claim sub của người tạo đơn.
type Order struct {
	ID        string    `json:"id"`
	OwnerID   string    `json:"owner_id"`
	Dept      string    `json:"dept"`
	Item      string    `json:"item"`
	Quantity  int       `json:"quantity"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// maxOrders: trần số đơn trong bộ nhớ — client hợp lệ cũng không làm đầy RAM được (T10).
const maxOrders = 1000

// Store giữ đơn hàng trong bộ nhớ (lab không có database). Restart = về lại fixture.
type Store struct {
	mu     sync.RWMutex
	orders map[string]Order
	newID  func() (string, error)
	now    func() time.Time
}

// NewStore nạp fixture (JSON mảng Order). Fixture sai → lỗi ngay khi khởi động (fail fast).
func NewStore(seed []byte) (*Store, error) {
	var list []Order
	dec := json.NewDecoder(bytes.NewReader(seed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("orders: fixture: %w", err)
	}
	s := &Store{orders: make(map[string]Order, len(list)), newID: randomID, now: time.Now}
	for _, o := range list {
		switch {
		case !validID(o.ID), o.OwnerID == "", o.Quantity < 1, !validItem(o.Item):
			return nil, fmt.Errorf("orders: fixture: đơn %q không hợp lệ", o.ID)
		case s.orders[o.ID].ID != "":
			return nil, fmt.Errorf("orders: fixture: trùng ID %q", o.ID)
		}
		s.orders[o.ID] = o
	}
	return s, nil
}

// Register gắn route nghiệp vụ. Bảng quyền ở gateway (policy/authz.rego) đứng TRƯỚC các route
// này; ở đây là lớp thứ hai — kiểm đối tượng.
//
//	GET    /orders          liệt kê đơn người gọi được xem          (OPA: employee, manager, batch)
//	POST   /orders          tạo đơn, chủ đơn = người gọi           (OPA: employee/manager + dept=sales)
//	GET    /orders/export   tổng hợp các đơn người gọi được xem     (OPA: + tier=premium)
//	GET    /orders/{id}     đọc một đơn                             (OPA: employee, manager)
//	DELETE /orders/{id}     xoá một đơn                             (OPA: manager)
func (s *Store) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /orders", s.list)
	mux.HandleFunc("POST /orders", s.create)
	mux.HandleFunc("GET /orders/export", s.export)
	mux.HandleFunc("GET /orders/{id}", s.read)
	mux.HandleFunc("DELETE /orders/{id}", s.remove)
}

// ---------------------------------------------------------------- Luật mức đối tượng
// Toàn bộ luật "ai được làm gì với đơn nào" nằm ở hai hàm dưới — một chỗ, có unit test riêng.
//
//	đọc:      chủ đơn (owner_id == sub)  HOẶC  manager cùng phòng ban với đơn
//	xoá:      manager cùng phòng ban với đơn (chủ đơn thường không tự xoá — xoá là việc quản lý)
//	liệt kê:  các đơn đọc được; role batch (job đối soát) đọc tất cả

// canRead trả (được phép?, mã lý do cho log).
func canRead(caller service.Identity, o Order) (bool, string) {
	if o.OwnerID == caller.Subject { // Subject không bao giờ rỗng (IdentityFrom đã kiểm)
		return true, "owner"
	}
	if deptManager(caller, o) {
		return true, "dept_manager"
	}
	return false, "not_owner"
}

// deptManager: người gọi là manager VÀ cùng phòng ban với đơn. dept rỗng không bao giờ khớp:
// P0 không gửi X-User-Dept, nên ở P0 không ai được coi là "manager cùng phòng" (ít quyền hơn).
func deptManager(caller service.Identity, o Order) bool {
	return caller.Has("manager") && caller.Dept != "" && caller.Dept == o.Dept
}

// ---------------------------------------------------------------- Handler

// notFound: đơn KHÔNG tồn tại và đơn CỦA NGƯỜI KHÁC trả cùng một response (404, cùng body) —
// kẻ dò ID không phân biệt được "có đơn này nhưng không phải của tôi" với "không có đơn này"
// (RFC 9110 §15.5.4 cho phép dùng 404 để giấu sự tồn tại của tài nguyên bị cấm).
// Lý do thật (not_found / not_owner) chỉ nằm trong log.
func notFound(w http.ResponseWriter) { service.WriteError(w, http.StatusNotFound, "not_found") }

func (s *Store) read(w http.ResponseWriter, r *http.Request) {
	caller, ok := service.RequireIdentity(w, r)
	if !ok {
		return
	}
	s.mu.RLock()
	o, found := s.orders[r.PathValue("id")]
	s.mu.RUnlock()
	if !found {
		service.Deny(r, "not_found")
		notFound(w)
		return
	}
	allowed, why := canRead(caller, o)
	if !allowed {
		service.Deny(r, why) // BOLA bị chặn ở đây — gateway đã cho qua request này
		notFound(w)
		return
	}
	service.Allow(r, why)
	service.WriteJSON(w, http.StatusOK, o)
}

func (s *Store) remove(w http.ResponseWriter, r *http.Request) {
	caller, ok := service.RequireIdentity(w, r)
	if !ok {
		return
	}
	// Kiểm và xoá trong cùng một lần khoá: không có khe giữa "kiểm" và "làm" (TOCTOU).
	status, decision, why := func() (int, bool, string) {
		s.mu.Lock()
		defer s.mu.Unlock()
		o, found := s.orders[r.PathValue("id")]
		if !found {
			return http.StatusNotFound, false, "not_found"
		}
		if readable, why := canRead(caller, o); !readable {
			return http.StatusNotFound, false, why // không đọc được thì cũng không được biết là có
		}
		if !deptManager(caller, o) {
			// Đọc được (là chủ đơn) nhưng không phải manager cùng phòng → 403: giấu cũng vô ích.
			return http.StatusForbidden, false, "not_dept_manager"
		}
		delete(s.orders, o.ID)
		return http.StatusNoContent, true, "dept_manager"
	}()
	switch {
	case decision:
		service.Allow(r, why)
		w.WriteHeader(status)
	case status == http.StatusNotFound:
		service.Deny(r, why)
		notFound(w)
	default:
		service.Deny(r, why)
		service.WriteError(w, status, "forbidden")
	}
}

// visible trả các đơn người gọi được xem, xếp theo ID. Lọc ở server — client không bao giờ
// nhận đơn của người khác rồi "tự ẩn" (OWASP API3: đừng dựa vào client lọc dữ liệu).
func (s *Store) visible(caller service.Identity) (list []Order, reason string) {
	all := caller.Has("batch")
	list = []Order{} // JSON là [] chứ không phải null khi rỗng
	s.mu.RLock()
	for _, o := range s.orders {
		if ok, _ := canRead(caller, o); ok || all {
			list = append(list, o)
		}
	}
	s.mu.RUnlock()
	slices.SortFunc(list, func(a, b Order) int { return strings.Compare(a.ID, b.ID) })
	if all {
		return list, "batch_all"
	}
	return list, "filtered"
}

func (s *Store) list(w http.ResponseWriter, r *http.Request) {
	caller, ok := service.RequireIdentity(w, r)
	if !ok {
		return
	}
	list, why := s.visible(caller)
	service.Allow(r, why)
	service.WriteJSON(w, http.StatusOK, map[string]any{"count": len(list), "orders": list})
}

// export: số liệu tổng hợp trên đúng tập đơn mà người gọi được xem (cùng luật với list).
func (s *Store) export(w http.ResponseWriter, r *http.Request) {
	caller, ok := service.RequireIdentity(w, r)
	if !ok {
		return
	}
	list, why := s.visible(caller)
	total, byStatus := 0, map[string]int{}
	for _, o := range list {
		total += o.Quantity
		byStatus[o.Status]++
	}
	service.Allow(r, why)
	service.WriteJSON(w, http.StatusOK, map[string]any{"count": len(list), "total_quantity": total, "by_status": byStatus})
}

// createRequest là allow-list những trường client ĐƯỢC gửi khi tạo đơn. Không có owner_id,
// dept, status, id: các trường đó do server đặt. Body có trường khác → 400 unknown_field
// (chống mass assignment — OWASP API3).
type createRequest struct {
	Item     string `json:"item"`
	Quantity int    `json:"quantity"`
}

func (s *Store) create(w http.ResponseWriter, r *http.Request) {
	caller, ok := service.RequireIdentity(w, r)
	if !ok {
		return
	}
	var in createRequest
	if err := service.ReadJSON(w, r, &in); err != nil {
		if errors.Is(err, service.ErrUnknownField) {
			service.Deny(r, "unknown_field") // cố gán thuộc tính không được phép (vd. owner_id)
			service.WriteError(w, http.StatusBadRequest, "unknown_field")
			return
		}
		service.WriteError(w, http.StatusBadRequest, "invalid_body")
		return
	}
	if !validItem(in.Item) || in.Quantity < 1 || in.Quantity > 1000 {
		service.WriteError(w, http.StatusBadRequest, "invalid_value")
		return
	}
	id, err := s.newID()
	if err != nil {
		service.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	o := Order{
		ID:        id,
		OwnerID:   caller.Subject, // chủ đơn = người gọi đã xác thực, KHÔNG BAO GIỜ lấy từ body
		Dept:      caller.Dept,    // P1/P2: OPA đã bắt dept = sales; P0: rỗng
		Item:      in.Item,
		Quantity:  in.Quantity,
		Status:    "open",
		CreatedAt: s.now().UTC().Truncate(time.Second),
	}
	s.mu.Lock()
	full := len(s.orders) >= maxOrders
	if !full {
		s.orders[o.ID] = o
	}
	s.mu.Unlock()
	if full {
		service.WriteError(w, http.StatusServiceUnavailable, "capacity_reached")
		return
	}
	service.Allow(r, "owner_is_caller")
	service.WriteJSON(w, http.StatusCreated, o)
}

// ---------------------------------------------------------------- Kiểm giá trị

// randomID: "ord-" + 12 ký tự hex từ CSPRNG. ID ngẫu nhiên làm việc dò ID khó hơn, nhưng KHÔNG
// thay được kiểm quyền: ID lọt ra (log, link chia sẻ) là đủ để thử — nên canRead vẫn bắt buộc.
func randomID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ord-" + hex.EncodeToString(b), nil
}

// validID: cùng mẫu tham số {id} của policy OPA: chữ, số, "-", "_", 1–64 ký tự.
func validID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// validItem: 1–100 ký tự UTF-8 hợp lệ, không ký tự điều khiển (chặn xuống dòng giả log, ESC…).
func validItem(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	n := utf8.RuneCountInString(s)
	if n == 0 || n > 100 || strings.TrimSpace(s) == "" {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}
