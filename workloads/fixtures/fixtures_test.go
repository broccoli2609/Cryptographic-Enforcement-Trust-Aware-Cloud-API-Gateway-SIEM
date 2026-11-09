package fixtures_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"topic09-lab/workloads/fixtures"
	"topic09-lab/workloads/internal/orders"
	"topic09-lab/workloads/internal/profiles"
)

// Kế hoạch tuần 7 T6: fixture 3 user × 5 order; ID xen kẽ chủ (bối cảnh dò ID của BOLA).
func TestOrdersFixtureIsThreeOwnersTimesFive(t *testing.T) {
	if _, err := orders.NewStore(fixtures.Orders); err != nil {
		t.Fatal(err)
	}
	var list []orders.Order
	if err := json.Unmarshal(fixtures.Orders, &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 15 {
		t.Fatalf("%d đơn, muốn 15", len(list))
	}
	perOwner := map[string]int{}
	for i, o := range list {
		perOwner[o.OwnerID]++
		if want := fmt.Sprintf("ord-%d", 1001+i); o.ID != want {
			t.Fatalf("đơn thứ %d có ID %s, muốn %s", i, o.ID, want)
		}
		if i > 0 && list[i-1].OwnerID == o.OwnerID {
			t.Fatalf("%s và %s cùng chủ — fixture phải xen kẽ", list[i-1].ID, o.ID)
		}
	}
	if len(perOwner) != 3 {
		t.Fatalf("%d chủ đơn, muốn 3", len(perOwner))
	}
	for owner, n := range perOwner {
		if n != 5 {
			t.Fatalf("chủ %s có %d đơn, muốn 5", owner, n)
		}
	}
}

// owner_id / user_id phải là sub thật của user trong realm — idp/realm-topic09.json ghim "id".
// Nếu ai đó đổi realm mà quên fixture (hoặc ngược lại), test BOLA đầu-cuối sẽ sai lặng lẽ.
func TestFixtureIDsMatchRealmUsers(t *testing.T) {
	raw, err := os.ReadFile("../../idp/realm-topic09.json")
	if err != nil {
		t.Fatalf("không đọc được realm: %v", err)
	}
	var realm struct {
		Users []struct {
			ID         string              `json:"id"`
			Username   string              `json:"username"`
			Attributes map[string][]string `json:"attributes"`
		} `json:"users"`
	}
	if err := json.Unmarshal(raw, &realm); err != nil {
		t.Fatal(err)
	}
	dept := map[string]string{} // sub → dept trong realm
	for _, u := range realm.Users {
		if u.ID == "" {
			t.Fatalf("user %s chưa ghim id trong realm", u.Username)
		}
		if d := u.Attributes["dept"]; len(d) == 1 {
			dept[u.ID] = d[0]
		}
	}

	if _, err := profiles.NewStore(fixtures.Profiles); err != nil {
		t.Fatal(err)
	}
	var ps []profiles.Profile
	if err := json.Unmarshal(fixtures.Profiles, &ps); err != nil {
		t.Fatal(err)
	}
	if len(ps) != 4 {
		t.Fatalf("%d hồ sơ, muốn 4", len(ps))
	}
	for _, p := range ps {
		if d, ok := dept[p.UserID]; !ok || d != p.Dept {
			t.Fatalf("hồ sơ %s: dept %q không khớp realm (%q, có=%v)", p.DisplayName, p.Dept, d, ok)
		}
	}
	var list []orders.Order
	_ = json.Unmarshal(fixtures.Orders, &list)
	for _, o := range list {
		if d, ok := dept[o.OwnerID]; !ok || d != o.Dept {
			t.Fatalf("đơn %s: owner/dept không khớp realm", o.ID)
		}
	}
}
