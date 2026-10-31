# Unit test cho policy topic09.authz — chạy:  make policy-test
# Mỗi luật có ca ALLOW và ca DENY (luật policy.md). User giống realm topic09 (idp/README.md).
package topic09.authz_test

import data.topic09.authz

alice := {"sub": "sub-alice", "client_id": "web-app", "roles": ["employee"], "dept": "sales", "tier": "standard"}

bob := {"sub": "sub-bob", "client_id": "web-app", "roles": ["employee"], "dept": "engineering", "tier": "premium"}

carol := {"sub": "sub-carol", "client_id": "web-app", "roles": ["employee", "hr"], "dept": "hr", "tier": "standard"}

dave := {"sub": "sub-dave", "client_id": "web-app", "roles": ["employee", "manager"], "dept": "sales", "tier": "premium"}

batch := {"sub": "sub-batch", "client_id": "batch-worker", "roles": ["batch"]}

decide(method, path, subject) := d if {
	d := authz.decision with input as {"method": method, "path": path, "subject": subject}
}

allowed(method, path, subject, route_id) if {
	d := decide(method, path, subject)
	d.allow == true
	d.route == route_id
	d.reason == "ok"
}

denied(method, path, subject, reason) if {
	d := decide(method, path, subject)
	d.allow == false
	d.reason == reason
}

# ---------------------------------------------------------------- RBAC: route + method

test_whoami_allowed_for_every_role if {
	allowed("GET", "/orders/whoami", alice, "orders.whoami")
	allowed("GET", "/orders/whoami", batch, "orders.whoami")
	allowed("GET", "/profile/whoami", carol, "profile.whoami")
	allowed("GET", "/profile/whoami", batch, "profile.whoami")
}

test_employee_reads_order if {
	allowed("GET", "/orders/123", alice, "orders.read")
}

test_batch_cannot_read_single_order if {
	denied("GET", "/orders/123", batch, "role_not_allowed")
}

test_batch_lists_orders if {
	allowed("GET", "/orders", batch, "orders.list")
}

# BFLA (OWASP API5): chức năng quản trị chỉ manager.
test_manager_deletes_order if {
	allowed("DELETE", "/orders/123", dave, "orders.delete")
}

test_employee_cannot_delete_order if {
	denied("DELETE", "/orders/123", alice, "role_not_allowed")
	denied("DELETE", "/orders/123", carol, "role_not_allowed")
}

test_batch_cannot_create_order if {
	denied("POST", "/orders", batch, "role_not_allowed")
}

test_hr_reads_any_profile if {
	allowed("GET", "/profile/sub-alice", carol, "profile.read")
}

test_employee_cannot_read_other_profile if {
	denied("GET", "/profile/sub-bob", alice, "role_not_allowed")
}

test_employee_reads_own_profile_route if {
	allowed("GET", "/profile/me", alice, "profile.me")
}

test_only_hr_updates_profile if {
	allowed("PATCH", "/profile/sub-alice", carol, "profile.update")
	denied("PATCH", "/profile/sub-alice", dave, "role_not_allowed")
}

# ---------------------------------------------------------------- ABAC 1: dept

test_sales_creates_order if {
	allowed("POST", "/orders", alice, "orders.create")
	allowed("POST", "/orders", dave, "orders.create")
}

test_other_dept_cannot_create_order if {
	denied("POST", "/orders", bob, "abac_dept")
	denied("POST", "/orders", carol, "abac_dept")
}

test_missing_dept_claim_is_denied if {
	denied("POST", "/orders", object.remove(alice, ["dept"]), "abac_dept")
}

test_dept_compare_is_exact if {
	denied("POST", "/orders", object.union(alice, {"dept": "Sales"}), "abac_dept")
	denied("POST", "/orders", object.union(alice, {"dept": ["sales"]}), "abac_dept")
}

# ---------------------------------------------------------------- ABAC 2: tier

test_premium_exports_orders if {
	allowed("GET", "/orders/export", bob, "orders.export")
	allowed("GET", "/orders/export", dave, "orders.export")
}

test_standard_tier_cannot_export if {
	denied("GET", "/orders/export", alice, "abac_tier")
	denied("GET", "/orders/export", carol, "abac_tier")
}

test_missing_tier_claim_is_denied if {
	denied("GET", "/orders/export", object.remove(bob, ["tier"]), "abac_tier")
}

# Route cụ thể đứng trước route có tham số: /orders/export KHÔNG bị hiểu là /orders/{id}.
test_specific_route_wins_over_param_route if {
	decide("GET", "/orders/export", alice).route == "orders.export"
}

# Role đúng là chưa đủ: role sai bị báo trước, thuộc tính sau.
test_role_checked_before_attributes if {
	denied("GET", "/orders/export", batch, "role_not_allowed")
}

# ---------------------------------------------------------------- Mặc định từ chối

test_unknown_route_is_denied if {
	denied("GET", "/admin", dave, "no_matching_route")
	denied("GET", "/", dave, "no_matching_route")
}

test_method_not_in_table_is_denied if {
	denied("PUT", "/orders/123", dave, "no_matching_route")
	denied("POST", "/orders/whoami", dave, "no_matching_route")
	denied("get", "/orders/whoami", dave, "no_matching_route")
}

test_bad_path_shapes_are_denied if {
	denied("GET", "/orders/", alice, "no_matching_route")
	denied("GET", "/orders/1/2", alice, "no_matching_route")
	denied("GET", "/orders/a.b", alice, "no_matching_route")
	denied("GET", "/orders/%2e%2e", alice, "no_matching_route")
	denied("GET", concat("", ["/orders/", concat("", [x | some _ in numbers.range(1, 65); x := "a"])]), alice, "no_matching_route")
}

test_role_names_are_exact if {
	denied("DELETE", "/orders/1", object.union(alice, {"roles": ["Manager"]}), "role_not_allowed")
	denied("DELETE", "/orders/1", object.union(alice, {"roles": ["manager-x"]}), "role_not_allowed")
}

# roles không phải mảng (ví dụ chuỗi "manager") → không có role nào hợp lệ.
test_roles_must_be_array if {
	denied("DELETE", "/orders/1", object.union(alice, {"roles": "manager"}), "role_not_allowed")
	denied("GET", "/orders/1", object.remove(alice, ["roles"]), "role_not_allowed")
}

test_empty_input_is_denied if {
	d := authz.decision with input as {}
	d.allow == false
	d.reason == "no_matching_route"
}

test_non_string_path_is_denied if {
	d := authz.decision with input as {"method": "GET", "path": ["orders", "whoami"], "subject": alice}
	d.allow == false
}

# ---------------------------------------------------------------- Kết quả luôn đủ trường

test_every_decision_has_policy_metadata if {
	every d in [decide("GET", "/orders/whoami", alice), decide("GET", "/admin", alice), decide("DELETE", "/orders/1", alice)] {
		d.policy_id == "topic09.authz"
		d.policy_version == authz.policy_version
		is_string(d.reason)
		is_string(d.route)
		is_boolean(d.allow)
	}
}

# ---------------------------------------------------------------- Decision log (SR-10)

test_decision_log_masks_real_path if {
	"/input/path" in data.system.log.mask
}
