# detections/ — 6 hunt của lab (tuần 9 T6)

Mỗi file `H*.json` là một hunt: **giả thuyết**, mối đe doạ (T*), kịch bản (S*), yêu cầu (SR-*), trụ,
**trường bằng chứng**, **ATT&CK** (chỉ ghi khi có bằng chứng thật trong lab), các phần truy vấn,
dương tính giả, giới hạn, cách phản ứng. `hunt.py` (chỉ thư viện chuẩn Python) chạy chúng trên
OpenSearch qua `docker compose exec` (OpenSearch không có cổng ra host).

| ID | Hunt | Phần truy vấn chính | ATT&CK (bằng chứng) |
|---|---|---|---|
| H1 | Token replay | `proof_status=replay`; `dpop_iat_out_of_window` | T1550.001 — gửi lại request P2 (dpop-test) |
| H2 | Sender-binding mismatch | `proof_status=key_mismatch` (cnf_jkt ≠ proof_jkt); token DPoP gửi kiểu Bearer (`wrong_typ`, `token_not_dpop_bound`) | T1528, T1550.001 — token trộm + khoá lạ, hạ cấp (dpop-test) |
| H3 | alg/kid bất thường | Envoy `jwt_authn_access_denied{Jwt_verification_fails / Jwks_doesn't_have_key… / header hỏng}`; auth-svc `alg_not_allowed`, `unknown_kid`, `bad_signature`; alg ≠ RS256 | T1606 — token tự ký / sửa chữ ký (gateway-test) |
| H4 | Leo quyền authz | ≥ 3 deny của PDP / principal; `subject_roles` của cùng principal đổi; `policy_version` đổi; admin event gán role → user đó hoạt động sau đó (`admin_target_hash` = `principal_hash`) | T1098 — gán role qua Admin REST (admin-event-test, hunt-test) |
| H5 | Dò BOLA / BFLA | backend `not_owner`/`not_found` nối `request_id` → Envoy `principal_hash` (≥ 3); `forbidden_property`/`unknown_field`; OPA `role_not_allowed` | **không ánh xạ** — không có kỹ thuật khớp chặt; dùng OWASP API1/API3/API5 2023 |
| H9 | Telemetry bị sửa/xoá | tính lại `event_hash` + đầu chuỗi + chữ ký digest (`telemetry/chain_check.py`); seq thiếu; digest cũ/mất; `chain_anomaly`; `digest_failed`; `chain_start` | T1565.001, T1070 — sửa/xoá sự kiện trong bản sao index (hunt-test) |

Kiểu phần truy vấn (`kind`): `terms` (gom nhóm + ngưỡng), `cardinality` (cùng nhóm nhưng giá trị đổi),
`join` (nối hai loại sự kiện qua `request_id` — OpenSearch không có join), `admin_then_use`,
`seq_gaps`, `digest_freshness`, `chain_verify`.

## Chạy

```bash
make hunt                                  # 24 giờ gần nhất
make hunt SINCE=2026-11-21T06:00:00Z
python3 detections/hunt.py --only H5 --json out.json
make hunt-test     # sinh kịch bản rồi khẳng định: lưu lượng bình thường → H1/H2/H3/H5 im lặng;
                   # tấn công → cả 5 hunt báo; H9 thấy sự kiện bị sửa + bị xoá trên BẢN SAO index,
                   # index thật băm lại khớp. Realm và SIEM thật trở về như cũ.
make siem-dashboard                        # dashboard tĩnh docs/evidence/siem-dashboard-<ngày>.html
```

## Ghi chú

- H5: backend không ghi danh tính (dữ liệu tối thiểu qua TB3) nên phải nối qua `request_id` với Envoy;
  request vòng qua gateway (S8) không nối được.
- H3: ở P1 token hỏng bị `jwt_authn` chặn trước auth-svc, nên phần auth-svc chỉ có dữ liệu khi token qua
  được Envoy (ý tưởng S2 tuần 10: thêm khoá ES256 vào realm).
- H9 phần `chain_verify` chỉ kiểm sự kiện đã có digest phủ; phần sau digest gần nhất đối chiếu được với
  file chuỗi của Vector bằng `chain_check.py --chain-file` (xem `scripts/chain-test.sh`).
- Ngưỡng (3 lần BOLA, 3 deny) chọn cho lab; tuần 10 có dataset S0–S11 gắn nhãn để đo lại.
