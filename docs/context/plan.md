# Kế hoạch 12 tuần (T5 = thứ 5, T6 = thứ 6, 08:00–13:00)

| Tuần | Ngày | T5 | T6 |
|---|---|---|---|
| 1 | 24–25/09 | Đọc RFC 8725; sơ đồ 4 plane (lưu file nguồn); bảng tài sản theo mục 4 đề bài | Trust boundary (mỗi biên: ai tin ai, bằng chứng gì, giả thì sao); tạo repo, commit sơ đồ + bảng tài sản |
| 2 | 01–02/10 | Data flow F0–F6; threat model T1–T11 (bỏ T6); đọc RFC 9846 §2, §7 | Cài Docker, Go, linux-tools; kiểm `perf stat -e cycles`; compose Keycloak + 2 backend rỗng |
| 3 | 08–09/10 | Đọc oauth.com (Auth Code + PKCE), RFC 9700; realm Keycloak, 2 client, 4 user (role, `dept`, `tier`) | Script curl chạy Auth Code + PKCE tự sinh `code_verifier`/`code_challenge`; trace vào `docs/traces/`; Client Credentials + `private_key_jwt` |
| 4 | 15–16/10 | Envoy + TLS 1.3 (cert tự ký, `openssl s_client -tls1_3`); `jwt_authn` trỏ JWKS = **P0** | auth-svc Go: gRPC ext_authz; strict JWT validator (alg allow-list, iss/aud/exp/nbf/typ, JWKS cache TTL); 8 unit test JWT sai |
| 5 | 22–23/10 | Học Rego (Styra Academy, Playground) | OPA vào compose; RBAC theo route + method, 2 luật ABAC; auth-svc gọi OPA; decision log có `policy_id` + version; `opa test`; test fail-closed |
| 6 | 29–30/10 | Đọc RFC 9449; bật DPoP trên client Keycloak, token có `cnf.jkt`; client sinh DPoP proof | auth-svc verify DPoP (`htm`, `htu`, `iat`, `ath`, `jti` cache TTL); chứng minh replay bị chặn = **P2** (phần gateway) |
| 7 | 05–06/11 | OWASP API Top 10; object-level authz orders-api (`owner_id`), property-level profile-api (`salary_band` chỉ HR) | Fixture 3 user × 5 order; test BOLA (gateway cho qua, backend chặn — chụp log 2 tầng); test BFLA; trường `backend_object_authz` |
| 8 | 12–13/11 | Schema 26 trường → `telemetry/schema.json`; sửa log Envoy, OPA, 2 backend cho khớp | Vector + OpenSearch; 5 source; VRL băm `principal_hash`, `aud_hash`, xoá token; scanner `eyJ` |
| 9 | 19–20/11 | Hash chain trong Vector; Vault dev + Transit, khoá `siem-digest` ed25519; digester Go (5 phút/lần) | 6 hunt: H1, H2, H3, H4, H5, H9 (giả thuyết, trường bằng chứng, ATT&CK); dashboard |
| 10 | 26–27/11 | `verify-chain` Go; kịch bản S0–S4 có `attack_label`, `attack_id` | S6, S7, S8, S10; chạy 24 security test; xuất corpus CSV/Parquet vào `dataset/` |
| 11 | 03–04/12 | Microbenchmark HS256/ES256/EdDSA/RS256 (5 lần, `benchstat`); cycles bằng perf; chi phí verify DPoP | k6: P0 vs P1 vs P2 ở 1/10/50/100 concurrent, p50/p95/p99; failure injection (tắt Keycloak, OPA, làm chậm OpenSearch) |
| 12 | 10–11/12 | Traceability matrix Requirement → Mechanism → Test → Evidence; runbook; bảng ánh xạ lab → AWS/Azure/GCP | Hoàn thiện báo cáo; video demo 8–10 phút; `docker compose down && up` trên máy sạch |

## Mốc nghiệm thu

| Mốc | Hạn | Phải có |
|---|---|---|
| M1 | 16/10 (cuối tuần 4) | Login PKCE → gateway → backend; token hợp lệ 200, token hỏng 401; phân tích kiến trúc viết xong |
| M2 | 20/11 (cuối tuần 9) | P0/P1/P2 chạy; bằng chứng object authz; telemetry về SIEM có digest ký bằng Vault; 6 hunt |
| M3 | 11/12 (cuối tuần 12) | Toàn bộ deliverable, traceability matrix, video demo |

## Khi trễ tiến độ — cắt theo thứ tự

Ký digest bằng Vault (giữ hash chain) → hash chain → hunt còn 3 → chỉ so HS256 vs ES256 → bỏ failure injection.
**Không bao giờ cắt:** DPoP, object-level authz, traceability matrix.

## Phương án dự phòng đã chốt

- `perf` không đếm được cycles trong WSL2 → `go test -bench` (`ns/op`) + `benchstat`, ghi hạn chế.
- Envoy quá khó (mất cả buổi tuần 4) → Kong hoặc reverse proxy Go ~200 dòng.
- DPoP của Keycloak trục trặc → tự cấp token có `cnf.jkt` bằng script (AS giả lập); phần verify ở gateway giữ nguyên.
- Rego khó → giữ RBAC thuần, ABAC để tuần 7.
- Vault Transit tốn thời gian → ký Ed25519 bằng khoá phần mềm trong digester, giữ định dạng digest.
- RAM yếu khi thêm OpenSearch → `OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m`, tắt Dashboards khi không dùng.
