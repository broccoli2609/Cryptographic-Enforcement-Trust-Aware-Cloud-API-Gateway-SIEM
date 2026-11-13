# telemetry/ — từ log của service tới SIEM (tuần 8)

Plane "security telemetry" của lab: mọi thành phần ghi log JSON ra stdout, **Vector** gom lại,
đổi về một schema chung, giả danh định danh, rồi ghi vào **OpenSearch**. Phần toàn vẹn (hash
chain, digest ký bằng Vault, `verify-chain`) là việc của tuần 9–10 và sẽ nằm cùng thư mục này.

```
 Envoy ─┐                                   Vector (telemetry/vector/vector.yaml)
 auth-svc ─┤  stdout/stderr   ┌──────────┐   ┌──────────────────────────────┐   ┌────────────┐
 OPA ──────┼─ của container ─►│ 5 nguồn  │──►│ norm_*  đổi tên trường       │──►│ OpenSearch │
 orders-api┤  (Docker đọc)    │ src_*    │   │ seal    HMAC · allow-list ·  │   │ topic09-   │
 profile-api                  └──────────┘   │         kiểm dạng · che token│   │ events     │
 Keycloak ─┘                                 └──────────────────────────────┘   │ (strict)   │
                                                                                └────────────┘
        TB5: trước Vector chỉ có vị trí mạng          mạng topic09-telemetry (internal, không port)
```

| File | Nội dung |
|---|---|
| `schema.json` | Schema của MỘT sự kiện trong SIEM: 27 trường của mục 13.1 đề bài + 25 trường mở rộng. Là allow-list (`additionalProperties: false`). |
| `schema_check.py` | Công cụ kiểm (Python chuẩn): `self` (schema), `source` (log thô ↔ schema), `siem` (sự kiện trong SIEM ↔ schema), `mapping` (sinh mapping OpenSearch), `sync` (schema ↔ Vector ↔ mapping). |
| `secret_scan.py` | Scanner SR-10: token, khoá PEM, mã uỷ quyền, bí mật trong `.env`, định danh thô của user. |
| `vector/vector.yaml` | Đường ống: 5 nguồn → `norm_*` → `seal` → OpenSearch. |
| `vector/tests.yaml` | 21 unit test của đường ống (`vector test`), gồm các ca chèn token. |
| `opensearch/index-template.json`, `index-mapping.json` | Mapping `dynamic: strict`, **sinh từ schema** (`make siem-mapping`) — không sửa tay. |
| `opensearch/init.sh` | Nạp mapping trước khi Vector ghi tài liệu đầu tiên (service `opensearch-init`). |

## 1. Năm nguồn

| Nguồn (`source`) | `event_type` | Mỗi sự kiện là | Trường chính |
|---|---|---|---|
| `envoy` | `gateway_access` | một request tới gateway (cả 3 profile) | `status_code`, `profile`, `decision`, `response_code_details`, `tls_version`, `principal_hash` |
| `auth-svc` | `authz_decision` | một quyết định của PEP (P1, P2) | `decision`, `decision_reason`, `token_type`, `alg`, `kid`, `iss`, `aud_hash`, `scope_set`, `proof_status`, `policy_*`, `route_template` |
| `opa` | `policy_decision` | một dòng decision log của PDP | `policy_id`, `policy_version`, `decision`, `subject_roles`, `policy_eval_us` |
| `orders-api`, `profile-api` | `backend_request` | một request tới backend | `backend_object_authz`, `backend_authz_reason`, `backend_redacted_fields`, `route_template` |
| `keycloak` | `idp_event` | một sự kiện đăng nhập / cấp token | `idp_event`, `idp_realm`, `grant_type`, `decision`, `principal_hash` |

Vault (audit device) là nguồn thứ 6, thêm ở tuần 9. Log vận hành ("listening", health check của
Docker, log khởi động) **không** vào SIEM — chỉ sự kiện bảo mật có cấu trúc mới qua được `norm_*`.

**Nguồn của sự kiện = container mà Docker đọc log**, không phải trường `service` trong dòng log:
một backend bị chiếm không tự xưng là `auth-svc` trong SIEM được (có unit test).

## 2. Nối sự kiện

| Khoá | Nối | Ví dụ dùng |
|---|---|---|
| `request_id` (UUID do Envoy sinh) | Envoy ↔ auth-svc ↔ backend | BOLA: `auth-svc.decision = allow` và `orders-api.backend_object_authz = deny`, cùng `request_id` |
| `opa_decision_id` | auth-svc ↔ OPA | quyết định nào của PEP ứng với dòng nào của PDP |
| `principal_hash` | mọi sự kiện của cùng một người, kể cả Keycloak | H5: một người bị backend từ chối nhiều ID liên tiếp |

Backend không ghi danh tính: muốn biết "ai" thì nối sang auth-svc/Envoy bằng `request_id`.
Sự kiện `backend_request` **không có** `request_id` hợp lệ và không có sự kiện Envoy đi kèm là
dấu hiệu gọi vòng qua gateway (kịch bản S8).

## 3. 27 trường của mục 13.1 đề bài

| # | Trường | Nguồn điền | Ghi chú |
|---|---|---|---|
| 1 | `event_time` | mọi nguồn | RFC 3339 UTC, do nguồn ghi lúc bắt đầu xử lý |
| 2 | `request_id` | envoy, auth-svc, backend | sai dạng UUID → Vector bỏ, gắn cờ |
| 3 | `principal_hash` | envoy, auth-svc, opa, keycloak | HMAC-SHA256, xem §4 |
| 4 | `client_id` | envoy, auth-svc, opa, keycloak | claim `azp` của token đã kiểm |
| 5 | `workload_id` | — | luôn `null`: track B ngoài phạm vi |
| 6 | `authn_method` | (Vector suy từ `client_id`) | `pkce` / `private_key_jwt` theo cấu hình realm |
| 7–10 | `token_type`, `alg`, `kid`, `iss` | auth-svc | `alg`/`kid` có cả khi token bị từ chối (H3) |
| 11 | `aud_hash` | auth-svc | HMAC của `aud` đã kiểm |
| 12 | `scope_set` | auth-svc | scope đã chuẩn hoá (bỏ trùng, sắp xếp) |
| 13 | `proof_status` | auth-svc | `valid` / `replay` / `key_mismatch` / `missing` / `invalid` / `not_checked` / `not_applicable` |
| 14–15 | `policy_id`, `policy_version` | auth-svc, opa | |
| 16–17 | `decision`, `decision_reason` | envoy, auth-svc, opa, keycloak | lý do là mã cố định, không phải câu chữ |
| 18 | `route_template` | auth-svc, opa, backend | `/orders/{id}` — không bao giờ là đường dẫn thật |
| 19 | `backend_object_authz` | backend | `allow` / `deny` / `not_applicable` |
| 20 | `status_code` | envoy, backend | |
| 21–22 | `gateway_cycles`, `crypto_verify_cycles` | — | tuần 11 (đo theo lô bằng perf) |
| 23 | `policy_eval_us` | auth-svc, opa | auth-svc: thời gian khứ hồi; opa: thời gian OPA tự đo |
| 24 | `kms_calls` | — | tuần 9 |
| 25 | `tls_peer_fingerprint` | — | luôn `null`: không dùng mTLS phía client; sender-binding bằng DPoP (`cnf_jkt`, `proof_jkt`) |
| 26–27 | `attack_label`, `attack_id` | — | tuần 10 (bộ sinh kịch bản gắn nhãn) |

Bảng "nguồn nào thật sự điền trường nào" được in lại mỗi lần chạy `make schema-test` và
`make siem-test` (lưu ở `docs/evidence/`).

## 4. Giả danh định danh (SR-10)

```
principal_hash = hex( HMAC-SHA256( SIEM_HMAC_KEY, "principal:" ‖ sub ) )
aud_hash       = hex( HMAC-SHA256( SIEM_HMAC_KEY, "aud:" ‖ aud ) )
```

- **Vì sao HMAC mà không phải SHA-256 trần:** `sub` là UUID lấy từ một tập nhỏ đã biết (danh sách
  user). Với hash trần, ai có danh sách đó chỉ cần băm từng `sub` rồi so là biết sự kiện của ai.
  HMAC cần thêm khoá bí mật — không có khoá thì không băm thử được.
- **Tiền tố `principal:` / `aud:`** tách miền: cùng một chuỗi ở hai trường không cho ra cùng hash.
- **Khoá** (`SIEM_HMAC_KEY`, 32 byte ngẫu nhiên, tài sản #14) nằm trong `.env`, Vector đọc lúc chạy.
  Thiếu khoá hoặc khoá ngắn hơn 32 ký tự → Vector **bỏ sự kiện**, không ghi định danh thật.
- **Giới hạn:** đây là *giả danh*, không phải ẩn danh — ai có khoá (hoặc có quyền Docker trên máy)
  tính lại được. Đổi khoá thì hash mới không nối được với sự kiện cũ. Tập user nhỏ nên thuộc tính
  đi kèm (`subject_roles`, `subject_dept`) có thể gián tiếp chỉ ra một người.

## 5. Ba lớp chặn dữ liệu nhạy cảm + một scanner

| Lớp | Ở đâu | Chặn bằng cách |
|---|---|---|
| 1 | service (Go, Envoy, OPA) | không ghi header/token/body; route theo mẫu; OPA xoá `input.path`; có unit test "log không chứa token" |
| 2 | Vector `seal` | allow-list trường theo schema; `request_id`/`method` sai dạng bị bỏ; che mọi giá trị dạng JWT / PEM / `code=`; gắn cờ `pipeline_redacted` |
| 3 | OpenSearch | mapping `dynamic: strict` — tài liệu có trường lạ bị từ chối (HTTP 400) |
| — | `scripts/siem-scan.sh` | quét toàn bộ SIEM + `dataset/`: `eyJ`, `-----BEGIN`, `code=`, giá trị bí mật trong `.env`, `sub`/username của user |

Lớp 2 tồn tại vì lớp 1 có chỗ không tự bảo vệ được: backend ghi `X-Request-Id` vào log, mà
request gọi thẳng backend (S8) tự đặt header đó tuỳ ý — kể cả một token. `make siem-test` mục E
chạy đúng kịch bản này: token giả **có** trong log thô, **không có** trong SIEM.

## 6. Chạy và kiểm

```bash
make vector-validate   # không cần lab: cú pháp vector.yaml, 21 unit test, schema ↔ Vector ↔ mapping
make schema-test       # log thô của 5 nguồn ↔ schema (27 trường mục 13.1)
make siem-test         # đầu-cuối: 5 nguồn → SIEM, HMAC đúng khoá, chèn token, scanner, mapping strict
make siem-scan         # chỉ chạy scanner (mã thoát 0 = sạch)
make siem-search       # 20 sự kiện mới nhất
./scripts/siem-export.sh [TỪ_THỜI_ĐIỂM] > events.ndjson   # xuất sự kiện (tuần 10 dùng cho dataset)
```

OpenSearch không có `ports:`; mọi truy vấn chạy từ trong container, ví dụ đếm lần backend từ chối
theo lý do:

```bash
docker compose exec -T opensearch curl -s -H 'Content-Type: application/json' \
  'http://127.0.0.1:9200/topic09-events/_search?size=0' \
  -d '{"query":{"term":{"backend_object_authz":"deny"}},"aggs":{"ly_do":{"terms":{"field":"backend_authz_reason"}}}}'
```

**Sửa schema:** sửa `schema.json` → thêm tên trường vào danh sách `allowed` của `seal` trong
`vector.yaml` → `make siem-mapping` → `make vector-validate` (báo lỗi nếu ba bên lệch nhau) →
`make up` (`opensearch-init` cập nhật mapping của index đang có).

## 7. Rủi ro còn lại

| Rủi ro | Vì sao chấp nhận trong lab | Hướng nâng cấp |
|---|---|---|
| Vector mount `/var/run/docker.sock` — ai điều khiển được Vector thì gọi được Docker API (T11, TB6) | Vector không có port, chỉ ở mạng internal, không nhận dữ liệu từ mạng, file hệ thống chỉ đọc, bỏ mọi capability | proxy chỉ cho phép API đọc log, hoặc để service đẩy log qua mTLS |
| OpenSearch không TLS, không tài khoản (TB5) | chỉ Vector ở cùng mạng internal; giống cách bảo vệ OPA | security plugin: TLS bằng CA nội bộ, tài khoản Vector chỉ được ghi |
| Log giả chèn **trước** Vector không bị phát hiện (T9) | ai ghi được vào stdout của container thì đã chiếm container đó | ký log tại nguồn; mTLS service → collector |
| Sửa/xoá tài liệu trong OpenSearch | tuần 9: hash chain + digest ký bằng Vault — *phát hiện* được, không *ngăn* được | index chỉ-ghi-thêm, lưu digest ở nơi khác |
| Vector dừng thì sự kiện trong lúc dừng bị mất (đọc log "từ bây giờ") | lab một máy | bộ đệm trên đĩa, checkpoint |
| `authn_method` là giá trị suy ra từ `client_id`, không phải quan sát được | mỗi client của realm chỉ bật một luồng | đối chiếu với `idp_event` / `grant_type` của Keycloak |
| Sự kiện quản trị của Keycloak (đổi cấu hình realm) chưa vào SIEM | chưa cần cho 6 hunt của tuần 9 | thêm một nhánh trong `norm_keycloak` |
