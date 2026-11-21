# digester — ký hash chain của SIEM (tuần 9). Build giống gateway/auth-svc/Dockerfile.
# Chỉ thư viện chuẩn của Go → không có go.sum, không tải dependency.

# Giai đoạn 1: biên dịch ra file chạy tĩnh; tạo sẵn /state thuộc uid 65532 (nonroot của
# distroless) để volume digester-state mới tạo được Docker chép quyền này sang — nếu không, volume
# thuộc root và digester không ghi được sổ digest.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/digester \
 && mkdir -p /out/state && chown 65532:65532 /out/state && chmod 750 /out/state

# Giai đoạn 2: chỉ chứa file chạy — không shell, không trình quản lý gói, user không phải root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
COPY --from=build --chown=65532:65532 /out/state /state
USER nonroot:nonroot
ENTRYPOINT ["/app"]
