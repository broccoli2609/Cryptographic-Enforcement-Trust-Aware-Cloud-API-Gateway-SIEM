# auth-svc — server gRPC ext_authz của gateway (tuần 4). Build giống workloads/Dockerfile.

# Giai đoạn 1: biên dịch ra file chạy tĩnh.
FROM golang:1.27-alpine AS build
WORKDIR /src
# Tải dependency trước (lớp cache riêng), rồi "go mod verify" đối chiếu checksum với go.sum:
# gói bị sửa trên đường tải về thì build dừng (rủi ro chuỗi cung ứng).
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/auth-svc

# Giai đoạn 2: chỉ chứa file chạy — không shell, không trình quản lý gói, user không phải root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
