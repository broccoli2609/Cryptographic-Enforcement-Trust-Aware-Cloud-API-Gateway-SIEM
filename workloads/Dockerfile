# Một Dockerfile build cho cả hai backend; docker-compose truyền tên qua build arg SERVICE.

# Giai đoạn 1: biên dịch ra một file chạy tĩnh (không cần thư viện C).
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY . .
ARG SERVICE
RUN test -n "$SERVICE" \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${SERVICE}

# Giai đoạn 2: image chạy chỉ chứa file chạy — không shell, không trình quản lý gói,
# chạy bằng user không phải root. Ít thứ bên trong = ít thứ để kẻ tấn công lợi dụng.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
