FROM golang:1.23 as builder

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o pvz-service ./cmd/server/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /root/
COPY --from=builder /app/pvz-service .
COPY --from=builder /app/migrations ./migrations

EXPOSE 8080
CMD ["./pvz-service"]