FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY ./peer/main.go .
RUN go mod init peerchat && \
  go get github.com/cloudflare/circl/kem/kyber/kyber512 && \
  go get golang.org/x/crypto/sha3 && \
  go build -o peer main.go

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/peer /app/peer
ENTRYPOINT ["/app/peer"]