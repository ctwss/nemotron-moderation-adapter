FROM golang:1.23-alpine AS builder

RUN apk add --no-cache ca-certificates
WORKDIR /src

COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/nemotron-moderation-adapter ./cmd/server

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/nemotron-moderation-adapter /nemotron-moderation-adapter

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/nemotron-moderation-adapter"]
