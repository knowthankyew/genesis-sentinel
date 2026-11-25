FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod ./
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /sentinel ./cmd/sentinel && \
    mkdir -p /var/lib/genesis-sentinel && \
    chmod 0700 /var/lib/genesis-sentinel

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /sentinel /sentinel
COPY --from=builder --chown=65532:65532 /var/lib/genesis-sentinel /var/lib/genesis-sentinel
USER nonroot:nonroot

EXPOSE 8090/tcp

ENTRYPOINT ["/sentinel"]
