# --- Build stage ---
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod first so dependency downloads are cached separately from
# source changes (there are no external deps here, but this keeps the
# pattern correct if any get added later).
COPY go.mod ./
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /ticket-system .

# --- Run stage ---
FROM alpine:3.20

WORKDIR /app
COPY --from=builder /ticket-system .

EXPOSE 8080

ENTRYPOINT ["./ticket-system"]
