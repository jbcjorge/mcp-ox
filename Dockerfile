# Build stage
FROM golang:1.25-alpine AS build

RUN apk add --no-cache ca-certificates

ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /mcp-ox-security .

# Runtime stage
FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /src/LICENSE /LICENSE
COPY --from=build /mcp-ox-security /mcp-ox-security

USER 10001

EXPOSE 8080

ENTRYPOINT ["/mcp-ox-security"]
