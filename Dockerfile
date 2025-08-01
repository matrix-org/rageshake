ARG GO_VERSION=1.17
ARG DEBIAN_VERSION=11
ARG DEBIAN_VERSION_NAME=bullseye

## Build stage ##
FROM --platform=${BUILDPLATFORM} docker.io/library/golang:${GO_VERSION}-${DEBIAN_VERSION_NAME} AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o rageshake

## Runtime stage, python scripts ##
FROM python:3-slim AS scripts
COPY scripts/cleanup.py /cleanup.py
WORKDIR /

## Runtime stage, debug variant ##
FROM gcr.io/distroless/static-debian${DEBIAN_VERSION}:debug-nonroot AS debug
COPY --from=builder /build/rageshake /rageshake
WORKDIR /
EXPOSE 9110
ENTRYPOINT ["/rageshake"]

## Runtime stage ##
FROM gcr.io/distroless/static-debian${DEBIAN_VERSION}:nonroot
COPY --from=builder /build/rageshake /rageshake
WORKDIR /
EXPOSE 9110
ENTRYPOINT ["/rageshake"]
