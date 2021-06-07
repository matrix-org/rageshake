FROM golang:alpine as builder
RUN apk add --update --no-cache git ca-certificates

RUN mkdir /build 
WORKDIR /build
COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o rageshake

FROM scratch
COPY --from=builder /build/rageshake /rageshake
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/rageshake.yaml /rageshake.yaml
WORKDIR /
EXPOSE 9110
CMD ["/rageshake"]
