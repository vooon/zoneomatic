FROM golang:alpine AS builder

WORKDIR /build

COPY . .
RUN go build -o zoneomatic ./cmd/zoneomatic

FROM alpine

LABEL org.opencontainers.image.description="Zone-o-matic DNS API Server"

COPY --from=builder /build/zoneomatic /zoneomatic

EXPOSE 9999

ENTRYPOINT ["/zoneomatic"]
