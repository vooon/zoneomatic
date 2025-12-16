FROM ghcr.io/goreleaser/goreleaser-cross:v1.25 AS builder

WORKDIR /build

COPY . .

RUN goreleaser build --snapshot --single-target

FROM scratch

LABEL org.opencontainers.image.description="Zone-o-matic DNS API Server"

COPY --from=builder /build/dist/zoneomatic*/zoneomatic /zoneomatic

EXPOSE 9999

ENTRYPOINT ["/zoneomatic"]
