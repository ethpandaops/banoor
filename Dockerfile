# syntax=docker/dockerfile:1

# The build runs on the builder's platform and cross-compiles, so the
# multi-platform release needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.4@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    GOWORK=off go mod download
COPY api/ api/
COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/ pkg/
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOWORK=off CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/ ./cmd/banoord ./cmd/banoorctl

# Static binaries on distroless, running as nonroot (uid 65532).
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
COPY --from=go /out/banoord /out/banoorctl /usr/local/bin/
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/banoord"]
CMD ["-listen", "0.0.0.0:8080", "-config", "/etc/banoor/config.json"]
