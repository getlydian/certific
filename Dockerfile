FROM golang:1.26.2-alpine AS build
WORKDIR /src

ARG VERSION=dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux \
    go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/certific \
        ./cmd/certific

# Pre-create the state dir owned by uid/gid 65532 (distroless `nonroot`).
# When a fresh Docker volume is mounted at /var/lib/certific at runtime,
# Docker copies the mount point's ownership onto the empty volume —
# without this, the volume comes up root:root and the nonroot process
# can't write to it.
RUN mkdir -p /out/var/lib/certific && chown -R 65532:65532 /out/var/lib/certific

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/certific /certific
COPY --from=build --chown=65532:65532 /out/var/lib/certific /var/lib/certific
USER nonroot:nonroot
ENTRYPOINT ["/certific"]
