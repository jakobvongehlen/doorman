# Doorman's WhatsApp sidecar: wacli (github.com/steipete/wacli, MIT) built from a pinned release, and
# shim.py, which keeps `wacli sync --follow` running and gives Doorman a small HTTP API.
ARG WACLI_VERSION=v0.26.0
ARG WACLI_COMMIT=535a8b969cc83c3aad57f66be77e8fd4a7fcaaa3

FROM golang:1.27.3-alpine AS build
ARG WACLI_VERSION
ARG WACLI_COMMIT
RUN apk add --no-cache build-base ca-certificates git
RUN git clone --depth 1 --branch "$WACLI_VERSION" https://github.com/steipete/wacli.git /src \
    && test "$(git -C /src rev-parse HEAD)" = "$WACLI_COMMIT"
WORKDIR /src
RUN go mod download
RUN CGO_ENABLED=1 CGO_CFLAGS="-Wno-error=missing-braces" GOOS=linux \
    go build -tags sqlite_fts5 -trimpath -ldflags="-s -w" -o /out/wacli ./cmd/wacli

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata python3 \
    && adduser -D -u 10001 -h /home/wacli wacli \
    && mkdir -p /data/store /data/state /data/config /data/cache /run/doorman-whatsapp \
    && chown -R wacli:wacli /data /run/doorman-whatsapp
# The token Doorman uses for the API: made up on the first start, kept in a volume Doorman mounts read-only.
# The file is 0600; Doorman reads it as its user doorman, which has the same uid (10001).
ENV HOME=/home/wacli \
    SIDECAR_TOKEN_FILE=/run/doorman-whatsapp/token \
    WACLI_STORE_DIR=/data/store \
    XDG_STATE_HOME=/data/state \
    XDG_CONFIG_HOME=/data/config \
    XDG_CACHE_HOME=/data/cache \
    LISTEN=0.0.0.0:8720
COPY --from=build /out/wacli /usr/local/bin/wacli
COPY shim.py /usr/local/lib/doorman-whatsapp/shim.py
VOLUME ["/data"]
WORKDIR /data
USER wacli
ENTRYPOINT ["python3", "-I", "/usr/local/lib/doorman-whatsapp/shim.py"]
