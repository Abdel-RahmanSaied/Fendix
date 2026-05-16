# Fendix GitHub App — multi-stage Docker build
#
# Produces a minimal image that runs `fendix-app` (the webhook server)
# alongside a working `fendix` CLI + embedded Python engine on PATH.
# The webhook handler shells out to `git` (to clone the PR head) and
# `fendix` (to run the actual scan + render SARIF) — both must be in
# the runtime image.
#
# Build:  docker build -f Dockerfile.app -t fendix-app .
# Run:    docker run --rm -p 8080:8080 \
#           -e FENDIX_APP_ID=<id> \
#           -e FENDIX_APP_PRIVATE_KEY="$(cat private-key.pem)" \
#           -e FENDIX_WEBHOOK_SECRET=<secret> \
#           fendix-app

# ---- Stage 1: Build the Go binaries ----
FROM golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052 AS go-builder
# Base image pinned to digest — see Dockerfile for rationale.

RUN apk add --no-cache git make

WORKDIR /build

COPY go/go.mod go/go.sum ./go/
RUN cd go && go mod download

COPY python/ ./python/
COPY go/ ./go/
COPY Makefile ./

# Bundle Python engine into the embed dir, then build both binaries.
# -trimpath + CGO_ENABLED=0 mirror release.yml so docker-built and
# release-built binaries share build provenance.
ARG VERSION=docker
RUN make embed-engine && \
    cd go && export CGO_ENABLED=0 && \
    go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /fendix      ./cmd/fendix/ && \
    go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /fendix-app  ./cmd/fendix-app/

# ---- Stage 2: Runtime image ----
FROM python:3.14-slim@sha256:7a500125bc50693f2214e842a621440a1b1b9cbb2188f74ab045d29ed2ea5856

# git is required for the clone step in the App's pull_request handler.
# ca-certificates so HTTPS to api.github.com + github.com works.
# tini for clean signal forwarding under non-PID-1 init.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Python deps for the embedded white-box engine.
COPY python/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

COPY --from=go-builder /fendix     /usr/local/bin/fendix
COPY --from=go-builder /fendix-app /usr/local/bin/fendix-app

COPY python/ /opt/fendix/python/
ENV FENDIX_PYTHON_ENGINE=/opt/fendix/python/

# Non-root runtime user. The clone target lives under /tmp which the
# scanner creates per-scan; no persistent state on disk.
RUN useradd -m -s /bin/sh fendix
USER fendix
WORKDIR /home/fendix

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/fendix-app"]
