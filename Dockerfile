# Fendix — Multi-stage Docker build
# Produces a minimal image with the Go binary + Python engine.
#
# Build:  docker build -t fendix .
# Run:    docker run --rm fendix scan --url https://api.example.com

# ---- Stage 1: Build the Go binary ----
FROM golang:1.25-alpine@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45 AS go-builder
# ↑ Base image pinned to digest. Bumps come through dependabot
# (docker ecosystem in .github/dependabot.yml); never silently shift
# under us. The `1.25-alpine` tag stays in the line so a human reader
# knows what minor version we're on.

RUN apk add --no-cache git make

WORKDIR /build

# Copy Go module files first for layer caching
COPY go/go.mod go/go.sum ./go/
RUN cd go && go mod download

# Copy Python engine files for embedding
COPY python/ ./python/

# Copy Go source
COPY go/ ./go/
COPY Makefile ./

# Bundle Python engine into Go embed directory and build.
# -trimpath + CGO_ENABLED=0 match release.yml so a docker-built fendix
# and a release-pipeline fendix have comparable build provenance.
RUN make embed-engine && \
    cd go && CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w -X main.Version=docker" \
    -o /fendix ./cmd/fendix/

# ---- Stage 2: Runtime image ----
FROM python:3.14-slim@sha256:7a500125bc50693f2214e842a621440a1b1b9cbb2188f74ab045d29ed2ea5856

# Install Python dependencies for whitebox analysis.
# build-essential (gcc + libc6-dev + standard C headers) is needed
# transiently to compile C-extension deps that lack a manylinux wheel for
# this image's CPython: semgrep pins ruamel.yaml.clib==0.2.14, which has no
# cp314 wheel, so pip builds it from source. Bare gcc is insufficient — the
# build needs libc dev headers (assert.h) that python:*-slim omits. The
# toolchain is installed only long enough to build the wheels, then purged
# in the same layer so the final runtime image ships no compiler.
COPY python/requirements.txt /tmp/requirements.txt
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    pip install --no-cache-dir -r /tmp/requirements.txt && \
    apt-get purge -y build-essential && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/requirements.txt

# Copy the Go binary
COPY --from=go-builder /fendix /usr/local/bin/fendix

# Copy the Python engine (for direct use, not just embedded)
COPY python/ /opt/fendix/python/
# EnsureEngine (go/internal/engine/extract.go) resolves the taint engine via
# the FENDIX_ENGINE env var — this MUST match that name. A prior typo set
# FENDIX_PYTHON_ENGINE, which the Go side never reads, so resolution fell
# through to the embedded placeholder and then the CWD-relative ./python
# fallback (WORKDIR /workspace → /workspace/python, absent), silently
# disabling whitebox taint analysis in every container. FENDIX_PYTHON_ENGINE
# is kept as a human-facing alias only.
ENV FENDIX_ENGINE=/opt/fendix/python/
ENV FENDIX_PYTHON_ENGINE=/opt/fendix/python/

# Non-root user for security
RUN useradd -m -s /bin/sh fendix
USER fendix
WORKDIR /workspace

ENTRYPOINT ["fendix"]
CMD ["version"]
