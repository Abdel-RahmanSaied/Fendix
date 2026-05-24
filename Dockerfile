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

# Install Python dependencies for whitebox analysis
COPY python/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Copy the Go binary
COPY --from=go-builder /fendix /usr/local/bin/fendix

# Copy the Python engine (for direct use, not just embedded)
COPY python/ /opt/fendix/python/
ENV FENDIX_PYTHON_ENGINE=/opt/fendix/python/

# Non-root user for security
RUN useradd -m -s /bin/sh fendix
USER fendix
WORKDIR /workspace

ENTRYPOINT ["fendix"]
CMD ["version"]
