# Fendix — Multi-stage Docker build
# Produces a minimal image with the Go binary + Python engine.
#
# Build:  docker build -t fendix .
# Run:    docker run --rm fendix scan --url https://api.example.com

# ---- Stage 1: Build the Go binary ----
FROM golang:1.21-alpine AS go-builder

RUN apk add --no-cache git

WORKDIR /build

# Copy Go module files first for layer caching
COPY go/go.mod go/go.sum ./go/
RUN cd go && go mod download

# Copy Python engine files for embedding
COPY python/ ./python/

# Copy Go source
COPY go/ ./go/
COPY Makefile ./

# Bundle Python engine into Go embed directory and build
RUN make embed-engine && \
    cd go && go build \
    -ldflags="-s -w -X main.Version=docker" \
    -o /fendix ./cmd/fendix/

# ---- Stage 2: Runtime image ----
FROM python:3.11-slim

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
