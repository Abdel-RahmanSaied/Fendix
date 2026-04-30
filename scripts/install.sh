#!/bin/sh
# Fendix installer — downloads the latest release binary for your platform.
#
# This script is mirrored to the public install repo on every release by
# .github/workflows/release.yml. The canonical user-facing URL is:
#   curl -fsSL https://get.fendix.dev/install.sh | sh
#
# Direct-from-mirror fallback (works even if get.fendix.dev DNS is down):
#   curl -fsSL https://raw.githubusercontent.com/Abdel-RahmanSaied/homebrew-fendix/main/install.sh | sh
#
# Options (environment variables):
#   FENDIX_VERSION  — specific version to install (default: latest)
#   FENDIX_DIR      — install directory (default: /usr/local/bin)
#   FENDIX_REPO     — override source repo (default: Abdel-RahmanSaied/homebrew-fendix)

set -e

REPO="${FENDIX_REPO:-Abdel-RahmanSaied/homebrew-fendix}"
INSTALL_DIR="${FENDIX_DIR:-/usr/local/bin}"

# Colors (if terminal supports them)
if [ -t 1 ]; then
    BOLD='\033[1m'
    GREEN='\033[32m'
    RED='\033[31m'
    YELLOW='\033[33m'
    RESET='\033[0m'
else
    BOLD='' GREEN='' RED='' YELLOW='' RESET=''
fi

info()  { printf "${GREEN}→${RESET} %s\n" "$1"; }
warn()  { printf "${YELLOW}!${RESET} %s\n" "$1"; }
error() { printf "${RED}✗${RESET} %s\n" "$1" >&2; exit 1; }

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux)  OS="linux" ;;
        darwin) OS="darwin" ;;
        *)      error "Unsupported OS: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64" ;;
        arm64|aarch64)  ARCH="arm64" ;;
        *)              error "Unsupported architecture: $ARCH" ;;
    esac
}

# Get the latest release version from GitHub
get_version() {
    if [ -n "$FENDIX_VERSION" ]; then
        VERSION="$FENDIX_VERSION"
        return
    fi

    info "Fetching latest version..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

    if [ -z "$VERSION" ]; then
        error "Could not determine latest version. Set FENDIX_VERSION manually."
    fi
}

# Download and install
install() {
    BINARY="fendix-${VERSION}-${OS}-${ARCH}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}"

    info "Downloading fendix ${VERSION} for ${OS}/${ARCH}..."

    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    if ! curl -fsSL -o "${TMP_DIR}/fendix" "$URL"; then
        error "Download failed. Check that version ${VERSION} exists for ${OS}/${ARCH}."
    fi

    # Verify checksum if available
    CHECKSUM_URL="${URL}.sha256"
    if curl -fsSL -o "${TMP_DIR}/fendix.sha256" "$CHECKSUM_URL" 2>/dev/null; then
        info "Verifying checksum..."
        EXPECTED=$(awk '{print $1}' "${TMP_DIR}/fendix.sha256")
        if command -v sha256sum >/dev/null 2>&1; then
            ACTUAL=$(sha256sum "${TMP_DIR}/fendix" | awk '{print $1}')
        elif command -v shasum >/dev/null 2>&1; then
            ACTUAL=$(shasum -a 256 "${TMP_DIR}/fendix" | awk '{print $1}')
        else
            warn "No sha256sum or shasum found — skipping checksum verification"
            ACTUAL="$EXPECTED"
        fi

        if [ "$EXPECTED" != "$ACTUAL" ]; then
            error "Checksum mismatch! Expected ${EXPECTED}, got ${ACTUAL}"
        fi
    fi

    chmod +x "${TMP_DIR}/fendix"

    # Install to target directory
    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMP_DIR}/fendix" "${INSTALL_DIR}/fendix"
    else
        info "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mv "${TMP_DIR}/fendix" "${INSTALL_DIR}/fendix"
    fi

    info "Installed fendix ${VERSION} to ${INSTALL_DIR}/fendix"
}

# Verify installation
verify() {
    if command -v fendix >/dev/null 2>&1; then
        printf "\n${BOLD}${GREEN}✓ fendix installed successfully!${RESET}\n\n"
        fendix version
        printf "\nGet started:\n"
        printf "  ${BOLD}fendix scan --url https://api.example.com${RESET}\n"
        printf "  ${BOLD}fendix scan --code ./src --spec openapi.yaml${RESET}\n\n"
    else
        warn "fendix installed but not in PATH. Add ${INSTALL_DIR} to your PATH,"
        warn "or re-run with FENDIX_DIR pointing at a directory already on PATH:"
        warn "  curl -fsSL https://get.fendix.dev/install.sh | FENDIX_DIR=\$HOME/.local/bin sh"
    fi
}

# Main
detect_platform
get_version
install
verify
