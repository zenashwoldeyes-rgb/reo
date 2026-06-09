#!/bin/sh
# REO installer — macOS / Linux.
#   curl -fsSL https://reo.sh/install.sh | sh
#
# Downloads the signed REO binary, verifies its checksum, and installs it to a
# directory on your PATH. REO itself never phones home; this installer is the one
# network step, and only at install time.
set -eu

# Binaries are served from GitHub Releases. Override REO_REPO to install a fork.
REPO="${REO_REPO:-zenashwoldeyes-rgb/reo}"
VERSION="${REO_VERSION:-latest}"
if [ "$VERSION" = "latest" ]; then
  BASE="https://github.com/${REPO}/releases/latest/download"
else
  BASE="https://github.com/${REPO}/releases/download/${VERSION}"
fi
INSTALL_DIR="${REO_INSTALL_DIR:-/usr/local/bin}"

say() { printf '\033[38;2;94;231;223m›\033[0m %s\n' "$1"; }
die() { printf '\033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }

# --- detect platform -------------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Darwin) os="apple-darwin" ;;
  Linux)  os="unknown-linux-gnu" ;;
  *) die "unsupported OS: $os (REO ships macOS and Linux binaries)" ;;
esac
case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) die "unsupported architecture: $arch" ;;
esac
target="${arch}-${os}"
asset="reo-${target}"

say "Installing REO ($target)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --- download + verify -----------------------------------------------------
url="${BASE}/${asset}"
say "Downloading $url"
curl -fsSL "$url" -o "$tmp/reo" || die "download failed"
curl -fsSL "$url.sha256" -o "$tmp/reo.sha256" || die "checksum download failed"

say "Verifying checksum"
expected="$(cut -d' ' -f1 "$tmp/reo.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/reo" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 "$tmp/reo" | cut -d' ' -f1)"
fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || die "checksum mismatch — refusing to install"

chmod +x "$tmp/reo"

# --- install ---------------------------------------------------------------
if [ -w "$INSTALL_DIR" ]; then
  mv "$tmp/reo" "$INSTALL_DIR/reo"
else
  say "Elevating to write $INSTALL_DIR"
  sudo mv "$tmp/reo" "$INSTALL_DIR/reo"
fi

# Defensively clear the macOS quarantine flag (curl doesn't set it, but this
# guarantees Gatekeeper never blocks the binary). No-op on Linux.
command -v xattr >/dev/null 2>&1 && xattr -d com.apple.quarantine "$INSTALL_DIR/reo" 2>/dev/null || true

say "Installed to $INSTALL_DIR/reo"

# --- optional: pull the local model ---------------------------------------
# REO runs on a quantized, on-device security model. If you have Ollama, we can
# pull it now; otherwise REO uses its heuristic engine until you install one.
if command -v ollama >/dev/null 2>&1; then
  say "Ollama detected — you can pull the REO model later with: ollama pull reo-security"
fi

printf '\n\033[1mDone.\033[0m Type \033[38;2;94;231;223mreo\033[0m to begin. Everything stays on your machine.\n'
