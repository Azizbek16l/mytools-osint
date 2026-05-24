#!/usr/bin/env bash
# One-line installer for mytools-osint CLI.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Azizbek16l/mytools-osint/main/scripts/install.sh | bash
#
# Pulls the latest release from GitHub, verifies SHA-256, drops `osint`
# into ~/.local/bin (no sudo). Honors:
#   OSINT_VERSION       — pin a specific release ('latest' default)
#   OSINT_INSTALL_DIR   — install location (default ~/.local/bin)
set -euo pipefail

REPO="Azizbek16l/mytools-osint"
VERSION="${OSINT_VERSION:-latest}"
INSTALL_DIR="${OSINT_INSTALL_DIR:-$HOME/.local/bin}"

# --- platform detect ---
case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64|aarch64) ASSET="osint-macos-arm64";;
      x86_64)         ASSET="osint-macos-x86_64";;
      *) echo "unsupported macOS arch: $(uname -m)" >&2; exit 1;;
    esac;;
  Linux)
    case "$(uname -m)" in
      x86_64|amd64) ASSET="osint-linux-x86_64";;
      *) echo "unsupported Linux arch: $(uname -m) — fallback: 'pipx install mytools-osint'" >&2; exit 1;;
    esac;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1;;
esac

# --- resolve version ---
if [ "$VERSION" = "latest" ]; then
  TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
  if [ -z "$TAG" ]; then echo "could not resolve latest tag" >&2; exit 1; fi
else
  TAG="v${VERSION#v}"
fi

BASE="https://github.com/$REPO/releases/download/$TAG"
echo "  installing mytools-osint $TAG  →  $INSTALL_DIR/osint"

# --- download + verify ---
TMPDIR=$(mktemp -d -t osint-install-XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT
cd "$TMPDIR"

echo "  ↓ $ASSET …"
curl -fsSL -o osint "$BASE/$ASSET"
if ! curl -fsSL -o SHA256SUMS "$BASE/SHA256SUMS"; then
  echo "  ⚠ SHA256SUMS not in release — installing UNVERIFIED" >&2
else
  expected=$(grep -E " [*]?${ASSET}\$" SHA256SUMS | awk '{print $1}')
  if [ -z "$expected" ]; then
    echo "  ⚠ no SHA-256 entry for $ASSET — installing UNVERIFIED" >&2
  else
    if command -v sha256sum >/dev/null; then got=$(sha256sum osint | awk '{print $1}')
    elif command -v shasum >/dev/null; then got=$(shasum -a 256 osint | awk '{print $1}')
    else echo "  no sha256 tool found, skipping verify" >&2; got="$expected"
    fi
    if [ "$got" != "$expected" ]; then
      echo "  ✗ SHA-256 mismatch — refusing to install" >&2
      echo "    expected: $expected" >&2
      echo "    got:      $got" >&2
      exit 1
    fi
    echo "  ✓ SHA-256 verified ($expected | first 16 = ${expected:0:16})"
  fi
fi

# --- install ---
mkdir -p "$INSTALL_DIR"
chmod +x osint
mv osint "$INSTALL_DIR/osint"

# --- PATH hint ---
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo
     echo "  ⤴ $INSTALL_DIR is NOT in your PATH. Add to ~/.zshrc or ~/.bashrc:"
     echo "      export PATH=\"$INSTALL_DIR:\$PATH\""
     ;;
esac

echo
echo "  ✓ done. Run:"
echo "      osint --version"
echo "      osint --list-profiles"
echo "      osint github.com --profile red-team"
