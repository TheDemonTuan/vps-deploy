#!/usr/bin/env bash
set -euo pipefail

GRYPE_VERSION="0.120.0"
BIN_DIR="${1:-/usr/local/bin}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

case "$(uname -m)" in
  x86_64|amd64)
    FILE="grype_${GRYPE_VERSION}_linux_amd64.tar.gz"
    EXPECTED_SHA="a5a1218dce63acdac152a6b3b5bb366e7267e36f4069848cf455543b3fa5700e"
    ;;
  aarch64|arm64)
    FILE="grype_${GRYPE_VERSION}_linux_arm64.tar.gz"
    EXPECTED_SHA="bc0e52b1a0de37e2ff021c4924d689dce7dcff2e7d74b39aea16c0453e69be18"
    ;;
  *) echo 'Unsupported native Grype architecture' >&2; exit 1 ;;
esac

curl -sSfL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/${FILE}" -o "$TMP_DIR/$FILE"
echo "$EXPECTED_SHA  $TMP_DIR/$FILE" | sha256sum -c -
tar -xzf "$TMP_DIR/$FILE" -C "$TMP_DIR" grype
install -m 0755 "$TMP_DIR/grype" "$BIN_DIR/grype"
"$BIN_DIR/grype" version
