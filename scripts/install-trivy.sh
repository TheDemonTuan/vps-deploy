#!/usr/bin/env bash
set -euo pipefail

TRIVY_VERSION="0.74.0"
BIN_DIR="${1:-/usr/local/bin}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)
    FILE="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
    EXPECTED_SHA="2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
    ;;
  aarch64|arm64)
    FILE="trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz"
    EXPECTED_SHA="b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5"
    ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${FILE}"
curl -sSfL "$URL" -o "${TMP_DIR}/${FILE}"
echo "${EXPECTED_SHA}  ${TMP_DIR}/${FILE}" | sha256sum -c -

tar -xzf "${TMP_DIR}/${FILE}" -C "${TMP_DIR}" trivy
install -m 0755 "${TMP_DIR}/trivy" "${BIN_DIR}/trivy"
"${BIN_DIR}/trivy" --version
