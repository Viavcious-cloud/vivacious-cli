#!/usr/bin/env bash

# Exit immediately if any command fails
set -e

echo "========================================================="
echo "  Installing Vivacious CLI..."
echo "========================================================="

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM="linux";;
    Darwin*)    PLATFORM="macos";;
    *)          echo "Error: Unsupported operating system: ${OS}"; exit 1;;
esac

# Detect Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)   ARCH_NAME="x64";;
    arm64|aarch64)  ARCH_NAME="arm64";;
    *)              echo "Error: Unsupported architecture: ${ARCH}"; exit 1;;
esac

BINARY_NAME="vivacious-${PLATFORM}-${ARCH_NAME}"
DOWNLOAD_URL="https://github.com/Viavcious-cloud/vivacious-cli/releases/latest/download/${BINARY_NAME}"

# Determine installation directory
INSTALL_DIR="/usr/local/bin"
USE_SUDO=true

if [ ! -w "$INSTALL_DIR" ] && [ "$EUID" -ne 0 ]; then
    INSTALL_DIR="${HOME}/.local/bin"
    USE_SUDO=false
    mkdir -p "$INSTALL_DIR"
fi

TARGET_PATH="${INSTALL_DIR}/vivacious"
TEMP_FILE="$(mktemp)"

echo "Downloading ${BINARY_NAME} from GitHub Releases..."
echo "Source: ${DOWNLOAD_URL}"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "${TEMP_FILE}" "${DOWNLOAD_URL}"
elif command -v wget >/dev/null 2>&1; then
    wget -q -O "${TEMP_FILE}" "${DOWNLOAD_URL}"
else
    echo "Error: curl or wget is required to download Vivacious CLI."
    exit 1
fi

if [ ! -s "${TEMP_FILE}" ]; then
    echo "Error: Downloaded binary is empty or failed to download."
    rm -f "${TEMP_FILE}"
    exit 1
fi

chmod +x "${TEMP_FILE}"

echo "Installing binary to ${TARGET_PATH}..."
if [ "$USE_SUDO" = true ] && [ "$EUID" -ne 0 ]; then
    sudo mv "${TEMP_FILE}" "${TARGET_PATH}"
    sudo chmod +x "${TARGET_PATH}"
else
    mv "${TEMP_FILE}" "${TARGET_PATH}"
    chmod +x "${TARGET_PATH}"
fi

echo ""
echo "========================================================="
echo "🎉 Vivacious CLI has been successfully installed!"
echo "========================================================="
echo ""

# Verify path eligibility
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "Notice: Directory '$INSTALL_DIR' is not in your PATH."
    echo "Please add it to your shell configuration (e.g., ~/.bashrc or ~/.zshrc):"
    echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
    echo ""
fi

echo "Run 'vivacious' from any shell terminal to get started."

