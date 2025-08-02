#!/bin/bash

# Zip Cracker - Automatic Installation Script for Linux/macOS
# Usage: curl -sSL https://raw.githubusercontent.com/fresh-milkshake/zip-cracker/master/scripts/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_OWNER="fresh-milkshake"
REPO_NAME="zip-cracker"
BINARY_NAME="zip-cracker"
INSTALL_DIR="$HOME/.local/bin"

# Function to print colored output
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to detect OS and architecture
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case "$os" in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="macos"
            ;;
        *)
            print_message $RED "Error: Unsupported operating system: $os"
            exit 1
            ;;
    esac
    
    case "$arch" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        *)
            print_message $RED "Error: Unsupported architecture: $arch"
            exit 1
            ;;
    esac
    
    print_message $BLUE "Detected platform: $OS-$ARCH"
}

# Function to get the latest release version
get_latest_version() {
    print_message $BLUE "Fetching latest release information..."
    
    if command -v curl >/dev/null 2>&1; then
        LATEST_VERSION=$(curl -s "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget >/dev/null 2>&1; then
        LATEST_VERSION=$(wget -qO- "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        print_message $RED "Error: Neither curl nor wget is available"
        exit 1
    fi
    
    if [ -z "$LATEST_VERSION" ]; then
        print_message $RED "Error: Could not fetch latest version"
        exit 1
    fi
    
    print_message $GREEN "Latest version: $LATEST_VERSION"
}

# Function to download and install the binary
install_binary() {
    local download_url="https://github.com/$REPO_OWNER/$REPO_NAME/releases/download/$LATEST_VERSION/${BINARY_NAME}-${LATEST_VERSION}-${OS}-${ARCH}.tar.gz"
    local temp_dir=$(mktemp -d)
    local temp_file="$temp_dir/${BINARY_NAME}.tar.gz"
    
    print_message $BLUE "Downloading $BINARY_NAME from $download_url..."
    
    if command -v curl >/dev/null 2>&1; then
        curl -L "$download_url" -o "$temp_file"
    elif command -v wget >/dev/null 2>&1; then
        wget "$download_url" -O "$temp_file"
    else
        print_message $RED "Error: Neither curl nor wget is available"
        exit 1
    fi
    
    if [ ! -f "$temp_file" ]; then
        print_message $RED "Error: Download failed"
        exit 1
    fi
    
    print_message $BLUE "Extracting archive..."
    tar -xzf "$temp_file" -C "$temp_dir"
    
    # Create install directory if it doesn't exist
    mkdir -p "$INSTALL_DIR"
    
    # Move binary to install directory
    if [ -f "$temp_dir/$BINARY_NAME" ]; then
        mv "$temp_dir/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
        print_message $GREEN "Binary installed to $INSTALL_DIR/$BINARY_NAME"
    else
        print_message $RED "Error: Binary not found in archive"
        exit 1
    fi
    
    # Clean up
    rm -rf "$temp_dir"
}

# Function to add to PATH
configure_path() {
    local shell_config=""
    local shell_name=$(basename "$SHELL")
    
    case "$shell_name" in
        bash)
            if [ -f "$HOME/.bashrc" ]; then
                shell_config="$HOME/.bashrc"
            elif [ -f "$HOME/.bash_profile" ]; then
                shell_config="$HOME/.bash_profile"
            fi
            ;;
        zsh)
            shell_config="$HOME/.zshrc"
            ;;
        fish)
            # Fish shell has different syntax
            if [ -d "$HOME/.config/fish" ]; then
                echo "set -gx PATH $INSTALL_DIR \$PATH" >> "$HOME/.config/fish/config.fish"
                print_message $GREEN "Added $INSTALL_DIR to PATH in Fish shell config"
                return
            fi
            ;;
        *)
            print_message $YELLOW "Unknown shell: $shell_name. You may need to manually add $INSTALL_DIR to your PATH."
            return
            ;;
    esac
    
    if [ -n "$shell_config" ]; then
        # Check if PATH export already exists
        if ! grep -q "export PATH.*$INSTALL_DIR" "$shell_config" 2>/dev/null; then
            echo "" >> "$shell_config"
            echo "# Added by zip-cracker installer" >> "$shell_config"
            echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$shell_config"
            print_message $GREEN "Added $INSTALL_DIR to PATH in $shell_config"
        else
            print_message $YELLOW "$INSTALL_DIR already in PATH in $shell_config"
        fi
    else
        print_message $YELLOW "Could not determine shell configuration file. Please manually add $INSTALL_DIR to your PATH."
    fi
}

# Function to verify installation
verify_installation() {
    if [ -x "$INSTALL_DIR/$BINARY_NAME" ]; then
        print_message $GREEN "Installation successful!"
        print_message $BLUE "Binary location: $INSTALL_DIR/$BINARY_NAME"
        
        # Check if binary is in PATH
        if command -v "$BINARY_NAME" >/dev/null 2>&1; then
            print_message $GREEN "$BINARY_NAME is available in PATH"
            print_message $BLUE "You can now run: $BINARY_NAME --help"
        else
            print_message $YELLOW "$BINARY_NAME is not yet available in PATH"
            print_message $BLUE "Please restart your terminal or run: source ~/.bashrc (or your shell's config file)"
            print_message $BLUE "Then you can run: $BINARY_NAME --help"
        fi
    else
        print_message $RED "Installation failed: Binary not found"
        exit 1
    fi
}

# Main installation process
main() {
    print_message $GREEN "=== Zip Cracker Installation Script ==="
    print_message $BLUE "This script will download and install zip-cracker to $INSTALL_DIR"
    
    # Check for required tools
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        print_message $RED "Error: Either curl or wget is required for installation"
        exit 1
    fi
    
    if ! command -v tar >/dev/null 2>&1; then
        print_message $RED "Error: tar is required for installation"
        exit 1
    fi
    
    detect_platform
    get_latest_version
    install_binary
    configure_path
    verify_installation
    
    print_message $GREEN "=== Installation Complete ==="
    print_message $BLUE "Documentation: https://github.com/$REPO_OWNER/$REPO_NAME"
}

# Run the installer
main "$@"