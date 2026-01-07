w3#!/bin/bash

# setup_env.sh
# A script to detect OS/Arch, install osquery, and install KCL-Planning/VAL

set -e

# --- Colors for Output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- 1. Check for Root Privileges ---
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run as root.${NC}"
  exit 1
fi

echo -e "${YELLOW}Starting environment setup...${NC}"

# --- 2. Detect Operating System & Architecture ---
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    DISTRO_ID=$ID
else
    echo -e "${RED}Error: Cannot detect OS. /etc/os-release not found.${NC}"
    exit 1
fi

# Detect Architecture
RAW_ARCH=$(uname -m)
case $RAW_ARCH in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo -e "${RED}Error: Unsupported architecture '$RAW_ARCH'.${NC}"
        exit 1
        ;;
esac

echo -e "${GREEN}Detected OS: $OS ($DISTRO_ID)${NC}"
echo -e "${GREEN}Detected Arch: $RAW_ARCH (Mapped to: $ARCH)${NC}"

# --- 3. Install osquery and VAL Dependencies ---
echo -e "${YELLOW}Installing osquery and build dependencies...${NC}"

case $DISTRO_ID in
    ubuntu|debian|kali|pop|linuxmint)
        # --- Ubuntu/Debian Family ---

        # 1. Osquery Setup
        apt-get update -y
        apt-get install -y software-properties-common curl gnupg

        # Add key
        curl -L https://pkg.osquery.io/deb/osquery.gpg | apt-key add -

        # Add repo (using dynamic $ARCH)
        add-apt-repository "deb [arch=$ARCH] https://pkg.osquery.io/deb deb main" -y

        # 2. VAL Dependencies
        apt-get update -y
        apt-get install -y osquery git cmake make g++ flex bison
        ;;

    centos|rhel|almalinux|rocky|fedora)
        # --- RHEL/Fedora Family ---
        # RPM repos typically handle arch automatically via $basearch

        # 1. Osquery Setup
        if command -v dnf &> /dev/null; then
            PKG_MGR="dnf"
        else
            PKG_MGR="yum"
            $PKG_MGR install -y yum-utils
        fi

        curl -L https://pkg.osquery.io/rpm/osquery-s3-rpm.repo -o /etc/yum.repos.d/osquery-s3-rpm.repo

        # 2. VAL Dependencies
        $PKG_MGR install -y osquery git cmake make gcc-c++ flex bison
        ;;

    *)
        echo -e "${RED}Error: Unsupported distribution '$DISTRO_ID'.${NC}"
        echo "Please install osquery and VAL dependencies manually."
        exit 1
        ;;
esac

# --- 4. Verify & Start osquery ---
if command -v osqueryi &> /dev/null; then
    echo -e "${GREEN}Success! osquery installed.${NC}"
    # Enable and start the daemon
    systemctl enable osqueryd
    systemctl start osqueryd
else
    echo -e "${RED}osquery installation failed.${NC}"
    exit 1
fi

# --- 5. Install VAL (KCL-Planning) ---
echo -e "${YELLOW}Starting VAL (KCL-Planning) installation...${NC}"

BUILD_DIR="/tmp/val_build_temp"

# Cleanup
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Clone
echo "Cloning VAL repository..."
git clone https://github.com/KCL-Planning/VAL.git "$BUILD_DIR/VAL"

# Build
echo "Compiling VAL..."
cd "$BUILD_DIR/VAL"
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Install
if [ -f "./Validate" ]; then
    echo "Installing binary to /usr/local/bin/Validate..."
    cp ./Validate /usr/local/bin/Validate
    chmod +x /usr/local/bin/Validate
    ln -sf /usr/local/bin/Validate /usr/local/bin/validate

    echo -e "${GREEN}Success! VAL installed.${NC}"
else
    echo -e "${RED}Error: VAL binary build failed. Check compilation output.${NC}"
    exit 1
fi

# Cleanup
cd /
rm -rf "$BUILD_DIR"

echo -e "${GREEN}All Setup complete.${NC}"