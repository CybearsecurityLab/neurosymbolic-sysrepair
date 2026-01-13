#!/bin/bash

# setup_env.sh
# Detects OS/Arch, installs osquery

set -e

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- 1. Check Root ---
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run as root.${NC}"
  exit 1
fi

echo -e "${BLUE}=== Environment Setup ===${NC}"

# --- 2. Detect OS & Arch ---
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    DISTRO_ID=$ID
else
    echo -e "${RED}Error: Cannot detect OS.${NC}"
    exit 1
fi

RAW_ARCH=$(uname -m)
case $RAW_ARCH in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo -e "${RED}Error: Unsupported arch '$RAW_ARCH'.${NC}"; exit 1 ;;
esac

echo -e "${GREEN}Detected: $OS ($DISTRO_ID) on $ARCH${NC}"

# --- 3. Osquery Check & Install ---
if command -v osqueryi &> /dev/null; then
    echo -e "${GREEN}✔ osquery is already installed.$(osqueryi --version | head -n 1)${NC}"
else
    echo -e "${YELLOW}osquery not found. Installing...${NC}"

    case $DISTRO_ID in
        ubuntu|debian|kali|pop|linuxmint)
            apt-get update -y
            apt-get install -y software-properties-common curl gnupg
            mkdir -p /etc/apt/keyrings
            curl -L https://pkg.osquery.io/deb/pubkey.gpg | tee /etc/apt/keyrings/osquery.asc > /dev/null
            echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/osquery.asc] https://pkg.osquery.io/deb deb main" | tee /etc/apt/sources.list.d/osquery.list
            apt-get update -y
            apt-get install -y osquery
            ;;
        centos|rhel|almalinux|rocky|fedora)
            if command -v dnf &> /dev/null; then PKG_MGR="dnf"; else PKG_MGR="yum"; fi
            $PKG_MGR install -y yum-utils
            curl -L https://pkg.osquery.io/rpm/osquery-s3-rpm.repo -o /etc/yum.repos.d/osquery-s3-rpm.repo
            $PKG_MGR install -y osquery
            ;;
        *)
            echo -e "${RED}Unsupported OS for automatic osquery install.${NC}"
            exit 1
            ;;
    esac
fi

# Ensure service is running
if ! systemctl is-active --quiet osqueryd; then
    echo -e "${YELLOW}Starting osqueryd service...${NC}"
    systemctl enable osqueryd
    systemctl start osqueryd
else
    echo -e "${GREEN}✔ osqueryd service is running.${NC}"
fi

echo -e "${BLUE}=== Setup Complete ===${NC}"