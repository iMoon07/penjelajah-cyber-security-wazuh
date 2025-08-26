#!/bin/bash

# Prompt for required values
read -p "Wazuh Agent version (e.g., 4.12.0-1): " AGENT_VERSION
read -p "Wazuh Manager IP address: " MANAGER_IP
read -p "Wazuh Agent group (e.g., server, default) [default]: " AGENT_GROUP
if [[ -z "$AGENT_GROUP" ]]; then
    AGENT_GROUP="default"
fi

# Detect architecture
ARCH=$(uname -m)
echo "[DEBUG] Detected architecture: $ARCH"
if [[ "$ARCH" == "x86_64" ]]; then
    ARCH_TYPE="amd64"
    RPM_ARCH="x86_64"
    echo "[DEBUG] ARCH_TYPE set to: $ARCH_TYPE"
elif [[ "$ARCH" == "aarch64" ]]; then
    ARCH_TYPE="arm64"
    RPM_ARCH="aarch64"
    echo "[DEBUG] ARCH_TYPE set to: $ARCH_TYPE"
else
    echo "[!] Unsupported architecture: $ARCH"
    exit 1
fi

# Detect OS type
if [[ -f /etc/debian_version ]]; then
    OS_TYPE="deb"
elif [[ -f /etc/redhat-release || -f /etc/centos-release || -f /etc/os-release && $(grep -i "rhel\|fedora\|centos" /etc/os-release) ]]; then
    OS_TYPE="rpm"
else
    echo "[!] Unsupported OS type."
    exit 1
fi

# Install Wazuh agent
if [[ "$OS_TYPE" == "deb" ]]; then
    FILE_NAME="wazuh-agent_${AGENT_VERSION}_${ARCH_TYPE}.deb"
    FILE_URL="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/$FILE_NAME"
    echo "[+] Downloading DEB package: $FILE_NAME"
    wget "$FILE_URL" -O "$FILE_NAME" || { echo "Download failed."; exit 1; }
    echo "[+] Installing DEB package..."
    sudo WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_GROUP="$AGENT_GROUP" dpkg -i "./$FILE_NAME" || exit 1
elif [[ "$OS_TYPE" == "rpm" ]]; then
    FILE_NAME="wazuh-agent-${AGENT_VERSION}.${RPM_ARCH}.rpm"
    FILE_URL="https://packages.wazuh.com/4.x/yum/$FILE_NAME"
    echo "[+] Downloading RPM package: $FILE_NAME"
    curl -sSL -o "$FILE_NAME" "$FILE_URL" || { echo "Download failed."; exit 1; }
    echo "[+] Installing RPM package..."
    sudo WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_GROUP="$AGENT_GROUP" rpm -ihv "./$FILE_NAME" || exit 1
fi

# Prompt for AUTH_KEY setup
read -p "Do you want to use an AUTH_KEY for authentication? (y/n): " USE_AUTH
if [[ "$USE_AUTH" =~ ^[Yy]$ ]]; then
    read -s -p "Enter Wazuh AUTH_KEY: " AUTH_KEY
    echo
    echo "[+] Configuring authd.pass..."
    echo "$AUTH_KEY" | sudo tee /var/ossec/etc/authd.pass > /dev/null
    sudo chmod 640 /var/ossec/etc/authd.pass
    sudo chown root:wazuh /var/ossec/etc/authd.pass
else
    echo "[!] Skipping AUTH_KEY configuration."
fi

# Enable and start Wazuh agent
echo "[+] Enabling and starting Wazuh agent..."
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

echo "Wazuh agent installation and configuration completed."