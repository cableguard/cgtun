#!/bin/bash

# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2023 Vicente Aceituno Canal vpn@cableguard.org All Rights Reserved.

VERSION="1.90.91"

# Function to display help message
show_help() {
    echo "Usage: $0 {help|testnet|mainnet}"
    echo "  help    : List of commands"
    echo "  testnet RODIT_CONTRACT_ID: Installs cgwallet, NEAR CLI and configure testnet"
    echo "  mainnet RODIT_CONTRACT_ID: Installs cgwallet, NEAR CLI and configure mainnet"
}

# Function to append environment variables to ~/.bashrc
add_env_vars() {
    export BLOCKCHAIN_ENV=$1
    export RODITCONTRACTID=$2
    echo "export BLOCKCHAIN_ENV="$BLOCKCHAIN_ENV"" >> ~/.bashrc
    echo "export RODITCONTRACTID="$RODITCONTRACTID"" >> ~/.bashrc
}

# Function to install NEAR CLI
install_near_cli() {
    sudo apt-get update
    curl --proto '=https' --tlsv1.2 -LsSf https://github.com/near/near-cli-rs/releases/download/v0.10.2/near-cli-rs-installer.sh | sh
}

# Function to install jq
install_jq() {
    sudo apt install -y jq
    if ! command -v jq &>/dev/null; then
        echo "Error: jq installation failed."
        exit 1
    fi
}

# Function to clone and run roditwallet
setup_cgwallet() {
    git clone https://github.com/cableguard/cgwallet
    if [ ! -f ~/cgwallet/roditwallet.sh ]; then
        echo "Error: roditwallet.sh script not found."
        exit 1
    fi
    chmod +x ~/cgwallet/roditwallet.sh
    ~/cgwallet/roditwallet.sh genaccount
    echo "Please write down the account number, you can use it to configure Cableguard TUN"
    echo "You can use RODiTWALLET if you have the correct network and smartcontract set in the RODITCONTRACTID env variable"
}

# Main script execution
if [ "$1" == "help" ]; then
    show_help
    exit 0
fi

# Set environment variables based on command-line arguments
if [ $# -eq 0 ]; then
    BLOCKCHAIN_ENV="mainnet"
else
    BLOCKCHAIN_ENV="$1"
fi

# Ensure RODITCONTRACTID is set or default to UNKNOWN
: "${RODITCONTRACTID:=UNKNOWN}"

# Add environment variables to .bashrc
add_env_vars

# Install necessary components
install_near_cli
install_jq

# Clone and setup cgwallet
setup_cgwallet
