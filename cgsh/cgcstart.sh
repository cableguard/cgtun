#!/bin/bash

#SPDX-License-Identifier: GPL-2.0
#Copyright (C) 2023 Vicente Aceituno Canal vpn@cableguard.org All Rights Reserved.

#minor version is odd for testnet, even for mainnet
VERSION="1.0.7"

# Print script information
#export NFTCONTRACTID=$(cat ~/cgtun/cgsh/account)
echo "Version" $VERSION "running on " $BLOCKCHAIN_ENV "at Smart Contract" $NFTCONTRACTID " Get help with: "$0" help"

# Check if there are no entry parameters
if [ $# -eq 0 ]; then
    echo "Error: No entry parameter provided. Usage:" $0 "<json_file_name> (without extension)"
    exit 1
fi

if [ "$1" == "help" ]; then
    echo "Usage: "$0" [account_id] [Options]"
    echo "Works best when called from the cgtun directory"
    echo ""
    echo "Options:"
    echo "  "$0" <json_file_name> (without extension)"
    exit 0
fi

# Check if the JSON file exists
json_file=~/.near-credentials/$BLOCKCHAIN_ENV/$1.json
if [ ! -f "$json_file" ]; then
    echo "Error: JSON file $json_file does not exist."
    exit 1
fi

# Run cableguard and start the tunnel
if sudo ./target/release/cableguard-cli -v trace $json_file >> ~/cableguard.$1.log 2>&1; then
    echo "cableguard-cli: Started and created the tunnel."
else
    echo "Error: cableguard-cli failed to start."
    exit 1
fi

# Check if IP forwarding is enabled, if not, enable it
ip_forwarding=$(sysctl -n net.ipv4.ip_forward)
if [ "$ip_forwarding" -eq 0 ]; then
    echo "IP forwarding is currently disabled. Enabling it..."
    sudo sysctl -w net.ipv4.ip_forward=1
    if [ $? -ne 0 ]; then
        echo "Failed to enable IP forwarding."
        exit 1
    fi
    echo "IP forwarding has been enabled."
fi


# Run `sudo wg show` and capture the interface name
interface_name=$(sudo wg show | awk '/^interface:/ {print $2}')

# Check if the interface name is not empty
if [ -n "$interface_name" ]; then
    # Update bring the interface up
    if sudo ip link set "$interface_name" up  >> ~/cableguard.$1.log 2>&1; then
        echo "Bringing up interface: '$interface_name'."
    else
        echo "Error: Could not bring interface up"
        exit 1
    fi

    # Update iptables rules
    if sudo ip route add 0.0.0.0/1 dev "$interface_name" >> ~/cableguard.$1.log 2>&1; then
        echo "Default Gateway 0.0.0.0/1 rule: Added for interface '$interface_name'."
    else
        echo "Error: Failed to add iptables FORWARD rule."
        exit 1
    fi

    if sudo ip route add 128.0.0.0/1 dev "$interface_name" >> ~/cableguard.$1.log 2>&1; then
        echo "Default Gateway 128.0.0.0/1 rule: Added for interface '$interface_name'."
    else
        echo "Error: Failed to add iptables NAT rule."
        exit 1
    fi

    echo "Script completed successfully."
else
    echo "Error: Interface name not found in 'sudo wg show' output."
    exit 1
fi
