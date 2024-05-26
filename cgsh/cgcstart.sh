#!/bin/bash

# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2023 Vicente Aceituno Canal vpn@cableguard.org All Rights Reserved.

# minor version is odd for testnet, even for mainnet
VERSION="1.1.31"

# Print script information
# export NFTCONTRACTID=$(cat ~/cgtun/cgsh/account)
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
echo "sudo ./target/release/cableguard-cli -v trace $json_file >> ~/cableguard.$1.log 2>&1"
if sudo ./target/release/cableguard-cli -v trace $json_file >> ~/cableguard.$1.log 2>&1; then
    echo "cableguard-cli: Started and created the tunnel."
else
    echo "Error: cableguard-cli failed to start."
    exit 1
fi

# Run `sudo wg show` and capture the interface name
echo "sudo wg show"
interface_name=$(sudo wg show | awk '/^interface:/ {print $2}')

echo "sudo nmcli connection modify" $interface_name "ipv4.ignore-auto-dns yes"
sudo nmcli connection modify $interface_name ipv4.ignore-auto-dns yes

# Extract the DNS resolver from the wg show command output
dns_resolver=$(sudo wg show | grep "DNS Resolver" | awk '{print $NF}')

# Check if the DNS resolver was found
if [ -z "$dns_resolver" ]; then
    echo "DNS Resolver not found in wg show output"
    exit 1
fi

# Modify the nmcli connection with the extracted DNS resolver
echo "sudo nmcli connection modify $interface_name ipv4.dns $dns_resolver"
sudo nmcli connection modify $interface_name ipv4.dns "$dns_resolver"

echo "sudo nmcli connection modify" $interface_name "ipv4.dns 8.8.8.8,8.8.4.4"
sudo nmcli connection modify $interface_name ipv4.dns "8.8.8.8,8.8.4.4"

# Check if the interface name is not empty
if [ -n "$interface_name" ]; then
    # Update bring the interface up
    echo "sudo ip link set "$interface_name" up"
    if sudo ip link set "$interface_name" up >> ~/cableguard.$1.log 2>&1; then
        echo "Bringing up interface: '$interface_name'."
    else
        echo "Error: Could not bring interface up"
        exit 1
    fi

    # Fetching the default gateway IP address
    DEFAULT_GATEWAY=$(ip route | awk '/default/ {print $3}')

    # Fetching the physical device IP address
    PHYSICAL_DEVICE_NAME=$(ip -4 route show default | awk '/default via/ {print $5}')

    # Fetching the server IP address, This is read from the A entry of the vpn server of the RODiT
    # or read again when running wg subdomain-peer to change server
    SERVER_IP=$(sudo wg show $interface_name | grep "endpoint:" | awk '{print $2}' | cut -d ':' -f 1)

    # Adding route using obtained values
    echo "sudo ip route add $SERVER_IP via $DEFAULT_GATEWAY dev $PHYSICAL_DEVICE_NAME"
    sudo ip route add $SERVER_IP via $DEFAULT_GATEWAY dev $PHYSICAL_DEVICE_NAME
    # sudo ip route del default via 0.0.0.0 dev wlo1
    # sudo ip route add 134.209.232.255 via 192.168.18.1 dev wlo1

    # Update iptables rules
    echo "sudo ip route add 0.0.0.0/1 dev "$interface_name""
    if sudo ip route add 0.0.0.0/1 dev "$interface_name" >> ~/cableguard.$1.log 2>&1; then
        echo "Default Gateway 0.0.0.0/1 rule: Added for interface '$interface_name'."
    else
        echo "Error: Failed to add iptables routing rule."
        exit 1
    fi

    echo "sudo ip route add 128.0.0.0/1 dev "$interface_name""
    if sudo ip route add 128.0.0.0/1 dev "$interface_name" >> ~/cableguard.$1.log 2>&1; then
        echo "Default Gateway 128.0.0.0/1 rule: Added for interface '$interface_name'."
    else
        echo "Error: Failed to add iptables routing rule."
        exit 1
    fi

    echo "Script completed successfully."
else
    echo "Error: Interface name not found in 'sudo wg show' output."
    exit 1
fi