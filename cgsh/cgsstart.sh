#!/bin/bash

# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2023 Vicente Aceituno Canal vpn@cableguard.org All Rights Reserved.

# minor version is odd for testnet, even for mainnet
VERSION="1.5.21"

# Print script information
# export NFTCONTRACTID=$(cat ~/cgtun/cgsh/account)
echo "Version" $VERSION "running on " $BLOCKCHAIN_ENV "at Smart Contract" $NFTCONTRACTID "thru eth0,  Get help with: "$0" help"

# Check if there are no entry parameters
if [ $# -eq 0 ]; then
    echo "Error: No entry parameter provided. Usage: $0 <json_file_name>"
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

# Check if IP forwarding is enabled, if not, enable it
ip_forwarding=$(sysctl -n net.ipv4.ip_forward)
if [ "$ip_forwarding" -eq 0 ]; then
    echo "IP forwarding is currently disabled. Enabling it..."
    echo "sudo sysctl -w net.ipv4.ip_forward=1"
    sudo sysctl -w net.ipv4.ip_forward=1
    if [ $? -ne 0 ]; then
        echo "Failed to enable IP forwarding."
        exit 1
    else
        echo "IP forwarding has been enabled."
    fi
else
    echo "IP forwarding is already enabled."
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

# Check if the interface name is not empty
if [ -n "$interface_name" ]; then
    # Update to bring the interface up
    echo "sudo ip link set "$interface_name" up"
    if sudo ip link set "$interface_name" up >> ~/cableguard.$1.log 2>&1; then
        echo "Bringing up interface: '$interface_name'."
    else
        echo "Error: Could not bring interface up."
        exit 1
    fi

    # Retrieve the IP address and class of the specified network interface
    ip_address=$(ip -o -4 addr show $interface_name | awk '{print $4}')

    # Check if the IP address is empty
    if [ -z "$ip_address" ]; then
        echo "Failed to retrieve IP address for interface $interface_name"
        exit 1
    fi

    echo "IP address configured on $interface_name: $ip_address"

    # Update iptables rules
    echo "sudo iptables -A FORWARD -i "$interface_name" -j ACCEPT"
    if sudo iptables -A FORWARD -i "$interface_name" -j ACCEPT >> ~/cableguard.$1.log 2>&1; then
        echo "iptables FORWARD rule: Added for interface '$interface_name'."
    else
        echo "Error: Failed to add iptables FORWARD rule."
        exit 1
    fi

    echo "sudo iptables -t nat -A POSTROUTING -s "$ip_address" -o eth0 -j MASQUERADE"
    if sudo iptables -t nat -A POSTROUTING -s $ip_address -o eth0 -j MASQUERADE >> ~/cableguard.$1.log 2>&1; then
        echo "iptables NAT rule: Added for interface '$interface_name' to eth0."
    else
        echo "Error: Failed to add iptables NAT rule."
        exit 1
    fi

    echo "sudo resolvectl dns "$interface_name" "$dns_server_ip4""
    if sudo resolvectl dns "$interface_name" "$dns_server_ip4"  >> ~/cableguard.$1.log 2>&1; then
        echo "resolvectl DNS configuration: Set for interface '$interface_name'."
    else
        echo "Error: Failed to set resolvectl DNS configuration."
        exit 1
    fi

    echo "sudo ip link set mtu 1420 up dev "$interface_name""
    if sudo ip link set mtu 1420 up dev "$interface_name" >> ~/cableguard.$1.log 2>&1; then
        echo "Interface MTU: Set to 1420 for '$interface_name'."
    else
        echo "Error: Failed to set interface MTU."
        exit 1
    fi

    echo "sudo ufw route allow in on "$interface_name" out on eth0"
    if sudo ufw route allow in on "$interface_name" out on eth0 >> ~/cableguard.$1.log 2>&1; then
        echo "UFW route: Allowed incoming on '$interface_name' out on eth0."
    else
        echo "Error: Failed to allow UFW route."
        exit 1
    fi

    echo "Script completed successfully."
else
    echo "Error: Interface name not found in 'sudo wg show' output."
    exit 1
fi