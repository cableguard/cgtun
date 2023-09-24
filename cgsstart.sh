#!/bin/bash

export BLOCKCHAIN_ENV=mainnet
export NEAR_ENV=mainnet
export NFTCONTRACTID=cableguard-org.near

VERSION="1.1.0"
#export NFTCONTRACTID=$(cat /home/icarus24/cgwallet/account)
echo "Version" $VERSION "running on " $BLOCKCHAIN_ENV "at Smart Contract" $NFTCONTRACTID " Get help with: "$0" help"

# Check if there are no entry parameters
if [ $# -eq 0 ]; then
    echo "Error: No entry parameter provided. Usage: $0 <json_file_name>"
    exit 1
fi

# Check if the JSON file exists
json_file="/home/icarus24/.near-credentials/mainnet/$1.json"
if [ ! -f "$json_file" ]; then
    echo "Error: JSON file '$json_file' does not exist."
    exit 1
fi

# Run cableguard and start the tunnel
if /usr/bin/sudo /home/icarus24/cgtun/target/release/cableguard-cli "$json_file" >> /var/log/cableguard.log 2>&1; then
    echo "cableguard-cli: Started and created the tunnel."
else
    echo "Error: cableguard-cli failed to start."
    exit 1
fi

# Run `sudo wg show` and capture the interface name
interface_name=$(sudo wg show | awk '/^interface:/ {print $2}')

# Check if the interface name is not empty
if [ -n "$interface_name" ]; then
    # Update bring the interface up
    if /usr/bin/sudo ip link set "$interface_name" up  >> /var/log/cableguard.log 2>&1; then
        echo "Bringing up interface: '$interface_name'."
    else
        echo "Error: Could not bring interface up"
        exit 1
    fi

    # Update iptables rules
#    if /usr/bin/sudo iptables -A FORWARD -i "$interface_name" -j ACCEPT >> /var/log/cableguard.log 2>&1; then
#        echo "iptables FORWARD rule: Added for interface '$interface_name'."
#    else
#        echo "Error: Failed to add iptables FORWARD rule."
#        exit 1
#    fi

    if /usr/bin/sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE >> /var/log/cableguard.log 2>&1; then
        echo "iptables NAT rule: Added for interface '$interface_name' to eth0."
    else
        echo "Error: Failed to add iptables NAT rule."
        exit 1
    fi

    if /usr/bin/sudo resolvectl dns "$interface_name" 4.4.4.4 >> /var/log/cableguard.log 2>&1; then
        echo "resolvectl DNS configuration: Set for interface '$interface_name'."
    else
        echo "Error: Failed to set resolvectl DNS configuration."
        exit 1
    fi

    if /usr/bin/sudo ip link set mtu 1420 up dev "$interface_name" >> /var/log/cableguard.log 2>&1; then
        echo "Interface MTU: Set to 1420 for '$interface_name'."
    else
        echo "Error: Failed to set interface MTU."
        exit 1
    fi

    if /usr/bin/sudo ufw route allow in on "$interface_name" out on eth0 >> /var/log/cableguard.log 2>&1; then
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
