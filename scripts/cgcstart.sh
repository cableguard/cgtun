#!/bin/bash

VERSION="1.0.0"
#export NFTCONTRACTID=$(cat /home/icarus24/cgwallet/account)
echo "Version" $VERSION "running on " $BLOCKCHAIN_ENV "at Smart Contract" $NFTCONTRACTID " Get help with: "$0" help"

# Run cableguard and start the tunnel
if /usr/bin/sudo /home/icarus24/cgtun/target/release/cableguard-cli /home/icarus24/.near-credentials/mainnet/3b251bcc1985e34c7fb8bb0f20304dd4f20c673e7977fe72f00c6eda81b60da6.json >> /var/log/cableguard.log 2>&1; then
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
    if /usr/bin/sudo ip route add 0.0.0.0/1 dev "$interface_name" >> /var/log/cableguard.log 2>&1; then
        echo "Default Gateway 0.0.0.0/1 rule: Added for interface '$interface_name'."
    else
        echo "Error: Failed to add iptables FORWARD rule."
        exit 1
    fi

    if /usr/bin/sudo ip route add 128.0.0.0/1 dev "$interface_name" >> /var/log/cableguard.log 2>&1; then
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
