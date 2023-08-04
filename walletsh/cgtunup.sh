#!/bin/bash

VERSION="0.9.1"
#export NFTCONTRACTID=$(cat ./walletsh/account)
echo "Version" $VERSION "running on " $BLOCKCHAIN_ENV "at Smart Contract" $NFTCONTRACTID " Get help with: "$0" help"

# Run `sudo wg` and capture the output
wg_output=$(sudo wg)

# Extract the interface name and the listening port from the output
interface=$(echo "$wg_output" | awk '/interface:/{print $2}')
listening_port=$(echo "$wg_output" | awk '/listening port:/{print $3}')

# Check if the interface name is non-empty before proceeding
if [ -n "$interface" ]; then
  # Bring up the WireGuard interface using `sudo ip link set <interface> up`
  sudo ip link set "$interface" up
  echo "WireGuard interface '$interface' has been brought up."
else
  echo "Error: Could not determine the WireGuard interface name."
fi
sudo wg set "$interface" peer $1 allowed-ips $2/32 endpoint $3:58578
