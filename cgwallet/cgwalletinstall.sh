#!/bin/bash

#SPDX-License-Identifier: GPL-2.0
#Copyright (C) 2023 Vicente Aceituno Canal vpn@cableguard.org All Rights Reserved.

#Step 1: Add environment variables to .bashrc

# If no command-line arguments provided, set to "mainnet"
if [ $# -eq 0 ]; then
    BLOCKCHAIN_ENV="mainnet"
    NEAR_ENV="mainnet"
else
    BLOCKCHAIN_ENV="$1"
    NEAR_ENV="$1"
fi

# Export the variables
export BLOCKCHAIN_ENV=\"$BLOCKCHAIN_ENV\"
export NEAR_ENV=\"$NEAR_ENV\"

# Append the export commands to ~/.bashrc
echo "export BLOCKCHAIN_ENV=\"$BLOCKCHAIN_ENV\"" >> ~/.bashrc
echo "export NEAR_ENV=\"$NEAR_ENV\"" >> ~/.bashrc

# Display a message
#!/bin/bash

# If NFTCONTRACTID is not set, set it to "UNKNOWN"
: "${NFTCONTRACTID:=UNKNOWN}"

VERSION="1.1.0"
echo "Cableguard WALLET install, Version $VERSION running on $BLOCKCHAIN_ENV at Smart Contract $NFTCONTRACTID. Get help with: $0 help"
echo "npm, jq, nodejs and near CLI will be installed"

export LC_ALL=C

#Step 2: Install Node.js and npm

sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo apt install -y npm
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
sudo npm install -g near-cli

#Check if Node.js and npm were installed successfully

if ! command -v node &>/dev/null || ! command -v npm &>/dev/null; then
    echo "Error: Node.js and/or npm installation failed."
    exit 1
fi

#Step 2: Install jq

sudo apt install -y jq

#Check if jq was installed successfully

if ! command -v jq &>/dev/null; then
    echo "Error: jq installation failed."
    exit 1
fi

#Step 3: Clone the GitHub repository and create the cgwallet directory

mkdir -p cgwallet
git clone https://github.com/alanesmizi/cgwallet.git  cgwallet

#Check if the repository was cloned successfully

if [ ! -d "cgwallet" ]; then
    echo "Error: Cloning cgwallet repository failed."
    exit 1
fi

echo "Installation of npm, jq, nodejs and near cli probably completed successfully."
echo "Now you can use rodwallet.sh"

~/cgwallet/rodtwallet.sh genaccount

#chmod 400 your_file

echo "Please write down the account number, you can use it to configue Cableguard TUN"
echo "You can use RODTWALLET as follows, if you have the correct network and smartcontract set in the NFTCONTRACTID env variable"

~/cgwallet/rodtwallet.sh help
