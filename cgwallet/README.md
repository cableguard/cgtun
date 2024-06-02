![cableguard logo banner](./banner.png)

# Cableguard WALLET for managing Cableguard RODT
This supplies the main userspace tooling for managing Rich Online Digital Tokens.

## License
This project is released under the [GPLv2](COPYING).
More information may be found at [WireGuard.com](https://www.wireguard.com/).**

## How to Install
Download cgwalletinstall.sh

Make it executable

Run it. It will install the npm, nodejs, jq, and near cli dependencies to be able to handle RODT with rodtwallet.sh

## How to Use
Options:

Usage: ./walletsh/rodtwallet.sh [account_id] [Options]

Options:
-  ./walletsh/rodtwallet.sh                   : List of available accounts
-  ./walletsh/rodtwallet.sh *accountID*       : Lists the RODT Ids in the account and its balance
-  ./walletsh/rodtwallet.sh *accountID* keys  : Displays the accountID and the Private Key of the account
-  ./walletsh/rodtwallet.sh *accountID* rodtId: Displays the indicated RODT
-  ./walletsh/rodtwallet.sh *fundingaccountId* *unitializedaccountId* init   : Initializes account with 0.01 NEAR from funding acount
-  ./walletsh/rodtwallet.sh *originaccountId*  *destinationaccountId* rodtId : Sends ROTD from origin account to destination account
-  ./walletsh/rodtwallet.sh genaccount        : Creates a new uninitialized accountID

From a funded wallet you need to send 0.01 NEAR to each new account to prime it
For testnet use: https://wallet.testnet.near.org/

# Cableguard Ecosystem
- Cableguard TUN: VPN tunnels
- Cableguard TOOLS: local VPN tunnel configuration
