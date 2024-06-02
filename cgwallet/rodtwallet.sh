#!/bin/bash

#SPDX-License-Identifier: GPL-2.0
#Copyright (C) 2023 Vicente Aceituno Canal vpn@cableguard.org All Rights Reserved.

VERSION="1.90.71"
#export RODITCONTRACTID=$(cat ./walletsh/account)
echo "Version" $VERSION "running on " $BLOCKCHAIN_ENV "at Smart Contract" $RODITCONTRACTID " Get help with: "$0" help"

if [ "$1" == "help" ]; then
    echo "Usage: "$0" [account_id] [Options]"
    echo "Works best when called from the cgtun directory"
    echo ""
    echo "Options:"
    echo "  "$0" List of available accounts"
    echo "  "$0" <accountID>           : Lists the RODiT Ids in the account and its balance"
    echo "  "$0" <accountID> keys      : Displays the accountID and the Private Key of the account"
    echo "  "$0" <accountID> <RODiT Id> : Displays the indicated RODiTT"
    echo "  "$0" <funding accountId> <unitialized accountId> init    : Initializes account with 0.01 NEAR from funding acount"
    echo "  "$0" <origin accountId>  <destination accountId> <rotid> : Sends RODiT from origin account to destination account"
    echo "  "$0" genaccount            : Creates a new uninitialized accountID"
    exit 0
fi

if [ "$1" == "genaccount" ]; then
    # Add code for generating a new uninitialized accountID
    echo "Generating a new uninitialized accountID..."
    near generate-key --saveImplicit
    echo Acccount number:
    ls -t "$HOME/.near-credentials/$BLOCKCHAIN_ENV/" | head -n 1 | xargs -I {} basename {} .json
    echo "The balance of the account is:"
    near_state=$(near state "$1")
    balance=$(echo "$near_state" | awk -F ': ' '/formattedAmount/ {print $2}')
    if [ -z "$balance" ]; then
        echo "The account does not exist in the blockchain as it has no balance. You need to initialize it with at least 0.01 NEAR."
    else
        echo "Account $1"
        echo "Balance: '$balance'"
    fi
    exit 0
fi

if [ -n "$3" ] && [ "$3" != "init" ]; then
    echo "Sending RODiTT $3 from $1 to $2..."
    near call $RODITCONTRACTID nft_transfer "{\"receiver_id\": \"$2\", \"token_id\": \"$3\"}" --accountId $1 --depositYocto 1
    exit 0
fi

if [ "$3" = "init" ] && [ -n "$3" ]; then
    echo "Initializing with 0.01 NEAR "$2""
    near send $1 $2 0.01
    exit 0
fi

if [ -z $1  ]; then
    echo "There is a lag while collecting information from the blockchain"
    echo "The following is a list of accounts found in ~/.near-credentials :"
    formatted_output=$(ls -tr "$HOME/.near-credentials/$BLOCKCHAIN_ENV/" | awk -F '.' '{ print $1 }')
    echo "$formatted_output"
fi

if [ -n "$2" ]; then
    if [ "$2" == "keys" ]; then
        key_file="$HOME/.near-credentials/$BLOCKCHAIN_ENV/$1.json"
        echo "The contents of the key file (PrivateKey in Base58 account ID in Hex) are:"
        cat "$key_file" | jq -r '"\(.private_key | sub("ed25519:"; ""))\n\(.account_id)"'
        exit 0
    else
        echo "RODiT Contents"
        near view $RODITCONTRACTID nft_token "{\"token_id\": \"$2\"}"
        exit 0
    fi
fi

if [ -n "$1" ]; then
    echo "There is a lag while collecting information from the blockchain"
    echo "The following is a list of RODiT belonging to the input account:"
    output2=$(near view "$RODITCONTRACTID" nft_tokens_for_owner "{\"account_id\": \"$1\"}")
    filtered_output2=$(echo "$output2" | grep -o "token_id: '[^']*'" | sed "s/token_id: //")
    echo "$filtered_output2"
    echo "The balance of the account is:"
    near_state=$(near state "$1")
    balance=$(echo "$near_state" | awk -F ': ' '/formattedAmount/ {print $2}')
    if [ -z "$balance" ]; then
        echo "The account does not exist in the blockchain as it has no balance. You need to initialize it with at least 0.01 NEAR."
    else
        echo "Account $1"
        echo "Balance: '$balance'"
    fi
fi