#!/bin/bash

VERSION="1.0.0"
echo Version $VERSION "Help: "$0" help"
export BLOCKCHAIN_ENV="testnet"
export NFTCONTRACTID=$(cat ./dev-account 2>/dev/null) || { echo "Error: dev-account file with the Smart Contract account ID not found."; exit 1; }

if [ "$1" == "help" ]; then
    echo "Usage: "$0" [account_id] [Options]"
    echo ""
    echo "Options:"
    echo "  "$0" List of available accounts"
    echo "  "$0" <accountID>      : Lists the RODT Ids in the account and its balance"
    echo "  "$0" <accountID> keys : Displays the accountID and the Private Key of the account"
    echo "  "$0" <accountID> full : Displays the full RODT"
    echo "  "$0" genaccount       : Creates a new uninitialized accountID"
    echo "  "$0" <funding accountId> <unitialized accountId> : Initializes account with 0.001 NEAR from funding acount"
    echo "  "$0" <origin accountId>  <destination accountId> <rotid> : Sends ROTD from origin account to destination account"
    exit 0
fi

if [ "$1" == "genaccount" ]; then
    # Add code for generating a new uninitialized accountID
    echo "Generating a new uninitialized accountID..."
    wg genaccount
    exit 0
fi

if [ "$3" ]; then
    # Add code for sending ROTD from origin account to destination account
    echo "Sending ROTD $3 from $1 to $2..."
    output=$(near call "$NFTCONTRACTID" nft_transfer "{\"receiver_id\": "$2", \"token_id\": "$3"}" --accountId $1 --depositYocto 1)
    exit 0
fi

if [ -n "$2" ] && [ "$2" != "full" ] && [ "$2" != "keys" ]; then
    # Add code for generating a new uninitialized accountID
    echo "Initializing with 0.001 NEAR "$2""
    near send $1 $2 0.001
    exit 0
fi

if [ -z "$1" ]; then
    echo "There is a lag while collecting information from the blockchain"
    echo "The following is a list of accounts found in ~/.near-credentials :"
    formatted_output=$(ls -tr "$HOME/.near-credentials/$BLOCKCHAIN_ENV/" | awk -F '.' '{ print $1 }')
    echo "$formatted_output"
fi

if [ -n "$1" ]; then
    if [ "$2" == "keys" ]; then
        key_file="$HOME/.near-credentials/$BLOCKCHAIN_ENV/$1.json"
        echo "The contents of the key file (accountID and PrivateKey) are:"
        cat "$key_file" | jq -r '"\(.account_id)\n\(.private_key)"'
    else
        echo "There is a lag while collecting information from the blockchain"
        echo "The following is a list of token_ids belonging to the input account:"

        output=$(near view "$NFTCONTRACTID" nft_tokens_for_owner "{\"account_id\": \"$1\"}")
        filtered_output=$(echo "$output" | grep -o "token_id: '[^']*'" | sed "s/token_id: '//")
        echo "$filtered_output"

        if [ "$2" == "full" ]; then
            exit 0
        fi
    fi
fi

if [ -n "$1" ]; then
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
