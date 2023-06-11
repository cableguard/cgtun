#!/bin/bash

export BLOCKCHAIN_ENV="testnet"
VERSION="1.2.0"
echo Version $VERSION "running on " $BLOCKCHAIN_ENV " Get help with: "$0" help"
export NFTCONTRACTID=$(cat ./dev-account 2>/dev/null) || { echo "Error: dev-account file with the Smart Contract account ID not found."; exit 1; }

if [ "$1" == "help" ]; then
    echo "Usage: "$0" [account_id] [Options]"
    echo ""
    echo "Options:"
    echo "  "$0" List of available accounts"
    echo "  "$0" <accountID>           : Lists the RODT Ids in the account and its balance"
    echo "  "$0" <accountID> keys      : Displays the accountID and the Private Key of the account"
    echo "  "$0" <accountID> <RODT Id> : Displays the indicated RODT"
    echo "  "$0" <funding accountId> <unitialized accountId> init    : Initializes account with 0.001 NEAR from funding acount"
    echo "  "$0" <origin accountId>  <destination accountId> <rotid> : Sends ROTD from origin account to destination account"
    echo "  "$0" genaccount            : Creates a new uninitialized accountID"
    exit 0
fi

if [ "$1" == "genaccount" ]; then
    # Add code for generating a new uninitialized accountID
    echo "Generating a new uninitialized accountID..."
    wg genaccount
    exit 0
fi

if [ -n "$3" ] && [ "$3" != "init" ]; then
    echo "Sending ROTD $3 from $1 to $2..."
    near call $NFTCONTRACTID nft_transfer "{\"receiver_id\": \"$2\", \"token_id\": \"$3\"}" --accountId $1 --depositYocto 1
    exit 0
fi

if [ "$3" = "init" ] && [ -n "$3" ]; then
    echo "Initializing with 0.001 NEAR "$2""
    near send $1 $2 0.001
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
        echo "The contents of the key file (accountID in Hex and PrivateKey in Base58) are:"
	cat "$key_file" | jq -r '"\(.account_id)\n\(.private_key)"' | sed '2s/ed25519://'
	exit 0
    else
	echo "RODT Contents"
        near view $NFTCONTRACTID nft_token "{\"token_id\": \"$2\"}"
	exit 0
    fi
fi

if [ -n "$1" ]; then
    echo "There is a lag while collecting information from the blockchain"
    echo "The following is a list of token_ids belonging to the input account:"
    output=$(near view "$NFTCONTRACTID" nft_tokens_for_owner "{\"account_id\": \"$1\"}")
    filtered_output=$(echo "$output" | grep -o "token_id: '[^']*'" | sed "s/token_id: //")
    echo "$filtered_output"
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
