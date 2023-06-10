#!/bin/bash

export BLOCKCHAIN_ENV="testnet"
export NFTCONTRACTID=$(cat ~/cgtun/dev-account)

if [ -z "$1" ]; then
    echo "There is a lag while collecting information from the blockchain"
    echo "The following is a list of accounts found in ~/.near-credentials"
    formatted_output=$(ls "$HOME/.near-credentials/$BLOCKCHAIN_ENV/" | awk -F '.' '{ print $1 }')
    echo "$formatted_output"
fi

if [ -n "$1" ]; then
    if [ "$2" == "keys" ]; then
        key_file="$HOME/.near-credentials/$BLOCKCHAIN_ENV/$1.json"
        echo "The contents of the key file (accountID and PrivateKey) are:"
        cat "$key_file" | jq -r '"\(.account_id)\n\(.private_key)"'
    else
        echo "The following is a list of token_ids belonging to the input account"

        if [ "$2" == "full" ]; then
            output=$(near view "$NFTCONTRACTID" nft_tokens_for_owner "{\"account_id\": \"$1\"}")
            filtered_output=$(echo "$output" | grep -o "token_id: '[^']*'" | sed "s/token_id: '//")
            echo "$filtered_output"
        else
            output=$(near view "$NFTCONTRACTID" nft_tokens_for_owner "{\"account_id\": \"$1\"}")
            filtered_output=$(echo "$output" | grep -o "token_id: '[^']*'" | sed "s/token_id: '//")
            echo "$filtered_output"
        fi
    fi
else
    echo "Use one of the accounts listed as an argument to list the available RODT for that account. Sometimes you have to append .testnet but I don't know why"
    echo "If you want the full rodt, not just the token_id, add 'full' after the accountID"
fi

if [ -n "$1" ]; then
    echo "The balance of the account is"

    near_state=$(near state "$1")
    balance=$(echo "$near_state" | awk -F ': ' '/formattedAmount/ {print $2}')
    if [ -z "$balance" ]; then
        echo "The account does not exist in the blockchain as it has no balance. You need to initialize it with at least 0.01 NEAR."
    else
        echo "Account $1"
        echo "Balance: '$balance'"
    fi
fi
