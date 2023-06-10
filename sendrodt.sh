#!/bin/bash

export BLOCKCHAIN_ENV="testnet"
export NFTCONTRACTID=$(cat ~/cgforge/contract/neardev/dev-account)

if [ -n "$1" ] && [ -n "$2" ] && [ -n "$3" ]; then
    SOURCEACCOUNTID="$1"
    RECEIVERACCOUNTID="$2"
    TOKENID="$3"  # Replace with the actual token ID

    echo "Sending tokens from $SOURCEACCOUNTID to $RECEIVERACCOUNTID"

    output=$(near call "$NFTCONTRACTID" nft_transfer "{\"receiver_id\": \"$RECEIVERACCOUNTID\", \"token_id\": \"$TOKENID\"}" --accountId "$SOURCEACCOUNTID" --depositYocto 1)
    echo "$output"
else
    echo "Usage: $0 SOURCEACCOUNTID RECEIVERACCOUNTID TOKENID"
fi
