export BLOCKCHAIN_ENV="testnet"
export NFTCONTRACTID=$(cat ~/cableguardforge/contract/neardev/dev-account)

echo "There is a lag while collecting information from the blockchain"
echo "The following is a list of accounts found in ~/.near-credentials"
formatted_output=$(ls ~/.near-credentials/"$BLOCKCHAIN_ENV"/ | awk -F '.' '{ print $1 }')
echo "$formatted_output"

if [ -n "$1" ]; then
    echo "The following is a list of token_ids belonging to the input account"

if [ "$2" == "full" ]; then     output=$(near view "$NFTCONTRACTID" nft_tokens_for_owner "{\\"account_id\\": \\"$1\\"}")     echo "$output" else     output=$(near view "$NFTCONTRACTID" nft_tokens_for_owner "{\\"account_id\\": \\"$1\\"}")     token_id=$(echo "$output" | grep -o "token_id: '[^']*'" | sed "s/token_id: '//")     echo "$token_id" fi

else
    echo "Use one of the accounts listed as an argument to list the available RODT for that account. Sometimes you have to append .testnet but I don't know why"
    echo "If you want the full ROTD, not just the token_id add  'full' after the accountID"
