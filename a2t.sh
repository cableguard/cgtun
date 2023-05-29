#!/bin/bash

# Check if a filename is provided as an argument
if [[ $# -eq 0 ]]; then
  echo "Error: Please provide a filename as an argument."
  exit 1
fi

filename=$1

# Read the content of the file as an ASCII array
ascii_array=$(<"$filename")

# Convert ASCII array to text
text=$(echo "$ascii_array" | awk '{ printf "%c", $0 }')

# Print the resulting text
echo "$text"

