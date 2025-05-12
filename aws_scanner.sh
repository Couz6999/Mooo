#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

# Check if input file is provided
if [ $# -ne 1 ]; then
    printf "${RED}Usage: $0 <url_list.txt>${RESET}\n"
    exit 1
fi

URL_FILE="$1"

# Check if file exists
if [ ! -f "$URL_FILE" ]; then
    printf "${RED}Error: File $URL_FILE not found${RESET}\n"
    exit 1
fi

# Create output directory
OUTPUT_DIR="aws_credentials_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

printf "${BLUE}[*] Starting AWS credential scan...${RESET}\n"
printf "${BLUE}[*] Reading URLs from: ${BOLD}$URL_FILE${RESET}\n"
printf "${BLUE}[*] Results will be saved to: ${BOLD}$OUTPUT_DIR${RESET}\n\n"

# Process each URL
while IFS= read -r url || [ -n "$url" ]; do
    # Skip empty lines and comments
    [ -z "$url" ] && continue
    [[ "$url" =~ ^#.*$ ]] && continue
    
    printf "${BLUE}[*] Scanning: $url${RESET}\n"
    
    # Make the request
    response=$(curl -s -L -A "Mozilla/5.0" "$url")
    
    # Look for AWS Access Key IDs
    while read -r line; do
        if [[ "$line" =~ AKIA[A-Z0-9]{16} ]]; then
            access_key=${BASH_REMATCH[0]}
            printf "${GREEN}[+] Found AWS Access Key: $access_key${RESET}\n"
            
            # Get context (10 lines before and after)
            context=$(echo "$response" | grep -A 10 -B 10 "$access_key")
            
            # Look for AWS Secret Keys near the access key
            if [[ "$context" =~ [A-Za-z0-9+/]{40}[A-Za-z0-9] ]]; then
                secret_key=${BASH_REMATCH[0]}
                printf "${GREEN}[+] Found AWS Secret Key${RESET}\n"
                
                # Look for AWS Region
                if [[ "$context" =~ (us|eu|ap|sa|ca|cn|af|me)-[a-z]+-[0-9]+ ]]; then
                    region=${BASH_REMATCH[0]}
                    printf "${GREEN}[+] Found AWS Region: $region${RESET}\n"
                    
                    # Save credentials
                    echo "$access_key / $secret_key / $region" >> "$OUTPUT_DIR/credentials.txt"
                else
                    # Save credentials without region
                    echo "$access_key / $secret_key / unknown" >> "$OUTPUT_DIR/credentials.txt"
                fi
                
                # Save context for analysis
                {
                    echo "=== AWS Credentials Found ==="
                    echo "URL: $url"
                    echo "Access Key: $access_key"
                    echo "Secret Key: $secret_key"
                    echo -e "\nContext:"
                    echo "$context"
                    echo -e "\n===================\n"
                } >> "$OUTPUT_DIR/context_${access_key}.txt"
            else
                # Save just the access key if no secret key is found
                echo "$access_key / unknown / unknown" >> "$OUTPUT_DIR/credentials.txt"
            fi
        fi
    done <<< "$response"
    
    # Add a small delay between requests
    sleep 1
done < "$URL_FILE"

# Check if we found any credentials
if [ -f "$OUTPUT_DIR/credentials.txt" ]; then
    cred_count=$(wc -l < "$OUTPUT_DIR/credentials.txt")
    printf "\n${GREEN}[+] Scan complete! Found $cred_count AWS credential sets${RESET}\n"
    printf "${GREEN}[+] Results saved to: $OUTPUT_DIR/credentials.txt${RESET}\n"
else
    printf "\n${YELLOW}[!] Scan complete! No AWS credentials found${RESET}\n"
fi