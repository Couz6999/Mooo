#!/bin/bash

# Colors for output
RED="\e[31m"
GREEN="\e[32m"
BLUE="\e[34m"
YELLOW="\e[33m"
BOLD="\e[1m"
RESET="\e[0m"

# Check if input file is provided
if [ $# -ne 1 ]; then
    echo -e "${RED}Usage: $0 <url_list.txt>${RESET}"
    exit 1
fi

URL_FILE="$1"

# Check if file exists
if [ ! -f "$URL_FILE" ]; then
    echo -e "${RED}Error: File $URL_FILE not found${RESET}"
    exit 1
fi

# Create output directory
OUTPUT_DIR="aws_credentials_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}[*] Starting AWS credential scan...${RESET}"
echo -e "${BLUE}[*] Reading URLs from: ${BOLD}$URL_FILE${RESET}"
echo -e "${BLUE}[*] Results will be saved to: ${BOLD}$OUTPUT_DIR${RESET}\n"

# Process each URL
while IFS= read -r url || [ -n "$url" ]; do
    # Skip empty lines and comments
    [[ -z "$url" || "$url" =~ ^#.*$ ]] && continue
    
    echo -e "${BLUE}[*] Scanning: $url${RESET}"
    
    # Make the request
    response=$(curl -s -L -A "Mozilla/5.0" "$url")
    
    # Look for AWS Access Key IDs
    if [[ "$response" =~ (AKIA[0-9A-Z]{16}) ]]; then
        access_key="${BASH_REMATCH[1]}"
        echo -e "${GREEN}[+] Found AWS Access Key: $access_key${RESET}"
        
        # Extract surrounding context (10 lines before and after)
        context=$(echo "$response" | grep -A 10 -B 10 "$access_key")
        
        # Look for AWS Secret Keys
        if [[ "$context" =~ ([0-9a-zA-Z+/]{40}) ]]; then
            secret_key="${BASH_REMATCH[1]}"
            echo -e "${GREEN}[+] Found AWS Secret Key${RESET}"
            
            # Look for AWS Region
            if [[ "$context" =~ (us|eu|ap|sa|ca|cn|af|me)-[a-z]+-[0-9]+ ]]; then
                region="${BASH_REMATCH[0]}"
                echo -e "${GREEN}[+] Found AWS Region: $region${RESET}"
                
                # Save credentials
                echo "$access_key / $secret_key / $region" >> "$OUTPUT_DIR/credentials.txt"
            else
                # Save credentials without region
                echo "$access_key / $secret_key / unknown" >> "$OUTPUT_DIR/credentials.txt"
            fi
            
            # Save context for analysis
            echo -e "\n=== AWS Credentials Found ===" >> "$OUTPUT_DIR/context_${access_key}.txt"
            echo "URL: $url" >> "$OUTPUT_DIR/context_${access_key}.txt"
            echo "Access Key: $access_key" >> "$OUTPUT_DIR/context_${access_key}.txt"
            echo "Secret Key: $secret_key" >> "$OUTPUT_DIR/context_${access_key}.txt"
            echo -e "\nContext:" >> "$OUTPUT_DIR/context_${access_key}.txt"
            echo "$context" >> "$OUTPUT_DIR/context_${access_key}.txt"
            echo -e "\n===================\n" >> "$OUTPUT_DIR/context_${access_key}.txt"
        else
            # Save just the access key if no secret key is found
            echo "$access_key / unknown / unknown" >> "$OUTPUT_DIR/credentials.txt"
        fi
    fi
    
    # Add a small delay between requests
    sleep 1
done < "$URL_FILE"

# Check if we found any credentials
if [ -f "$OUTPUT_DIR/credentials.txt" ]; then
    cred_count=$(wc -l < "$OUTPUT_DIR/credentials.txt")
    echo -e "\n${GREEN}[+] Scan complete! Found $cred_count AWS credential sets${RESET}"
    echo -e "${GREEN}[+] Results saved to: $OUTPUT_DIR/credentials.txt${RESET}"
else
    echo -e "\n${YELLOW}[!] Scan complete! No AWS credentials found${RESET}"
fi