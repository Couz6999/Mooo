#!/bin/bash
# AWS Credential Detector Module

# Analyze and validate detected AWS credentials
detect_aws_credentials() {
  local aws_creds_dir=$1
  local verbose=$2
  
  # Check if AWS credentials were found during the scan
  if [[ ! -f "$aws_creds_dir/aws_keys.txt" ]]; then
    echo -e "${GREEN}[+] No AWS credentials were found.${RESET}"
    return 0
  fi
  
  local count=$(wc -l < "$aws_creds_dir/aws_keys.txt")
  echo -e "${RED}[!] Found $count potential AWS credential sets.${RESET}"
  
  echo -e "\n## AWS Credentials Found" >> "$OUTPUT_FILE"
  echo -e "Detected $count potential AWS credential sets:" >> "$OUTPUT_FILE"
  
  local counter=1
  while read -r line; do
    local access_key=$(echo "$line" | cut -d '/' -f1 | tr -d ' ')
    local secret_key=$(echo "$line" | cut -d '/' -f2 | tr -d ' ')
    local region=$(echo "$line" | cut -d '/' -f3 | tr -d ' ')
    
    echo -e "${RED}[!] AWS Credential Set #$counter:${RESET}"
    echo -e "${RED}[!] - Access Key ID: $access_key${RESET}"
    
    if [[ "$secret_key" != "unknown" ]]; then
      # Mask most of the secret key for display purposes
      local masked_secret="${secret_key:0:4}...${secret_key: -4}"
      echo -e "${RED}[!] - Secret Access Key: $masked_secret (masked for security)${RESET}"
    else
      echo -e "${RED}[!] - Secret Access Key: Not found${RESET}"
    fi
    
    if [[ "$region" != "unknown" ]]; then
      echo -e "${RED}[!] - Region: $region${RESET}"
    else
      echo -e "${RED}[!] - Region: Not found${RESET}"
    fi
    
    # Add to the report
    echo -e "### AWS Credential Set #$counter:" >> "$OUTPUT_FILE"
    echo -e "- Access Key ID: $access_key" >> "$OUTPUT_FILE"
    
    if [[ "$secret_key" != "unknown" ]]; then
      # Mask most of the secret key for security in the report
      local masked_secret="${secret_key:0:4}...${secret_key: -4}"
      echo -e "- Secret Access Key: $masked_secret (masked for security)" >> "$OUTPUT_FILE"
    else
      echo -e "- Secret Access Key: Not found" >> "$OUTPUT_FILE"
    fi
    
    if [[ "$region" != "unknown" ]]; then
      echo -e "- Region: $region" >> "$OUTPUT_FILE"
    else
      echo -e "- Region: Not found" >> "$OUTPUT_FILE"
    fi
    
    echo -e "" >> "$OUTPUT_FILE"
    
    counter=$((counter + 1))
  done < "$aws_creds_dir/aws_keys.txt"
  
  echo -e "\nSecurity Recommendation: These AWS credentials should be revoked immediately!" >> "$OUTPUT_FILE"
  echo -e "---\n" >> "$OUTPUT_FILE"
  
  echo -e "${RED}[!] RECOMMENDATION: These AWS credentials should be revoked immediately!${RESET}"
}

# Validate an AWS Access Key format
validate_aws_access_key() {
  local key=$1
  if [[ "$key" =~ ^AKIA[0-9A-Z]{16}$ ]]; then
    return 0  # Valid format
  else
    return 1  # Invalid format
  fi
}

# Validate an AWS Secret Key format
validate_aws_secret_key() {
  local key=$1
  if [[ ${#key} -eq 40 && "$key" =~ ^[0-9a-zA-Z+/]+$ ]]; then
    return 0  # Potential valid format
  else
    return 1  # Invalid format
  fi
}

# Validate an AWS Region format
validate_aws_region() {
  local region=$1
  if [[ "$region" =~ ^(us|eu|ap|sa|ca|cn|af|me)-[a-z]+-[0-9]+$ ]]; then
    return 0  # Valid format
  else
    return 1  # Invalid format
  fi
}