#!/bin/bash
# Scanner module - Main scanning functionality

# Perform the website scan
perform_scan() {
  local target_url=$1
  local depth=$2
  local rate_limit=$3
  local user_agent=$4
  local cookies=$5
  local headers=("${@:6:$#-7}")
  local stealth_mode=${@: -2:1}
  local verbose=${@: -1:1}
  
  # Extract the domain from the URL
  local domain=$(extract_domain "$target_url")
  
  # Create a temporary directory for the crawled pages
  local temp_dir=$(mktemp -d /tmp/websec-scan.XXXXXX)
  
  # Add the initial URL to the queue
  echo "$target_url" > "$temp_dir/queue.txt"
  touch "$temp_dir/visited.txt"
  
  echo -e "${BLUE}[*] Starting security scan of $domain${RESET}"
  
  # Check basic DNS information
  check_dns_info "$domain"
  
  # Check SSL/TLS Configuration
  check_ssl_configuration "$target_url"
  
  # Check HTTP headers
  check_http_headers "$target_url" "$user_agent" "$cookies" "${headers[@]}"
  
  # Start crawling
  echo -e "${BLUE}[*] Crawling website to depth $depth...${RESET}"
  crawl_website "$target_url" "$depth" "$rate_limit" "$user_agent" "$cookies" "${headers[@]}" "$stealth_mode" "$verbose" "$temp_dir"
  
  # Check for common vulnerabilities
  echo -e "${BLUE}[*] Checking for common vulnerabilities...${RESET}"
  check_common_vulnerabilities "$temp_dir/visited.txt" "$user_agent" "$cookies" "${headers[@]}" "$stealth_mode" "$verbose"
  
  # Cleanup
  if [[ "$verbose" != "true" ]]; then
    rm -rf "$temp_dir"
  else
    echo -e "${BLUE}[*] Temporary files stored in: $temp_dir${RESET}"
  fi
}

# Check DNS information
check_dns_info() {
  local domain=$1
  
  echo -e "${BLUE}[*] Checking DNS information for $domain...${RESET}"
  
  echo -e "\n## DNS Information" >> "$OUTPUT_FILE"
  
  # A records
  echo -e "${GREEN}[+] Retrieving A records...${RESET}"
  local a_records=$(dig +short A "$domain" 2>/dev/null)
  echo -e "### A Records:" >> "$OUTPUT_FILE"
  if [[ -n "$a_records" ]]; then
    echo -e "$a_records" >> "$OUTPUT_FILE"
  else
    echo -e "No A records found." >> "$OUTPUT_FILE"
  fi
  
  # MX records
  echo -e "${GREEN}[+] Retrieving MX records...${RESET}"
  local mx_records=$(dig +short MX "$domain" 2>/dev/null)
  echo -e "### MX Records:" >> "$OUTPUT_FILE"
  if [[ -n "$mx_records" ]]; then
    echo -e "$mx_records" >> "$OUTPUT_FILE"
  else
    echo -e "No MX records found." >> "$OUTPUT_FILE"
  fi
  
  # NS records
  echo -e "${GREEN}[+] Retrieving NS records...${RESET}"
  local ns_records=$(dig +short NS "$domain" 2>/dev/null)
  echo -e "### NS Records:" >> "$OUTPUT_FILE"
  if [[ -n "$ns_records" ]]; then
    echo -e "$ns_records" >> "$OUTPUT_FILE"
  else
    echo -e "No NS records found." >> "$OUTPUT_FILE"
  fi
  
  # TXT records (may contain sensitive information)
  echo -e "${GREEN}[+] Retrieving TXT records...${RESET}"
  local txt_records=$(dig +short TXT "$domain" 2>/dev/null)
  echo -e "### TXT Records:" >> "$OUTPUT_FILE"
  if [[ -n "$txt_records" ]]; then
    echo -e "$txt_records" >> "$OUTPUT_FILE"
    
    # Check for SPF records
    if echo "$txt_records" | grep -q "v=spf1"; then
      echo -e "${GREEN}[+] SPF record found.${RESET}"
    else
      echo -e "${YELLOW}[!] No SPF record found. Email spoofing may be possible.${RESET}"
      report_vulnerability "No SPF Record" "The domain does not have an SPF record configured, which could allow email spoofing." "MEDIUM"
    fi
    
    # Check for DMARC records
    local dmarc_record=$(dig +short TXT "_dmarc.$domain" 2>/dev/null)
    if [[ -n "$dmarc_record" ]]; then
      echo -e "${GREEN}[+] DMARC record found.${RESET}"
    else
      echo -e "${YELLOW}[!] No DMARC record found. Email authentication is incomplete.${RESET}"
      report_vulnerability "No DMARC Record" "The domain does not have a DMARC record configured, which weakens email authentication." "MEDIUM"
    fi
  else
    echo -e "No TXT records found." >> "$OUTPUT_FILE"
  fi
  
  echo -e "\n---\n" >> "$OUTPUT_FILE"
}

# Check SSL/TLS configuration
check_ssl_configuration() {
  local url=$1
  
  # Only check HTTPS URLs
  if [[ ! "$url" =~ ^https:// ]]; then
    echo -e "${YELLOW}[!] Warning: Target is using HTTP, not HTTPS. Skipping SSL/TLS checks.${RESET}"
    report_vulnerability "No HTTPS" "The website is not using HTTPS, which means all traffic is unencrypted." "HIGH"
    return
  fi
  
  local domain=$(echo "$url" | sed -E 's|^https?://||' | sed -E 's|/.*$||')
  
  echo -e "${BLUE}[*] Checking SSL/TLS configuration for $domain...${RESET}"
  
  echo -e "\n## SSL/TLS Configuration" >> "$OUTPUT_FILE"
  
  # Check SSL certificate
  local cert_info=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)
  
  if [[ -z "$cert_info" ]]; then
    echo -e "${YELLOW}[!] Warning: Unable to retrieve SSL certificate information.${RESET}"
    report_vulnerability "SSL Certificate Retrieval Failed" "Unable to retrieve SSL certificate information, which may indicate misconfigurations." "MEDIUM"
    return
  fi
  
  # Extract certificate details
  local issuer=$(echo "$cert_info" | grep "Issuer:" | sed 's/^.*Issuer: //')
  local subject=$(echo "$cert_info" | grep "Subject:" | sed 's/^.*Subject: //')
  local valid_from=$(echo "$cert_info" | grep "Not Before:" | sed 's/^.*Not Before: //')
  local valid_until=$(echo "$cert_info" | grep "Not After :" | sed 's/^.*Not After : //')
  local san=$(echo "$cert_info" | grep -A1 "Subject Alternative Name" | grep "DNS:" | sed 's/^[[:space:]]*//')
  
  # Check for certificate expiration
  local now=$(date +%s)
  local expiry=$(date -d "$valid_until" +%s 2>/dev/null)
  
  if [[ $? -ne 0 ]]; then
    # Try alternative date format for macOS
    expiry=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$valid_until" +%s 2>/dev/null)
  fi
  
  local days_left=$(( (expiry - now) / 86400 ))
  
  echo -e "### SSL Certificate Information:" >> "$OUTPUT_FILE"
  echo -e "- Issuer: $issuer" >> "$OUTPUT_FILE"
  echo -e "- Subject: $subject" >> "$OUTPUT_FILE"
  echo -e "- Valid From: $valid_from" >> "$OUTPUT_FILE"
  echo -e "- Valid Until: $valid_until" >> "$OUTPUT_FILE"
  echo -e "- Days Until Expiration: $days_left" >> "$OUTPUT_FILE"
  echo -e "- Subject Alternative Names: $san" >> "$OUTPUT_FILE"
  
  if [[ $days_left -lt 0 ]]; then
    echo -e "${RED}[!] Critical: SSL certificate has expired!${RESET}"
    report_vulnerability "Expired SSL Certificate" "The SSL certificate has expired, which will cause browser warnings and security issues." "CRITICAL"
  elif [[ $days_left -lt 30 ]]; then
    echo -e "${YELLOW}[!] Warning: SSL certificate will expire in $days_left days.${RESET}"
    report_vulnerability "Expiring SSL Certificate" "The SSL certificate will expire in $days_left days." "MEDIUM"
  else
    echo -e "${GREEN}[+] SSL certificate is valid for $days_left more days.${RESET}"
  fi
  
  # Check for supported SSL/TLS protocols
  echo -e "${BLUE}[*] Checking supported SSL/TLS protocols...${RESET}"
  
  local protocols=("ssl2" "ssl3" "tls1" "tls1_1" "tls1_2" "tls1_3")
  local results=()
  
  echo -e "### Supported SSL/TLS Protocols:" >> "$OUTPUT_FILE"
  
  for protocol in "${protocols[@]}"; do
    local display_name=""
    case "$protocol" in
      "ssl2") display_name="SSLv2" ;;
      "ssl3") display_name="SSLv3" ;;
      "tls1") display_name="TLSv1.0" ;;
      "tls1_1") display_name="TLSv1.1" ;;
      "tls1_2") display_name="TLSv1.2" ;;
      "tls1_3") display_name="TLSv1.3" ;;
    esac
    
    if echo | openssl s_client -"$protocol" -connect "$domain:443" 2>/dev/null | grep -q "CONNECTED"; then
      results+=("$display_name: Supported")
      echo -e "- $display_name: Supported" >> "$OUTPUT_FILE"
      
      # Report vulnerable protocols
      if [[ "$protocol" == "ssl2" || "$protocol" == "ssl3" || "$protocol" == "tls1" || "$protocol" == "tls1_1" ]]; then
        echo -e "${RED}[!] Warning: Insecure protocol $display_name is supported!${RESET}"
        report_vulnerability "Insecure Protocol: $display_name" "The server supports the insecure protocol $display_name, which should be disabled." "HIGH"
      fi
    else
      results+=("$display_name: Not Supported")
      echo -e "- $display_name: Not Supported" >> "$OUTPUT_FILE"
    fi
  done
  
  # Output results
  for result in "${results[@]}"; do
    echo -e "${GREEN}[+] $result${RESET}"
  done
  
  echo -e "\n---\n" >> "$OUTPUT_FILE"
}

# Check HTTP headers
check_http_headers() {
  local url=$1
  local user_agent=$2
  local cookies=$3
  shift 3
  local headers=("$@")
  
  echo -e "${BLUE}[*] Checking HTTP headers for $url...${RESET}"
  
  echo -e "\n## HTTP Security Headers" >> "$OUTPUT_FILE"
  
  # Get headers
  local header_output
  if [[ -n "$cookies" ]]; then
    header_output=$(curl -sI -A "$user_agent" -b "$cookies" "${headers[@]}" "$url")
  else
    header_output=$(curl -sI -A "$user_agent" "${headers[@]}" "$url")
  fi
  
  # Check for security headers
  local security_headers=(
    "Strict-Transport-Security"
    "Content-Security-Policy"
    "X-Content-Type-Options"
    "X-Frame-Options"
    "X-XSS-Protection"
    "Referrer-Policy"
    "Feature-Policy"
    "Permissions-Policy"
  )
  
  echo -e "### Security Headers:" >> "$OUTPUT_FILE"
  
  local missing_headers=()
  for header in "${security_headers[@]}"; do
    if echo "$header_output" | grep -q "$header:"; then
      local value=$(echo "$header_output" | grep -i "$header:" | head -1 | sed "s/$header://i" | tr -d '\r')
      echo -e "${GREEN}[+] $header: $value${RESET}"
      echo -e "- $header: $value" >> "$OUTPUT_FILE"
    else
      echo -e "${YELLOW}[!] $header: Missing${RESET}"
      echo -e "- $header: Missing" >> "$OUTPUT_FILE"
      missing_headers+=("$header")
    fi
  done
  
  # Report missing security headers
  if [[ ${#missing_headers[@]} -gt 0 ]]; then
    local missing=$(IFS=", "; echo "${missing_headers[*]}")
    report_vulnerability "Missing Security Headers" "The following security headers are missing: $missing" "MEDIUM"
  fi
  
  # Check for server information disclosure
  local server=$(echo "$header_output" | grep -i "Server:" | head -1 | sed "s/Server://i" | tr -d '\r')
  if [[ -n "$server" ]]; then
    echo -e "${YELLOW}[!] Server header reveals information: $server${RESET}"
    echo -e "- Server: $server" >> "$OUTPUT_FILE"
    report_vulnerability "Server Information Disclosure" "The server header reveals information about the server software: $server" "LOW"
  else
    echo -e "${GREEN}[+] Server header: Not disclosed${RESET}"
    echo -e "- Server: Not disclosed" >> "$OUTPUT_FILE"
  fi
  
  echo -e "\n---\n" >> "$OUTPUT_FILE"
}

# Crawl the website recursively
crawl_website() {
  local base_url=$1
  local max_depth=$2
  local rate_limit=$3
  local user_agent=$4
  local cookies=$5
  local headers=("${@:6:$#-8}")
  local stealth_mode=${@: -3:1}
  local verbose=${@: -2:1}
  local temp_dir=${@: -1:1}
  
  echo -e "${BLUE}[*] Crawling website with max depth: $max_depth${RESET}"
  
  local current_depth=0
  local queue_file="$temp_dir/queue.txt"
  local visited_file="$temp_dir/visited.txt"
  local new_queue_file="$temp_dir/new_queue.txt"
  
  while [[ $current_depth -lt $max_depth ]]; do
    echo -e "${BLUE}[*] Crawling depth: $current_depth${RESET}"
    
    # Reset the new queue file
    > "$new_queue_file"
    
    # Process each URL in the current queue
    while read -r url; do
      # Skip if already visited
      if grep -q "^$url$" "$visited_file"; then
        continue
      fi
      
      # Mark as visited
      echo "$url" >> "$visited_file"
      
      if [[ "$verbose" == "true" ]]; then
        echo -e "${BLUE}[*] Crawling: $url${RESET}"
      else
        # Show progress indicator
        echo -ne "${BLUE}[*] URLs crawled: $(wc -l < "$visited_file")\r${RESET}"
      fi
      
      # Apply rate limiting
      if [[ "$stealth_mode" == "true" ]]; then
        random_delay
      else
        rate_limit "$rate_limit"
      fi
      
      # Fetch the page
      local response
      if [[ -n "$cookies" ]]; then
        response=$(curl -s -L -A "$user_agent" -b "$cookies" "${headers[@]}" "$url")
      else
        response=$(curl -s -L -A "$user_agent" "${headers[@]}" "$url")
      fi
      
      # Extract links if HTML content is returned
      if [[ $? -eq 0 && "$response" == *"<html"* ]]; then
        # Extract links and add to new queue
        extract_links "$response" "$base_url" | while read -r new_url; do
          # Only process URLs from the same domain
          if [[ "$new_url" == "$base_url"* || "$new_url" == "/"* ]]; then
            echo "$new_url" >> "$new_queue_file"
          fi
        done
      fi
      
      # Process response for AWS credentials
      process_response_for_aws_creds "$url" "$response"
      
    done < "$queue_file"
    
    # Update the queue for the next depth level
    sort -u "$new_queue_file" > "$queue_file"
    
    # Check if there are any URLs left to crawl
    if [[ ! -s "$queue_file" ]]; then
      echo -e "${GREEN}[+] Crawling complete. No more URLs to process.${RESET}"
      break
    fi
    
    current_depth=$((current_depth + 1))
  done
  
  echo -e "${GREEN}[+] Crawling complete. Visited $(wc -l < "$visited_file") unique URLs.${RESET}"
}

# Process the response for AWS credentials
process_response_for_aws_creds() {
  local url=$1
  local response=$2
  
  # Check for AWS Access Key IDs
  if [[ "$response" =~ (AKIA[0-9A-Z]{16}) ]]; then
    local access_key="${BASH_REMATCH[1]}"
    echo -e "${RED}[!] Found AWS Access Key ID: $access_key in $url${RESET}"
    
    # Check for AWS Secret Access Keys (usually near the Access Key ID)
    local context=$(echo "$response" | grep -A10 -B10 "$access_key")
    
    # Look for patterns that might be AWS Secret Keys
    if [[ "$context" =~ ([0-9a-zA-Z+/]{40}) ]]; then
      local secret_key="${BASH_REMATCH[1]}"
      echo -e "${RED}[!] Found potential AWS Secret Access Key near Access Key ID${RESET}"
      
      # Look for potential region information
      if [[ "$context" =~ (us|eu|ap|sa|ca|cn|af|me)-[a-z]+-[0-9]+ ]]; then
        local region="${BASH_REMATCH[0]}"
        echo -e "${RED}[!] Found potential AWS Region: $region${RESET}"
        
        # Save the credentials to the output file
        echo "$access_key / $secret_key / $region" >> "$AWS_CREDS_DIR/aws_keys.txt"
        
        # Save the context for further analysis
        echo -e "\n--- AWS Credentials Found ---" >> "$AWS_CREDS_DIR/context_${access_key}.txt"
        echo -e "URL: $url" >> "$AWS_CREDS_DIR/context_${access_key}.txt"
        echo -e "Access Key ID: $access_key" >> "$AWS_CREDS_DIR/context_${access_key}.txt"
        echo -e "Secret Access Key: $secret_key" >> "$AWS_CREDS_DIR/context_${access_key}.txt"
        echo -e "Region: $region" >> "$AWS_CREDS_DIR/context_${access_key}.txt"
        echo -e "Context:" >> "$AWS_CREDS_DIR/context_${access_key}.txt"
        echo "$context" >> "$AWS_CREDS_DIR/context_${access_key}.txt"
      else
        # Save without region
        echo "$access_key / $secret_key / unknown" >> "$AWS_CREDS_DIR/aws_keys.txt"
        
        # Save the context for further analysis
        echo -e "\n--- AWS Credentials Found ---" >> "$AWS_CREDS_DIR/context_${access_key}.txt"
        echo -e "URL: $url" >> "$AWS_CREDS_DIR/context_${access_key}.txt"
        echo -e "Access Key ID: $access_key" >> "$AWS_CREDS_DIR/context_${access_key}.txt"
        echo -e "Secret Access Key: $secret_key" >> "$AWS_CREDS_DIR/context_${access_key}.txt"
        echo -e "Context:" >> "$AWS_CREDS_DIR/context_${access_key}.txt"
        echo "$context" >> "$AWS_CREDS_DIR/context_${access_key}.txt"
      fi
      
      report_vulnerability "AWS Credentials Exposed" "AWS credentials found in page: Access Key ID: $access_key" "CRITICAL"
    else
      # Just save the Access Key
      echo "$access_key / unknown / unknown" >> "$AWS_CREDS_DIR/aws_keys.txt"
      report_vulnerability "AWS Access Key Exposed" "AWS Access Key ID found in page: $access_key" "HIGH"
    fi
  fi
}

# Check for common vulnerabilities
check_common_vulnerabilities() {
  local visited_file=$1
  local user_agent=$2
  local cookies=$3
  local headers=("${@:4:$#-6}")
  local stealth_mode=${@: -2:1}
  local verbose=${@: -1:1}
  
  echo -e "${BLUE}[*] Checking for common web vulnerabilities...${RESET}"
  
  echo -e "\n## Vulnerability Scan Results" >> "$OUTPUT_FILE"
  
  # Read the list of visited URLs
  local url_count=$(wc -l < "$visited_file")
  local current=0
  
  while read -r url; do
    current=$((current + 1))
    
    if [[ "$verbose" == "true" ]]; then
      echo -e "${BLUE}[*] Checking URL ($current/$url_count): $url${RESET}"
    else
      # Show progress indicator
      echo -ne "${BLUE}[*] Checking vulnerabilities: $current/$url_count\r${RESET}"
    fi
    
    # Apply rate limiting
    if [[ "$stealth_mode" == "true" ]]; then
      random_delay
    else
      rate_limit 5
    fi
    
    # Check for common vulnerabilities:
    
    # 1. XSS vulnerabilities (reflected)
    check_xss_vulnerability "$url" "$user_agent" "$cookies" "${headers[@]}"
    
    # 2. SQL Injection vulnerabilities
    check_sqli_vulnerability "$url" "$user_agent" "$cookies" "${headers[@]}"
    
    # 3. Directory traversal
    check_directory_traversal "$url" "$user_agent" "$cookies" "${headers[@]}"
    
    # 4. Sensitive files exposure
    check_sensitive_files_exposure "$url" "$user_agent" "$cookies" "${headers[@]}"
    
  done < "$visited_file"
  
  echo -e "\n${GREEN}[+] Vulnerability scanning complete.${RESET}"
  
  echo -e "\n---\n" >> "$OUTPUT_FILE"
}

# Check for XSS vulnerability
check_xss_vulnerability() {
  local url=$1
  local user_agent=$2
  local cookies=$3
  shift 3
  local headers=("$@")
  
  # Only test URLs with parameters
  if [[ "$url" != *"?"* ]]; then
    return
  fi
  
  # Extract base URL and parameters
  local base_url=$(echo "$url" | cut -d '?' -f1)
  local params=$(echo "$url" | cut -d '?' -f2)
  
  # Convert params string to array
  IFS='&' read -ra param_array <<< "$params"
  
  # XSS payloads to test
  local payloads=(
    "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
    "%3Cimg%20src%3Dx%20onerror%3Dalert%28%27XSS%27%29%3E"
  )
  
  for param in "${param_array[@]}"; do
    local param_name=$(echo "$param" | cut -d '=' -f1)
    
    for payload in "${payloads[@]}"; do
      # Create a new set of parameters with the payload
      local new_params=""
      for p in "${param_array[@]}"; do
        local p_name=$(echo "$p" | cut -d '=' -f1)
        if [[ "$p_name" == "$param_name" ]]; then
          new_params+="$param_name=$payload&"
        else
          new_params+="$p&"
        fi
      done
      
      # Remove trailing &
      new_params=${new_params%&}
      
      # Create new URL with payload
      local test_url="$base_url?$new_params"
      
      # Make the request
      local response
      if [[ -n "$cookies" ]]; then
        response=$(curl -s -L -A "$user_agent" -b "$cookies" "${headers[@]}" "$test_url")
      else
        response=$(curl -s -L -A "$user_agent" "${headers[@]}" "$test_url")
      fi
      
      # Check if the payload is reflected in the response
      if [[ "$response" == *"alert('XSS')"* || "$response" == *"alert(\'XSS\')"* ]]; then
        echo -e "${RED}[!] Potential XSS vulnerability found in parameter '$param_name' at $base_url${RESET}"
        report_vulnerability "Potential XSS Vulnerability" "Parameter '$param_name' at $base_url may be vulnerable to XSS attacks." "HIGH"
        break
      fi
    done
  done
}

# Check for SQL Injection vulnerability
check_sqli_vulnerability() {
  local url=$1
  local user_agent=$2
  local cookies=$3
  shift 3
  local headers=("$@")
  
  # Only test URLs with parameters
  if [[ "$url" != *"?"* ]]; then
    return
  fi
  
  # Extract base URL and parameters
  local base_url=$(echo "$url" | cut -d '?' -f1)
  local params=$(echo "$url" | cut -d '?' -f2)
  
  # Convert params string to array
  IFS='&' read -ra param_array <<< "$params"
  
  # SQL Injection payloads to test
  local payloads=(
    "'"
    "\""
    "1'"
    "1\""
    "1 OR 1=1"
    "' OR '1'='1"
    "\" OR \"1\"=\"1"
  )
  
  for param in "${param_array[@]}"; do
    local param_name=$(echo "$param" | cut -d '=' -f1)
    
    for payload in "${payloads[@]}"; do
      # URL encode the payload
      local encoded_payload=$(url_encode "$payload")
      
      # Create a new set of parameters with the payload
      local new_params=""
      for p in "${param_array[@]}"; do
        local p_name=$(echo "$p" | cut -d '=' -f1)
        if [[ "$p_name" == "$param_name" ]]; then
          new_params+="$param_name=$encoded_payload&"
        else
          new_params+="$p&"
        fi
      done
      
      # Remove trailing &
      new_params=${new_params%&}
      
      # Create new URL with payload
      local test_url="$base_url?$new_params"
      
      # Make the request
      local response
      if [[ -n "$cookies" ]]; then
        response=$(curl -s -L -A "$user_agent" -b "$cookies" "${headers[@]}" "$test_url")
      else
        response=$(curl -s -L -A "$user_agent" "${headers[@]}" "$test_url")
      fi
      
      # Check for SQL error patterns
      if [[ "$response" == *"SQL syntax"* || "$response" == *"mysql_fetch"* || "$response" == *"ORA-"* || 
            "$response" == *"syntax error"* || "$response" == *"Microsoft SQL Server"* || 
            "$response" == *"PostgreSQL"* || "$response" == *"SQLite"* ]]; then
        echo -e "${RED}[!] Potential SQL Injection vulnerability found in parameter '$param_name' at $base_url${RESET}"
        report_vulnerability "Potential SQL Injection Vulnerability" "Parameter '$param_name' at $base_url may be vulnerable to SQL Injection attacks." "HIGH"
        break
      fi
    done
  done
}

# Check for directory traversal vulnerability
check_directory_traversal() {
  local url=$1
  local user_agent=$2
  local cookies=$3
  shift 3
  local headers=("$@")
  
  # Extract the base URL and path
  local base_url=$(echo "$url" | cut -d '?' -f1)
  
  # Directory traversal payloads
  local payloads=(
    "../../../../../etc/passwd"
    "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    "....//....//....//....//....//etc/passwd"
  )
  
  for payload in "${payloads[@]}"; do
    # Create test URL with payload
    local test_url="${base_url%/}/$payload"
    
    # Make the request
    local response
    if [[ -n "$cookies" ]]; then
      response=$(curl -s -L -A "$user_agent" -b "$cookies" "${headers[@]}" "$test_url")
    else
      response=$(curl -s -L -A "$user_agent" "${headers[@]}" "$test_url")
    fi
    
    # Check for signs of successful directory traversal
    if [[ "$response" == *"root:x:"* || "$response" == *"nobody:x:"* ]]; then
      echo -e "${RED}[!] Potential directory traversal vulnerability found at $base_url${RESET}"
      report_vulnerability "Potential Directory Traversal Vulnerability" "The URL $base_url may be vulnerable to directory traversal attacks." "HIGH"
      break
    fi
  done
}

# Check for sensitive files exposure
check_sensitive_files_exposure() {
  local url=$1
  local user_agent=$2
  local cookies=$3
  shift 3
  local headers=("$@")
  
  # Extract the domain from the URL
  local domain=$(extract_domain "$url")
  local base_url=$(echo "$url" | cut -d '?' -f1 | sed 's#/[^/]*$##')
  
  # Common sensitive files to check
  local sensitive_files=(
    "/.git/config"
    "/.env"
    "/config.php"
    "/wp-config.php"
    "/config/database.yml"
    "/credentials.json"
    "/config.json"
    "/db.sqlite"
    "/backup.sql"
    "/dump.sql"
    "/database.sql"
    "/.htpasswd"
    "/.svn/entries"
    "/robots.txt"
    "/phpinfo.php"
    "/server-status"
    "/wp-admin/admin-ajax.php"
  )
  
  for file in "${sensitive_files[@]}"; do
    # Create test URL
    local test_url="${base_url%/}$file"
    
    # Make the request
    local response
    local http_code
    if [[ -n "$cookies" ]]; then
      http_code=$(curl -s -o /dev/null -w "%{http_code}" -A "$user_agent" -b "$cookies" "${headers[@]}" "$test_url")
      if [[ "$http_code" == "200" ]]; then
        response=$(curl -s -L -A "$user_agent" -b "$cookies" "${headers[@]}" "$test_url")
      fi
    else
      http_code=$(curl -s -o /dev/null -w "%{http_code}" -A "$user_agent" "${headers[@]}" "$test_url")
      if [[ "$http_code" == "200" ]]; then
        response=$(curl -s -L -A "$user_agent" "${headers[@]}" "$test_url")
      fi
    fi
    
    # Check if file is accessible
    if [[ "$http_code" == "200" ]]; then
      # Check if it's not a standard 404 page (some servers return 200 for custom 404 pages)
      local content_length=${#response}
      
      if [[ $content_length -gt 0 ]]; then
        # For Git config, check if it contains git-related content
        if [[ "$file" == "/.git/config" && "$response" == *"[core]"* ]]; then
          echo -e "${RED}[!] Git repository exposed at $test_url${RESET}"
          report_vulnerability "Git Repository Exposed" "A Git repository is exposed at $test_url, which may contain sensitive information." "HIGH"
        
        # For .env files, check if they contain environment variables
        elif [[ "$file" == "/.env" && "$response" == *"="* ]]; then
          echo -e "${RED}[!] Environment file exposed at $test_url${RESET}"
          report_vulnerability "Environment File Exposed" "An environment file is exposed at $test_url, which may contain sensitive information." "HIGH"
          
          # Check for AWS credentials in .env file
          process_response_for_aws_creds "$test_url" "$response"
        
        # For config files, just report them
        elif [[ "$file" == *"config"* || "$file" == *"credentials"* ]]; then
          echo -e "${RED}[!] Configuration file exposed at $test_url${RESET}"
          report_vulnerability "Configuration File Exposed" "A configuration file is exposed at $test_url, which may contain sensitive information." "HIGH"
          
          # Check for AWS credentials in config files
          process_response_for_aws_creds "$test_url" "$response"
        
        # For database files
        elif [[ "$file" == *"database"* || "$file" == *".sql"* || "$file" == *"db."* ]]; then
          echo -e "${RED}[!] Database file exposed at $test_url${RESET}"
          report_vulnerability "Database File Exposed" "A database file is exposed at $test_url, which contains sensitive information." "CRITICAL"
        
        # For phpinfo
        elif [[ "$file" == "/phpinfo.php" && "$response" == *"PHP Version"* ]]; then
          echo -e "${RED}[!] PHP info page exposed at $test_url${RESET}"
          report_vulnerability "PHP Info Exposed" "A PHP info page is exposed at $test_url, revealing server configuration details." "MEDIUM"
        
        # For server-status
        elif [[ "$file" == "/server-status" && "$response" == *"Apache Server Status"* ]]; then
          echo -e "${RED}[!] Apache server status page exposed at $test_url${RESET}"
          report_vulnerability "Server Status Exposed" "The Apache server status page is exposed at $test_url, revealing server details." "MEDIUM"
        
        # For robots.txt, check if it has interesting disallow entries
        elif [[ "$file" == "/robots.txt" ]]; then
          if [[ "$response" == *"Disallow: /admin"* || "$response" == *"Disallow: /backup"* || 
                "$response" == *"Disallow: /config"* || "$response" == *"Disallow: /db"* ||
                "$response" == *"Disallow: /logs"* ]]; then
            echo -e "${YELLOW}[!] robots.txt contains interesting disallow entries at $test_url${RESET}"
            report_vulnerability "Sensitive Directories in robots.txt" "The robots.txt file at $test_url reveals potentially sensitive directories." "LOW"
          fi
        fi
      fi
    fi
  done
}