#!/bin/bash
# Utility functions for WebSec Scanner

# Check if required tools are installed
check_requirements() {
  echo -e "${BLUE}[*] Checking for required tools...${RESET}"
  
  local missing_tools=()
  
  # List of required tools
  local tools=("curl" "grep" "sed" "awk" "dig" "nmap" "whois")
  
  for tool in "${tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
      missing_tools+=("$tool")
    fi
  done
  
  if [[ ${#missing_tools[@]} -gt 0 ]]; then
    echo -e "${YELLOW}[!] Warning: The following tools are not installed:${RESET}"
    for tool in "${missing_tools[@]}"; do
      echo -e "${YELLOW}    - $tool${RESET}"
    done
    echo -e "${YELLOW}[!] Some functionality may be limited. Install the missing tools for full capabilities.${RESET}"
    sleep 2
  else
    echo -e "${GREEN}[+] All required tools are installed.${RESET}"
  fi
}

# Validate URL format
validate_url() {
  local url=$1
  if [[ $url =~ ^https?://[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(/[-a-zA-Z0-9_%&:/.=?]*)?$ ]]; then
    return 0
  else
    return 1
  fi
}

# Extract domain from URL
extract_domain() {
  local url=$1
  echo "$url" | sed -E 's|^https?://||' | sed -E 's|/.*$||'
}

# Make an HTTP request with error handling
make_request() {
  local url=$1
  local user_agent=$2
  local cookies=$3
  local timeout=10
  local max_retries=3
  local retry_delay=2
  shift 3
  
  local headers=()
  while [[ $# -gt 0 ]]; do
    headers+=("-H" "$1")
    shift
  done
  
  local retry=0
  local response=""
  
  while [[ $retry -lt $max_retries ]]; do
    if [[ -n "$cookies" ]]; then
      response=$(curl -s -k -L --connect-timeout "$timeout" -A "$user_agent" -b "$cookies" "${headers[@]}" "$url" 2>&1)
    else
      response=$(curl -s -k -L --connect-timeout "$timeout" -A "$user_agent" "${headers[@]}" "$url" 2>&1)
    fi
    
    if [[ $? -eq 0 ]]; then
      echo "$response"
      return 0
    fi
    
    retry=$((retry + 1))
    sleep "$retry_delay"
  done
  
  echo "ERROR: Failed to retrieve $url after $max_retries attempts"
  return 1
}

# Safely create temporary files and ensure they're deleted on exit
create_temp_file() {
  local temp_file
  temp_file=$(mktemp /tmp/websec.XXXXXX)
  echo "$temp_file"
}

# Rate limiting function
rate_limit() {
  local rate=$1
  local delay=$(bc <<< "scale=3; 1/$rate")
  sleep "$delay"
}

# Function to get a random delay for stealth mode
random_delay() {
  local min=1
  local max=3
  local delay=$(bc <<< "scale=3; $min + ($max - $min) * $RANDOM / 32767")
  sleep "$delay"
}

# Extract links from HTML content
extract_links() {
  local content=$1
  local base_url=$2
  echo "$content" | grep -o 'href="[^"]*"' | sed 's/href="//;s/"$//' | \
    awk -v base="$base_url" '{
      if ($0 ~ /^http/) print $0;
      else if ($0 ~ /^\//) print base $0;
      else if ($0 !~ /^#/) print base "/" $0;
    }' | sort -u
}

# Human-readable time format
format_time() {
  local seconds=$1
  printf "%02d:%02d:%02d" $((seconds/3600)) $((seconds%3600/60)) $((seconds%60))
}

# URL encode a string
url_encode() {
  local string="$1"
  local length="${#string}"
  local char i
  
  for ((i = 0; i < length; i++)); do
    char="${string:$i:1}"
    case "$char" in
      [a-zA-Z0-9.~_-]) echo -n "$char" ;;
      *) printf '%%%02X' "'$char" ;;
    esac
  done
}

# Generate a unique file name
generate_unique_filename() {
  local base_name=$1
  local extension=$2
  local timestamp=$(date +%Y%m%d%H%M%S)
  local random_str=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 6)
  echo "${base_name}_${timestamp}_${random_str}.${extension}"
}

# Log message with timestamp
log_message() {
  local level=$1
  local message=$2
  local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
  
  case "$level" in
    "INFO") echo -e "${INFO_COLOR}[INFO]${RESET} [$timestamp] $message" ;;
    "LOW") echo -e "${LOW_COLOR}[LOW]${RESET} [$timestamp] $message" ;;
    "MEDIUM") echo -e "${MEDIUM_COLOR}[MEDIUM]${RESET} [$timestamp] $message" ;;
    "HIGH") echo -e "${HIGH_COLOR}[HIGH]${RESET} [$timestamp] $message" ;;
    "CRITICAL") echo -e "${CRITICAL_COLOR}[CRITICAL]${RESET} [$timestamp] $message" ;;
    *) echo -e "[$timestamp] $message" ;;
  esac
}

# Check if a port is open
check_port() {
  local host=$1
  local port=$2
  local timeout=2
  
  (echo > "/dev/tcp/$host/$port") >/dev/null 2>&1
  return $?
}

# Sanitize a string for safe inclusion in reports
sanitize_string() {
  local input=$1
  echo "$input" | sed 's/[^a-zA-Z0-9._-]/_/g'
}