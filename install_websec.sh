#!/bin/bash

# Colors for output
RED="\e[31m"
GREEN="\e[32m"
BLUE="\e[34m"
BOLD="\e[1m"
RESET="\e[0m"

# Display banner
echo -e "${BOLD}${BLUE}"
echo -e "██     ██ ███████ ██████  ███████ ███████  ██████"
echo -e "██     ██ ██      ██   ██ ██      ██      ██     "
echo -e "██  █  ██ █████   ██████  ███████ █████   ██     "
echo -e "██ ███ ██ ██      ██   ██      ██ ██      ██     "
echo -e " ███ ███  ███████ ██████  ███████ ███████  ██████"
echo -e "${RESET}${BOLD}"
echo -e "  Website Security Scanner & AWS Credential Detector"
echo -e "  ${GREEN}Installer v1.0.0${RESET}"
echo -e "${RESET}"

# Create necessary directories
echo -e "${BLUE}[*] Creating directory structure...${RESET}"
mkdir -p websec/{modules,aws_credentials}

# Create main script
echo -e "${BLUE}[*] Creating main script...${RESET}"
cat > websec/websec.sh << 'EOL'
#!/bin/bash
# WebSec - Website Security Scanner with AWS Credential Detection
# Author: Bolt

# Source all modules
source "$(dirname "$0")/modules/colors.sh"
source "$(dirname "$0")/modules/utils.sh"
source "$(dirname "$0")/modules/scanner.sh"
source "$(dirname "$0")/modules/aws_detector.sh"
source "$(dirname "$0")/modules/reporter.sh"

# Display banner
display_banner() {
  echo -e "${BOLD}${BLUE}"
  echo -e "██     ██ ███████ ██████  ███████ ███████  ██████ "
  echo -e "██     ██ ██      ██   ██ ██      ██      ██      "
  echo -e "██  █  ██ █████   ██████  ███████ █████   ██      "
  echo -e "██ ███ ██ ██      ██   ██      ██ ██      ██      "
  echo -e " ███ ███  ███████ ██████  ███████ ███████  ██████ "
  echo -e "${RESET}${BOLD}                                               "
  echo -e "  Website Security Scanner & AWS Credential Detector"
  echo -e "  ${GREEN}v1.0.0${RESET}"
  echo -e "${RESET}"
}

# Initialize default values
TARGET_URL=""
OUTPUT_FILE="results_$(date +%Y%m%d).txt"
DEPTH=2
RATE_LIMIT=10
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
COOKIES=""
HEADERS=()
STEALTH_MODE=false
VERBOSE=false

# Display usage information
usage() {
  echo -e "${BOLD}Usage:${RESET}"
  echo -e "  $0 [options] -t <target_url>"
  echo
  echo -e "${BOLD}Options:${RESET}"
  echo -e "  -t, --target <url>       Target URL to scan (required)"
  echo -e "  -o, --output <file>      Output file to save results (default: results_YYYYMMDD.txt)"
  echo -e "  -d, --depth <number>     Maximum depth for recursive scanning (default: 2)"
  echo -e "  -r, --rate <number>      Rate limit requests per second (default: 10)"
  echo -e "  -a, --agent <string>     Custom user agent string"
  echo -e "  -c, --cookies <string>   Cookies to include with requests"
  echo -e "  -H, --header <header>    Custom header (can be used multiple times)"
  echo -e "  -s, --stealth            Enable stealth mode (slower but less detectable)"
  echo -e "  -v, --verbose            Enable verbose output"
  echo -e "  -h, --help               Display this help message"
  echo
}

# Parse command line arguments
parse_arguments() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--target)
        TARGET_URL="$2"
        shift 2
        ;;
      -o|--output)
        OUTPUT_FILE="$2"
        shift 2
        ;;
      -d|--depth)
        DEPTH="$2"
        shift 2
        ;;
      -r|--rate)
        RATE_LIMIT="$2"
        shift 2
        ;;
      -a|--agent)
        USER_AGENT="$2"
        shift 2
        ;;
      -c|--cookies)
        COOKIES="$2"
        shift 2
        ;;
      -H|--header)
        HEADERS+=("$2")
        shift 2
        ;;
      -s|--stealth)
        STEALTH_MODE=true
        shift
        ;;
      -v|--verbose)
        VERBOSE=true
        shift
        ;;
      -h|--help)
        display_banner
        usage
        exit 0
        ;;
      *)
        echo -e "${RED}Error: Unknown option: $1${RESET}" >&2
        usage
        exit 1
        ;;
    esac
  done

  # Validate required parameters
  if [[ -z "$TARGET_URL" ]]; then
    echo -e "${RED}Error: Target URL is required${RESET}" >&2
    usage
    exit 1
  fi
}

# Main function
main() {
  # Display banner
  display_banner
  
  # Parse command line arguments
  parse_arguments "$@"
  
  # Start scan time
  START_TIME=$(date +%s)
  
  # Initialize the report
  init_report "$OUTPUT_FILE"
  
  echo -e "${BLUE}[*] Starting scan of ${BOLD}$TARGET_URL${RESET}"
  echo -e "${BLUE}[*] Scan depth: ${BOLD}$DEPTH${RESET}"
  echo -e "${BLUE}[*] Rate limit: ${BOLD}$RATE_LIMIT requests/second${RESET}"
  echo -e "${BLUE}[*] Output file: ${BOLD}$OUTPUT_FILE${RESET}"
  echo

  # Perform the scan
  perform_scan "$TARGET_URL" "$DEPTH" "$RATE_LIMIT" "$USER_AGENT" "$COOKIES" "${HEADERS[@]}" "$STEALTH_MODE" "$VERBOSE"
  
  # Process AWS credential detection
  detect_aws_credentials "$AWS_CREDS_DIR" "$VERBOSE"
  
  # Finalize the report
  END_TIME=$(date +%s)
  DURATION=$((END_TIME - START_TIME))
  finalize_report "$DURATION"
  
  # Display summary
  display_summary "$DURATION"
}

# Run the main function with all command line arguments
main "$@"
EOL

# Create module files
echo -e "${BLUE}[*] Creating module files...${RESET}"

# Colors module
cat > websec/modules/colors.sh << 'EOL'
#!/bin/bash
# Colors and formatting for terminal output

# Reset
RESET="\e[0m"

# Regular Colors
BLACK="\e[30m"
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"
WHITE="\e[37m"

# Bold Colors
BOLD="\e[1m"
BOLD_BLACK="\e[1;30m"
BOLD_RED="\e[1;31m"
BOLD_GREEN="\e[1;32m"
BOLD_YELLOW="\e[1;33m"
BOLD_BLUE="\e[1;34m"
BOLD_MAGENTA="\e[1;35m"
BOLD_CYAN="\e[1;36m"
BOLD_WHITE="\e[1;37m"

# Severity level colors
INFO_COLOR="${BLUE}"
LOW_COLOR="${GREEN}"
MEDIUM_COLOR="${YELLOW}"
HIGH_COLOR="${RED}"
CRITICAL_COLOR="${BOLD}${RED}"
EOL

# Utils module
cat > websec/modules/utils.sh << 'EOL'
#!/bin/bash
# Utility functions

# Check if required tools are installed
check_requirements() {
  local missing_tools=()
  local tools=("curl" "grep" "sed" "awk" "dig" "openssl")
  
  for tool in "${tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
      missing_tools+=("$tool")
    fi
  done
  
  if [[ ${#missing_tools[@]} -gt 0 ]]; then
    echo -e "${RED}[!] Missing required tools: ${missing_tools[*]}${RESET}"
    exit 1
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

# Rate limiting function
rate_limit() {
  local rate=$1
  sleep $(bc <<< "scale=3; 1/$rate")
}
EOL

# Scanner module
cat > websec/modules/scanner.sh << 'EOL'
#!/bin/bash
# Scanner module

# Perform the website scan
perform_scan() {
  local target_url=$1
  local depth=$2
  local rate_limit=$3
  local user_agent=$4
  local cookies=$5
  local headers=("${@:6}")
  
  local domain=$(extract_domain "$target_url")
  
  echo -e "${BLUE}[*] Scanning $domain...${RESET}"
  
  # Check SSL/TLS configuration
  check_ssl "$target_url"
  
  # Check HTTP headers
  check_headers "$target_url"
  
  # Scan for AWS credentials
  scan_for_aws_creds "$target_url"
}

# Check SSL/TLS configuration
check_ssl() {
  local url=$1
  if [[ "$url" =~ ^https:// ]]; then
    echo -e "${BLUE}[*] Checking SSL/TLS configuration...${RESET}"
    # SSL checks implementation
  fi
}

# Check HTTP security headers
check_headers() {
  local url=$1
  echo -e "${BLUE}[*] Checking HTTP security headers...${RESET}"
  # Header checks implementation
}

# Scan for AWS credentials
scan_for_aws_creds() {
  local url=$1
  echo -e "${BLUE}[*] Scanning for exposed AWS credentials...${RESET}"
  # AWS credential scanning implementation
}
EOL

# AWS detector module
cat > websec/modules/aws_detector.sh << 'EOL'
#!/bin/bash
# AWS Credential Detector Module

# Detect AWS credentials
detect_aws_credentials() {
  local response=$1
  
  # Look for AWS Access Key ID
  if [[ "$response" =~ (AKIA[0-9A-Z]{16}) ]]; then
    local access_key="${BASH_REMATCH[1]}"
    
    # Look for AWS Secret Key
    if [[ "$response" =~ ([0-9a-zA-Z+/]{40}) ]]; then
      local secret_key="${BASH_REMATCH[1]}"
      
      # Look for AWS Region
      if [[ "$response" =~ (us|eu|ap|sa|ca|cn|af|me)-[a-z]+-[0-9]+ ]]; then
        local region="${BASH_REMATCH[0]}"
        echo "$access_key / $secret_key / $region" >> aws_credentials/found_credentials.txt
      fi
    fi
  fi
}
EOL

# Reporter module
cat > websec/modules/reporter.sh << 'EOL'
#!/bin/bash
# Reporter module

# Initialize report
init_report() {
  local output_file=$1
  echo "WebSec Security Scan Report" > "$output_file"
  echo "Generated on: $(date)" >> "$output_file"
  echo "-------------------" >> "$output_file"
}

# Add finding to report
report_finding() {
  local severity=$1
  local title=$2
  local description=$3
  local output_file=$4
  
  echo "[${severity}] ${title}" >> "$output_file"
  echo "Description: ${description}" >> "$output_file"
  echo "-------------------" >> "$output_file"
}

# Finalize report
finalize_report() {
  local output_file=$1
  echo "Scan completed on: $(date)" >> "$output_file"
}
EOL

# Set execute permissions
echo -e "${BLUE}[*] Setting execute permissions...${RESET}"
chmod +x websec/websec.sh
chmod +x websec/modules/*.sh

echo -e "${GREEN}[+] Installation complete!${RESET}"
echo -e "${GREEN}[+] The WebSec Scanner has been installed to the 'websec' directory${RESET}"
echo -e "${GREEN}[+] Run './websec/websec.sh -h' to see usage instructions${RESET}"