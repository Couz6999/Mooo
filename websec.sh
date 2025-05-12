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
  echo -e "${BOLD}Examples:${RESET}"
  echo -e "  $0 -t https://example.com"
  echo -e "  $0 -t https://example.com -d 3 -r 5 -s -v -o scan_results.txt"
  echo
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
  
  # Validate URL format
  if ! validate_url "$TARGET_URL"; then
    echo -e "${RED}Error: Invalid URL format. Please provide a valid URL.${RESET}" >&2
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
  
  # Create the output directory for AWS credentials if it doesn't exist
  AWS_CREDS_DIR="aws_credentials"
  mkdir -p "$AWS_CREDS_DIR"
  
  # Initialize the report
  init_report "$OUTPUT_FILE"
  
  # Write scan configuration to report
  write_config_to_report
  
  echo -e "${BLUE}[*] Starting scan of ${BOLD}$TARGET_URL${RESET}"
  echo -e "${BLUE}[*] Scan depth: ${BOLD}$DEPTH${RESET}"
  echo -e "${BLUE}[*] Rate limit: ${BOLD}$RATE_LIMIT requests/second${RESET}"
  echo -e "${BLUE}[*] Output file: ${BOLD}$OUTPUT_FILE${RESET}"
  echo -e "${BLUE}[*] AWS credentials will be saved to: ${BOLD}$AWS_CREDS_DIR${RESET}"
  echo

  # Check if required tools are installed
  check_requirements

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

# Write scan configuration to report
write_config_to_report() {
  echo -e "# WebSec Scan Configuration" >> "$OUTPUT_FILE"
  echo -e "- Target URL: $TARGET_URL" >> "$OUTPUT_FILE"
  echo -e "- Scan Depth: $DEPTH" >> "$OUTPUT_FILE"
  echo -e "- Rate Limit: $RATE_LIMIT requests/second" >> "$OUTPUT_FILE"
  echo -e "- Stealth Mode: $([ "$STEALTH_MODE" = true ] && echo "Enabled" || echo "Disabled")" >> "$OUTPUT_FILE"
  echo -e "- Scan started at: $(date)" >> "$OUTPUT_FILE"
  echo -e "\n---\n" >> "$OUTPUT_FILE"
}

# Display scan summary
display_summary() {
  local duration=$1
  local hours=$((duration / 3600))
  local minutes=$(((duration % 3600) / 60))
  local seconds=$((duration % 60))
  
  echo
  echo -e "${GREEN}[+] Scan completed in ${BOLD}${hours}h ${minutes}m ${seconds}s${RESET}"
  echo -e "${GREEN}[+] Results saved to ${BOLD}$OUTPUT_FILE${RESET}"
  
  # Display AWS credential summary if any were found
  if [[ -f "$AWS_CREDS_DIR/aws_keys.txt" ]]; then
    local count=$(wc -l < "$AWS_CREDS_DIR/aws_keys.txt")
    if [[ $count -gt 0 ]]; then
      echo -e "${RED}[!] CRITICAL: ${BOLD}$count AWS credentials found${RESET}"
      echo -e "${RED}[!] AWS credentials saved to ${BOLD}$AWS_CREDS_DIR/aws_keys.txt${RESET}"
    fi
  fi
}

# Run the main function with all command line arguments
main "$@"