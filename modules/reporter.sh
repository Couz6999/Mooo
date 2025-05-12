#!/bin/bash
# Reporter module - Handles reporting of vulnerabilities and results

# Initialize vulnerability counter
VULN_COUNT=0
VULN_CRITICAL=0
VULN_HIGH=0
VULN_MEDIUM=0
VULN_LOW=0
VULN_INFO=0

# Initialize the report file
init_report() {
  local output_file=$1
  
  echo -e "# WebSec Security Scan Report" > "$output_file"
  echo -e "Generated on: $(date)" >> "$output_file"
  echo -e "\n---\n" >> "$output_file"
}

# Report a vulnerability
report_vulnerability() {
  local title=$1
  local description=$2
  local severity=$3  # CRITICAL, HIGH, MEDIUM, LOW, INFO
  
  # Increment vulnerability counter
  VULN_COUNT=$((VULN_COUNT + 1))
  
  # Increment severity-specific counter
  case "$severity" in
    "CRITICAL") VULN_CRITICAL=$((VULN_CRITICAL + 1)) ;;
    "HIGH") VULN_HIGH=$((VULN_HIGH + 1)) ;;
    "MEDIUM") VULN_MEDIUM=$((VULN_MEDIUM + 1)) ;;
    "LOW") VULN_LOW=$((VULN_LOW + 1)) ;;
    "INFO") VULN_INFO=$((VULN_INFO + 1)) ;;
  esac
  
  # Determine color based on severity
  local color=""
  case "$severity" in
    "CRITICAL") color="${CRITICAL_COLOR}" ;;
    "HIGH") color="${HIGH_COLOR}" ;;
    "MEDIUM") color="${MEDIUM_COLOR}" ;;
    "LOW") color="${LOW_COLOR}" ;;
    "INFO") color="${INFO_COLOR}" ;;
    *) color="${RESET}" ;;
  esac
  
  # Log the vulnerability
  echo -e "${color}[!] ${BOLD}$severity:${RESET}${color} $title - $description${RESET}"
  
  # Add to the report
  echo -e "### $severity: $title" >> "$OUTPUT_FILE"
  echo -e "- Description: $description" >> "$OUTPUT_FILE"
  echo -e "- Severity: $severity" >> "$OUTPUT_FILE"
  echo -e "- Recommendation: " >> "$OUTPUT_FILE"
  
  # Add recommendations based on vulnerability type
  case "$title" in
    "No HTTPS")
      echo -e "  - Implement HTTPS by obtaining an SSL certificate and configuring your web server to use it." >> "$OUTPUT_FILE"
      echo -e "  - Consider using Let's Encrypt for free SSL certificates." >> "$OUTPUT_FILE"
      echo -e "  - Implement HTTP to HTTPS redirection." >> "$OUTPUT_FILE"
      ;;
    "Expired SSL Certificate")
      echo -e "  - Renew the SSL certificate immediately." >> "$OUTPUT_FILE"
      echo -e "  - Set up automated renewal notifications to prevent future expirations." >> "$OUTPUT_FILE"
      ;;
    "Expiring SSL Certificate")
      echo -e "  - Renew the SSL certificate before it expires." >> "$OUTPUT_FILE"
      echo -e "  - Set up automated renewal processes." >> "$OUTPUT_FILE"
      ;;
    "Missing Security Headers")
      echo -e "  - Implement the missing security headers to improve security posture." >> "$OUTPUT_FILE"
      echo -e "  - Consider using security header generator tools or templates for proper configurations." >> "$OUTPUT_FILE"
      ;;
    "Server Information Disclosure")
      echo -e "  - Configure your web server to hide version information." >> "$OUTPUT_FILE"
      echo -e "  - Use custom Server headers or remove them entirely." >> "$OUTPUT_FILE"
      ;;
    "Potential XSS Vulnerability")
      echo -e "  - Implement proper input validation and output encoding." >> "$OUTPUT_FILE"
      echo -e "  - Consider using Content-Security-Policy header." >> "$OUTPUT_FILE"
      echo -e "  - Sanitize user inputs before processing or storing them." >> "$OUTPUT_FILE"
      ;;
    "Potential SQL Injection Vulnerability")
      echo -e "  - Use parameterized queries or prepared statements instead of string concatenation." >> "$OUTPUT_FILE"
      echo -e "  - Implement proper input validation and use an ORM if possible." >> "$OUTPUT_FILE"
      echo -e "  - Apply the principle of least privilege to database accounts." >> "$OUTPUT_FILE"
      ;;
    "Potential Directory Traversal Vulnerability")
      echo -e "  - Validate and sanitize file path inputs." >> "$OUTPUT_FILE"
      echo -e "  - Use a whitelist approach for allowed files/directories." >> "$OUTPUT_FILE"
      echo -e "  - Implement proper access controls and file permissions." >> "$OUTPUT_FILE"
      ;;
    "Git Repository Exposed"|"Environment File Exposed"|"Configuration File Exposed"|"Database File Exposed")
      echo -e "  - Immediately restrict access to the exposed file." >> "$OUTPUT_FILE"
      echo -e "  - Implement proper .htaccess or web server configuration to deny access." >> "$OUTPUT_FILE"
      echo -e "  - Move sensitive files outside of the web root directory." >> "$OUTPUT_FILE"
      echo -e "  - Replace any leaked credentials or secrets." >> "$OUTPUT_FILE"
      ;;
    "AWS Credentials Exposed"|"AWS Access Key Exposed")
      echo -e "  - Immediately revoke the exposed AWS credentials." >> "$OUTPUT_FILE"
      echo -e "  - Create new keys if needed with proper access restrictions." >> "$OUTPUT_FILE"
      echo -e "  - Review AWS CloudTrail logs for suspicious activities." >> "$OUTPUT_FILE"
      echo -e "  - Implement proper secrets management solutions." >> "$OUTPUT_FILE"
      ;;
    *)
      echo -e "  - Address the vulnerability according to best security practices." >> "$OUTPUT_FILE"
      echo -e "  - Conduct regular security audits and stay updated on security patches." >> "$OUTPUT_FILE"
      ;;
  esac
  
  echo -e "" >> "$OUTPUT_FILE"
}

# Finalize the report
finalize_report() {
  local duration=$1
  local hours=$((duration / 3600))
  local minutes=$(((duration % 3600) / 60))
  local seconds=$((duration % 60))
  
  echo -e "## Scan Summary" >> "$OUTPUT_FILE"
  echo -e "- Scan duration: ${hours}h ${minutes}m ${seconds}s" >> "$OUTPUT_FILE"
  echo -e "- Total vulnerabilities found: $VULN_COUNT" >> "$OUTPUT_FILE"
  echo -e "  - Critical: $VULN_CRITICAL" >> "$OUTPUT_FILE"
  echo -e "  - High: $VULN_HIGH" >> "$OUTPUT_FILE"
  echo -e "  - Medium: $VULN_MEDIUM" >> "$OUTPUT_FILE"
  echo -e "  - Low: $VULN_LOW" >> "$OUTPUT_FILE"
  echo -e "  - Info: $VULN_INFO" >> "$OUTPUT_FILE"
  
  echo -e "\n## Recommendations" >> "$OUTPUT_FILE"
  
  if [[ $VULN_CRITICAL -gt 0 || $VULN_HIGH -gt 0 ]]; then
    echo -e "### Urgent Actions Required:" >> "$OUTPUT_FILE"
    echo -e "- Address all Critical and High vulnerabilities immediately." >> "$OUTPUT_FILE"
    echo -e "- Implement a security incident response plan if not already in place." >> "$OUTPUT_FILE"
    
    if [[ -f "$AWS_CREDS_DIR/aws_keys.txt" ]]; then
      echo -e "- **IMMEDIATELY REVOKE ALL EXPOSED AWS CREDENTIALS**" >> "$OUTPUT_FILE"
    fi
  fi
  
  echo -e "\n### General Security Recommendations:" >> "$OUTPUT_FILE"
  echo -e "1. Implement a Web Application Firewall (WAF) to protect against common attacks." >> "$OUTPUT_FILE"
  echo -e "2. Conduct regular security assessments and penetration testing." >> "$OUTPUT_FILE"
  echo -e "3. Keep all software components and dependencies up to date." >> "$OUTPUT_FILE"
  echo -e "4. Implement proper logging and monitoring for security events." >> "$OUTPUT_FILE"
  echo -e "5. Develop and maintain a security policy for web applications." >> "$OUTPUT_FILE"
  echo -e "6. Train developers and maintainers on secure coding practices." >> "$OUTPUT_FILE"
  
  echo -e "\n---\n" >> "$OUTPUT_FILE"
  echo -e "Report generated by WebSec Scanner v1.0.0" >> "$OUTPUT_FILE"
}