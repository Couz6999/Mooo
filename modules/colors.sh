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

# Special formatting
UNDERLINE="\e[4m"
BLINK="\e[5m"