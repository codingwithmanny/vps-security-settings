#!/bin/bash

# ============================================================================
# UBUNTU 25.04 VPS SECURITY HARDENING SCRIPT
# ============================================================================
# VERSION: 1.0.0
# AUTHOR: Security Hardening Script
# TESTED ON: Ubuntu 25.04 LTS
#
# PURPOSE:
#   This script applies recommended security best practices to a fresh Ubuntu
#   25.04 VPS. It's designed for intermediate users who want sensible defaults
#   with optional customization through interactive prompts.
#
# USAGE:
#   sudo ./secure-ubuntu.sh           # Interactive mode (recommended)
#   sudo ./secure-ubuntu.sh --quiet   # Quick mode with all defaults
#   sudo ./secure-ubuntu.sh --dry-run # Preview changes without applying
#
# WHAT THIS SCRIPT DOES:
#   1. Creates a non-root sudo user (prevents direct root access)
#   2. Hardens SSH configuration (key-based auth, limits attempts)
#   3. Configures UFW firewall (blocks unwanted traffic)
#   4. Installs fail2ban (blocks brute-force attacks)
#   5. Sets up automatic security updates (keeps system patched)
#   6. Installs security auditing tools (monitors for threats)
#
# SAFETY:
#   - All original config files are backed up before modification
#   - Script warns before making changes that could lock you out
#   - Can be run in dry-run mode to preview all changes first
#
# ============================================================================
# SCRIPT SECTION LEGEND (TABLE OF CONTENTS)
# ============================================================================
#   - GLOBAL VARIABLES............Set global settings, flags, paths, etc.
#   - HELPER FUNCTIONS............Utility functions for output, logging, etc.
#   - ARGUMENT PARSING............Handles --quiet, --dry-run, etc.
#   - PRE-FLIGHT CHECKS...........Ensures root, correct Ubuntu version, warns user
#   - USER MANAGEMENT.............Creates and secures a non-root sudo user
#   - SSH HARDENING...............Secures SSH (disables root, changes port, key auth)
#   - FIREWALL CONFIGURATION......Sets up UFW firewall and allowed ports
#   - FAIL2BAN SETUP..............Configures fail2ban to defend from brute force
#   - AUTO-UPDATES................Installs/configures unattended-upgrades
#   - SECURITY TOOLS..............Installs extra audit & monitoring tools
#   - FINALIZATION................Prints summary, tips, and audit logs location
# ============================================================================

set -e  # Exit on any error

# ============================================================================
# SECTION: GLOBAL VARIABLES
# ============================================================================
# PURPOSE: Define script-wide settings and state variables
#
# These variables control script behavior and store configuration choices
# made during the interactive prompts for use across different sections.
# ============================================================================

SCRIPT_VERSION="1.0.0"
LOG_FILE="/var/log/secure-ubuntu.log"
BACKUP_DIR="/root/security-backup-$(date +%Y%m%d-%H%M%S)"
AUDIT_LOG_DIR="/var/log/security-audit"

# Mode flags - controlled by command line arguments
DRY_RUN=false
QUIET_MODE=false

# User configuration - populated during user management section
NEW_USERNAME=""
CREATED_USER=false

# SSH configuration - populated during SSH hardening section
SSH_PORT=22
SSH_KEY_PATH=""

# Firewall configuration - populated during firewall section
EXTRA_PORTS=""

# Fail2ban configuration
BAN_TIME="1h"

# Auto-updates configuration
AUTO_REBOOT=false


# ============================================================================
# SECTION: HELPER FUNCTIONS - COLORS AND OUTPUT
# ============================================================================
# PURPOSE: Provide consistent, color-coded output for better readability
#
# WHY THIS MATTERS:
#   Clear visual feedback helps users understand what's happening and quickly
#   identify warnings, errors, or successful operations. Color coding reduces
#   the chance of missing important messages during script execution.
#
# COLOR SCHEME:
#   - GREEN: Success messages and completed operations
#   - YELLOW: Warnings and prompts requiring attention
#   - RED: Errors and critical warnings
#   - BLUE: Informational messages and section headers
#   - CYAN: User prompts and input requests
# ============================================================================

# Terminal color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'  # No Color - resets terminal color

# print_header - Displays a prominent section header
# USAGE: print_header "Section Name"
# Creates a visual separator to clearly mark the start of each major section
print_header() {
    echo ""
    echo -e "${BLUE}============================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}============================================================================${NC}"
    echo ""
}

# print_success - Displays a success message in green
# USAGE: print_success "Operation completed"
print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
    log_action "SUCCESS: $1"
}

# print_warning - Displays a warning message in yellow
# USAGE: print_warning "Something needs attention"
print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
    log_action "WARNING: $1"
}

# print_error - Displays an error message in red
# USAGE: print_error "Something went wrong"
print_error() {
    echo -e "${RED}[✗] $1${NC}"
    log_action "ERROR: $1"
}

# print_info - Displays an informational message in blue
# USAGE: print_info "Here's some information"
print_info() {
    echo -e "${BLUE}[i] $1${NC}"
    log_action "INFO: $1"
}

# print_prompt - Displays a prompt message in cyan
# USAGE: print_prompt "Enter your choice"
print_prompt() {
    echo -e "${CYAN}[?] $1${NC}"
}


# ============================================================================
# SECTION: HELPER FUNCTIONS - LOGGING
# ============================================================================
# PURPOSE: Record all script actions for audit trail and troubleshooting
#
# WHY THIS MATTERS:
#   Security changes should always be logged for:
#   - Audit compliance: Know exactly what was changed and when
#   - Troubleshooting: If something breaks, logs show what happened
#   - Rollback planning: Logs help identify what needs to be undone
#
# LOG FORMAT:
#   [TIMESTAMP] ACTION_TYPE: Description
#   Example: [2024-01-15 10:30:45] SUCCESS: SSH port changed to 2222
# ============================================================================

# log_action - Records an action to the log file
# USAGE: log_action "Description of what happened"
# NOTE: In dry-run mode, actions are logged with [DRY-RUN] prefix
log_action() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local prefix=""
    
    if [[ "$DRY_RUN" == true ]]; then
        prefix="[DRY-RUN] "
    fi
    
    # Create log file if it doesn't exist (skip in dry-run)
    if [[ "$DRY_RUN" == false ]]; then
        echo "[${timestamp}] ${prefix}$1" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# init_logging - Initializes the log file with session header
# Creates the log file and records the start of a new hardening session
init_logging() {
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Dry-run mode: Actions will be logged to console only"
        return
    fi
    
    # Create log directory if needed
    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    mkdir -p "$log_dir" 2>/dev/null || true
    
    # Write session header to log
    {
        echo ""
        echo "========================================"
        echo "Security Hardening Session Started"
        echo "Date: $(date)"
        echo "Script Version: $SCRIPT_VERSION"
        echo "========================================"
    } >> "$LOG_FILE" 2>/dev/null || true
    
    print_success "Logging initialized: $LOG_FILE"
}


# ============================================================================
# SECTION: HELPER FUNCTIONS - BACKUP
# ============================================================================
# PURPOSE: Create backups of all configuration files before modification
#
# WHY THIS MATTERS:
#   NEVER modify system configuration without a backup! If something goes
#   wrong (misconfigured SSH could lock you out), you need the ability to
#   restore the original configuration.
#
# BACKUP STRATEGY:
#   - All backups stored in /root/security-backup-{timestamp}/
#   - Original file paths are preserved in backup directory structure
#   - Backup directory is created with restricted permissions (700)
# ============================================================================

# create_backup_dir - Creates the backup directory for this session
# Called once at the start of the script to prepare for backups
create_backup_dir() {
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would create backup directory: $BACKUP_DIR"
        return
    fi
    
    mkdir -p "$BACKUP_DIR"
    # Restrict access to root only - backups may contain sensitive data
    chmod 700 "$BACKUP_DIR"
    print_success "Backup directory created: $BACKUP_DIR"
    log_action "Backup directory created: $BACKUP_DIR"
}

# backup_file - Creates a backup of a specific file
# USAGE: backup_file "/path/to/config/file"
# Preserves the directory structure within the backup folder
backup_file() {
    local file_path="$1"
    
    # Skip if file doesn't exist
    if [[ ! -f "$file_path" ]]; then
        print_info "No existing file to backup: $file_path"
        return
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would backup: $file_path"
        return
    fi
    
    # Create parent directories in backup location
    local backup_path="${BACKUP_DIR}${file_path}"
    mkdir -p "$(dirname "$backup_path")"
    
    # Copy the file preserving permissions and timestamps
    cp -p "$file_path" "$backup_path"
    print_success "Backed up: $file_path"
    log_action "Backed up file: $file_path -> $backup_path"
}


# ============================================================================
# SECTION: HELPER FUNCTIONS - USER PROMPTS
# ============================================================================
# PURPOSE: Provide consistent, user-friendly prompts with sensible defaults
#
# WHY THIS MATTERS:
#   Good prompts make the script accessible to intermediate users by:
#   - Clearly stating what's being asked
#   - Showing the default value that will be used if Enter is pressed
#   - Validating input where appropriate
#   
# QUIET MODE:
#   When --quiet flag is used, all prompts automatically use their defaults
#   to enable unattended/automated deployments.
# ============================================================================

# prompt_yes_no - Asks a yes/no question with a default value
# USAGE: prompt_yes_no "Question text" "default" (y or n)
# RETURNS: 0 for yes, 1 for no (use with if statements)
# EXAMPLE: if prompt_yes_no "Enable feature?" "y"; then ...
prompt_yes_no() {
    local question="$1"
    local default="$2"
    
    # In quiet mode, use the default without prompting
    if [[ "$QUIET_MODE" == true ]]; then
        [[ "$default" == "y" ]] && return 0 || return 1
    fi
    
    local prompt_suffix
    if [[ "$default" == "y" ]]; then
        prompt_suffix="[Y/n]"
    else
        prompt_suffix="[y/N]"
    fi
    
    print_prompt "$question $prompt_suffix"
    read -r response
    
    # Use default if empty response
    if [[ -z "$response" ]]; then
        response="$default"
    fi
    
    # Return based on response
    [[ "$response" =~ ^[Yy]$ ]] && return 0 || return 1
}

# prompt_input - Asks for text input with an optional default
# USAGE: prompt_input "Question" "default_value"
# RETURNS: The user's input (or default if empty) via echo
# EXAMPLE: username=$(prompt_input "Enter username" "admin")
# NOTE: Prompts are sent to stderr so they display when used in command substitution
prompt_input() {
    local question="$1"
    local default="$2"
    
    # In quiet mode, return the default without prompting
    if [[ "$QUIET_MODE" == true ]]; then
        echo "$default"
        return
    fi
    
    # Use stderr (>&2) for prompts so they display even inside $(...) command substitution
    # Without this, the prompt would be captured instead of shown to the user
    if [[ -n "$default" ]]; then
        echo -e "${CYAN}[?] $question [default: $default]${NC}" >&2
    else
        echo -e "${CYAN}[?] $question${NC}" >&2
    fi
    
    read -r response
    
    # Return default if empty, otherwise return response
    if [[ -z "$response" ]]; then
        echo "$default"
    else
        echo "$response"
    fi
}

# prompt_password - Asks for password input (hidden)
# USAGE: prompt_password "Enter password"
# RETURNS: The password via echo
# NOTE: Input is hidden for security. Prompt sent to stderr for command substitution.
prompt_password() {
    local question="$1"
    
    # Use stderr for prompt so it displays even inside $(...) command substitution
    echo -e "${CYAN}[?] $question${NC}" >&2
    read -rs response
    echo "" >&2  # New line after hidden input (also to stderr)
    echo "$response"
}


# ============================================================================
# SECTION: HELPER FUNCTIONS - SYSTEM OPERATIONS
# ============================================================================
# PURPOSE: Wrapper functions for system operations with dry-run support
#
# WHY THIS MATTERS:
#   Dry-run mode allows users to preview all changes before applying them.
#   These wrappers ensure consistent handling of dry-run across all operations.
# ============================================================================

# run_cmd - Executes a command with dry-run support
# USAGE: run_cmd "description" "command to run"
# In dry-run mode, prints what would be executed instead of running it
run_cmd() {
    local description="$1"
    local command="$2"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would execute: $command"
        return 0
    fi
    
    print_info "$description"
    eval "$command"
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log_action "Executed: $command"
    else
        log_action "Failed (exit $exit_code): $command"
    fi
    
    return $exit_code
}

# install_package - Installs a package with apt
# USAGE: install_package "package-name"
# Handles apt update if needed and provides consistent output
install_package() {
    local package="$1"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would install package: $package"
        return 0
    fi
    
    print_info "Installing $package..."
    
    # Check if already installed
    if dpkg -l "$package" &>/dev/null; then
        print_info "$package is already installed"
        return 0
    fi
    
    # Install the package
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" &>/dev/null
    
    if [[ $? -eq 0 ]]; then
        print_success "Installed $package"
        log_action "Installed package: $package"
    else
        print_error "Failed to install $package"
        log_action "Failed to install package: $package"
        return 1
    fi
}


# ============================================================================
# SECTION: PRE-FLIGHT CHECKS
# ============================================================================
# PURPOSE: Verify the system is ready for security hardening
#
# WHY THIS MATTERS:
#   Running this script on the wrong system or without proper permissions
#   could cause serious problems. These checks ensure:
#   - Script runs with root privileges (required for system changes)
#   - System is Ubuntu 25.04 (settings are version-specific)
#   - User understands they're about to modify system security
#
# CHECKS PERFORMED:
#   1. Root/sudo privileges
#   2. Ubuntu version verification
#   3. User confirmation before proceeding
# ============================================================================

preflight_checks() {
    print_header "PRE-FLIGHT CHECKS"
    
    # Check 1: Root privileges
    # REASONING: All security configurations require root access to modify
    #            system files in /etc/ and install packages
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        print_info "Try: sudo $0"
        exit 1
    fi
    print_success "Running with root privileges"
    
    # Check 2: Ubuntu version
    # REASONING: Security settings and file locations vary between Ubuntu versions.
    #            This script is tested on Ubuntu 25.04 and may not work correctly
    #            on other versions.
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]]; then
            print_error "This script is designed for Ubuntu. Detected: $ID"
            exit 1
        fi
        
        # Extract major version (e.g., "25" from "25.04")
        local major_version
        major_version=$(echo "$VERSION_ID" | cut -d. -f1)
        
        if [[ "$major_version" -lt 24 ]]; then
            print_warning "This script is optimized for Ubuntu 25.04"
            print_warning "Detected version: $VERSION_ID"
            if ! prompt_yes_no "Continue anyway?" "n"; then
                print_info "Exiting. Please use Ubuntu 25.04 or later."
                exit 0
            fi
        else
            print_success "Ubuntu $VERSION_ID detected"
        fi
    else
        print_warning "Could not detect OS version"
        if ! prompt_yes_no "Continue anyway?" "n"; then
            exit 0
        fi
    fi
    
    # Check 3: Confirm with user
    # REASONING: Security changes can lock users out if misconfigured.
    #            Explicit confirmation ensures user understands the risks.
    echo ""
    print_warning "This script will modify system security settings."
    print_warning "A backup of all modified files will be created."
    echo ""
    
    if [[ "$QUIET_MODE" == false ]]; then
        if ! prompt_yes_no "Do you want to proceed with security hardening?" "y"; then
            print_info "Exiting without making changes."
            exit 0
        fi
    fi
    
    # Update package lists
    # REASONING: Ensures we install the latest versions of security packages
    print_info "Updating package lists..."
    if [[ "$DRY_RUN" == false ]]; then
        apt-get update &>/dev/null
        print_success "Package lists updated"
    else
        print_info "Would update package lists"
    fi
    
    print_success "Pre-flight checks completed"
}


# ============================================================================
# SECTION: USER MANAGEMENT
# ============================================================================
# PURPOSE: Create a non-root sudo user for daily server administration
#
# WHY THIS MATTERS:
#   Using root directly is a security anti-pattern because:
#   - Root has unlimited power - a typo can destroy your system
#   - All actions are logged under the same user - no accountability
#   - Attackers specifically target root logins
#   - Many automated attacks assume root is the only admin user
#
# BEST PRACTICE:
#   Create a regular user with sudo privileges. This provides:
#   - Accountability (actions logged under specific username)
#   - Safety net (must explicitly use sudo for dangerous commands)
#   - Reduced attack surface (root login can be disabled)
#
# RISK IF NOT CONFIGURED:
#   Direct root access means any compromise gives full system control.
#   Brute-force attacks against root are extremely common.
# ============================================================================

setup_user_management() {
    print_header "USER MANAGEMENT"
    
    echo "# ---------------------------------------------------------------"
    echo "# Creating a non-root sudo user is a fundamental security practice."
    echo "# This user will be used for SSH access instead of root."
    echo "# ---------------------------------------------------------------"
    echo ""
    
    # Prompt: Create a new sudo user?
    # Default is yes because most fresh VPS installations only have root
    if prompt_yes_no "Create a new sudo user?" "y"; then
        
        # Get username
        # REASONING: Username should be unique and not easily guessable
        NEW_USERNAME=$(prompt_input "Enter username for new sudo user" "")
        
        # Validate username
        if [[ -z "$NEW_USERNAME" ]]; then
            print_error "Username cannot be empty"
            return 1
        fi
        
        # Check if user already exists
        if id "$NEW_USERNAME" &>/dev/null; then
            print_warning "User '$NEW_USERNAME' already exists"
            if prompt_yes_no "Add existing user to sudo group?" "y"; then
                if [[ "$DRY_RUN" == false ]]; then
                    usermod -aG sudo "$NEW_USERNAME"
                    print_success "Added '$NEW_USERNAME' to sudo group"
                else
                    print_info "Would add '$NEW_USERNAME' to sudo group"
                fi
            fi
            CREATED_USER=true
        else
            # Create new user
            if [[ "$DRY_RUN" == true ]]; then
                print_info "Would create user: $NEW_USERNAME"
                print_info "Would add user to sudo group"
                CREATED_USER=true
            else
                # Create user with home directory
                # REASONING: -m creates home directory, -s sets shell to bash
                print_info "Creating user '$NEW_USERNAME'..."
                useradd -m -s /bin/bash "$NEW_USERNAME"
                
                # Set password
                # REASONING: User needs a password for sudo authentication
                echo ""
                print_prompt "Set password for '$NEW_USERNAME':"
                passwd "$NEW_USERNAME"
                
                # Add to sudo group
                # REASONING: sudo group membership allows running commands as root
                usermod -aG sudo "$NEW_USERNAME"
                
                print_success "User '$NEW_USERNAME' created and added to sudo group"
                log_action "Created sudo user: $NEW_USERNAME"
                CREATED_USER=true
            fi
        fi
        
        # Create .ssh directory for the new user
        # REASONING: Prepare for SSH key authentication
        if [[ "$DRY_RUN" == false && "$CREATED_USER" == true ]]; then
            local user_home
            user_home=$(getent passwd "$NEW_USERNAME" | cut -d: -f6)
            
            if [[ -n "$user_home" ]]; then
                mkdir -p "$user_home/.ssh"
                chmod 700 "$user_home/.ssh"
                touch "$user_home/.ssh/authorized_keys"
                chmod 600 "$user_home/.ssh/authorized_keys"
                chown -R "$NEW_USERNAME:$NEW_USERNAME" "$user_home/.ssh"
                print_success "Created .ssh directory for $NEW_USERNAME"
            fi
        fi
    else
        print_info "Skipping user creation"
        
        # If not creating user, ask which user to configure SSH for
        NEW_USERNAME=$(prompt_input "Enter existing username for SSH access" "$(whoami)")
    fi
    
    print_success "User management completed"
}


# ============================================================================
# SECTION: SSH HARDENING
# ============================================================================
# PURPOSE: Secure SSH access to prevent unauthorized remote access
#
# WHY THIS MATTERS:
#   SSH is the #1 attack vector for VPS servers. Within minutes of a server
#   going online, automated bots begin attempting to brute-force SSH access.
#   Without proper hardening:
#   - Password guessing attacks can eventually succeed
#   - Root login attempts are constant
#   - Default port 22 is scanned by every bot on the internet
#
# CHANGES MADE:
#   - Key-based authentication only (passwords can be guessed)
#   - Disable root login (forces use of sudo user)
#   - Limit authentication attempts (slows brute-force)
#   - Optional: Non-standard port (reduces automated scanning noise)
#
# RISK IF NOT CONFIGURED:
#   Server compromise through brute-force SSH attacks. Attackers gain
#   full access to your server and can install malware, steal data,
#   or use your server for attacks on others.
# ============================================================================

setup_ssh_hardening() {
    print_header "SSH HARDENING"
    
    echo "# ---------------------------------------------------------------"
    echo "# SSH hardening significantly reduces your attack surface."
    echo "# Key-based authentication and limited attempts prevent most attacks."
    echo "# ---------------------------------------------------------------"
    echo ""
    
    local sshd_config="/etc/ssh/sshd_config"
    
    # Backup original SSH config
    # REASONING: SSH misconfiguration can lock you out - always backup first!
    backup_file "$sshd_config"
    
    # --- SSH Port Configuration ---
    # NOTE: Changing SSH port is "security through obscurity" - it doesn't
    #       stop determined attackers but dramatically reduces automated scans.
    #       This reduces log noise and makes real attacks easier to spot.
    
    if prompt_yes_no "Change SSH port from default (22)?" "n"; then
        local suggested_port=$((RANDOM % 10000 + 10000))  # Random port 10000-20000
        SSH_PORT=$(prompt_input "Enter new SSH port" "$suggested_port")
        
        # Validate port number
        if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$SSH_PORT" -lt 1024 ]] || [[ "$SSH_PORT" -gt 65535 ]]; then
            print_warning "Invalid port. Using default port 22"
            SSH_PORT=22
        fi
    fi
    
    print_info "SSH will use port: $SSH_PORT"
    
    # --- SSH Key Configuration ---
    # REASONING: SSH keys are cryptographically secure and cannot be brute-forced
    #            like passwords. A 4096-bit RSA key would take billions of years to crack.
    
    echo ""
    print_warning "SSH key authentication is strongly recommended!"
    print_info "Password authentication will be disabled after key is configured."
    echo ""
    
    if [[ "$CREATED_USER" == true && -n "$NEW_USERNAME" ]]; then
        local user_home
        user_home=$(getent passwd "$NEW_USERNAME" | cut -d: -f6)
        local auth_keys="$user_home/.ssh/authorized_keys"
        
        echo "You can add your SSH public key now, or do it manually later."
        echo "To generate a key on your LOCAL machine: ssh-keygen -t ed25519"
        echo ""
        
        SSH_KEY_PATH=$(prompt_input "Paste your SSH public key (or press Enter to skip)" "")
        
        if [[ -n "$SSH_KEY_PATH" ]]; then
            if [[ "$DRY_RUN" == false ]]; then
                echo "$SSH_KEY_PATH" >> "$auth_keys"
                chown "$NEW_USERNAME:$NEW_USERNAME" "$auth_keys"
                chmod 600 "$auth_keys"
                print_success "SSH public key added for $NEW_USERNAME"
                log_action "Added SSH public key for $NEW_USERNAME"
            else
                print_info "Would add SSH public key for $NEW_USERNAME"
            fi
        else
            print_warning "No SSH key provided - password authentication will remain enabled"
            print_warning "Add your key later to: $auth_keys"
        fi
    fi
    
    # --- Apply SSH Configuration Changes ---
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would apply the following SSH hardening settings:"
        echo ""
        echo "  Port $SSH_PORT"
        echo "  PermitRootLogin no"
        echo "  MaxAuthTries 3"
        echo "  LoginGraceTime 60"
        echo "  PermitEmptyPasswords no"
        echo "  X11Forwarding no"
        [[ -n "$SSH_KEY_PATH" ]] && echo "  PasswordAuthentication no"
        [[ -n "$NEW_USERNAME" ]] && echo "  AllowUsers $NEW_USERNAME"
        echo ""
    else
        # Create a hardened sshd_config
        # REASONING: Each setting addresses a specific attack vector
        
        print_info "Applying SSH hardening configuration..."
        
        # Port - Change from default to reduce automated scanning
        # REASONING: Most bots only scan port 22, changing port reduces noise
        sed -i "s/^#Port .*/Port $SSH_PORT/" "$sshd_config"
        sed -i "s/^Port .*/Port $SSH_PORT/" "$sshd_config"
        
        # PermitRootLogin no - Disable direct root SSH access
        # REASONING: Forces attackers to guess both username AND password
        #            Also creates audit trail under specific usernames
        sed -i 's/^#PermitRootLogin .*/PermitRootLogin no/' "$sshd_config"
        sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' "$sshd_config"
        
        # MaxAuthTries 3 - Limit authentication attempts per connection
        # REASONING: Slows brute-force attacks and makes fail2ban more effective
        #            Attacker must reconnect after 3 failed attempts
        sed -i 's/^#MaxAuthTries .*/MaxAuthTries 3/' "$sshd_config"
        sed -i 's/^MaxAuthTries .*/MaxAuthTries 3/' "$sshd_config"
        
        # LoginGraceTime 60 - Time allowed to authenticate (seconds)
        # REASONING: Prevents attackers from holding connections open
        #            60 seconds is plenty for legitimate users
        sed -i 's/^#LoginGraceTime .*/LoginGraceTime 60/' "$sshd_config"
        sed -i 's/^LoginGraceTime .*/LoginGraceTime 60/' "$sshd_config"
        
        # PermitEmptyPasswords no - Disallow empty passwords
        # REASONING: Some systems allow empty passwords - this is extremely dangerous
        sed -i 's/^#PermitEmptyPasswords .*/PermitEmptyPasswords no/' "$sshd_config"
        sed -i 's/^PermitEmptyPasswords .*/PermitEmptyPasswords no/' "$sshd_config"
        
        # X11Forwarding no - Disable X11 forwarding
        # REASONING: X11 forwarding is rarely needed on servers and adds attack surface
        sed -i 's/^#X11Forwarding .*/X11Forwarding no/' "$sshd_config"
        sed -i 's/^X11Forwarding .*/X11Forwarding no/' "$sshd_config"
        
        # PasswordAuthentication - Only disable if SSH key was provided
        # WARNING: Disabling password auth without a working key will lock you out!
        if [[ -n "$SSH_KEY_PATH" ]]; then
            sed -i 's/^#PasswordAuthentication .*/PasswordAuthentication no/' "$sshd_config"
            sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' "$sshd_config"
            print_success "Password authentication disabled (key-based only)"
        else
            print_warning "Password authentication remains enabled (no SSH key provided)"
        fi
        
        # AllowUsers - Restrict which users can SSH in
        # REASONING: Even if other users exist, only specified users can connect
        if [[ -n "$NEW_USERNAME" ]]; then
            # Remove any existing AllowUsers line and add new one
            sed -i '/^AllowUsers/d' "$sshd_config"
            echo "AllowUsers $NEW_USERNAME" >> "$sshd_config"
            print_success "SSH access restricted to user: $NEW_USERNAME"
        fi
        
        # Test SSH configuration before restarting
        # REASONING: A syntax error in sshd_config will prevent SSH from starting
        #            This test catches errors before we restart the service
        if sshd -t &>/dev/null; then
            print_success "SSH configuration syntax is valid"
            
            # Restart SSH service to apply changes
            systemctl restart sshd
            print_success "SSH service restarted with new configuration"
            log_action "SSH hardening applied: Port=$SSH_PORT, RootLogin=no, MaxAuthTries=3"
        else
            print_error "SSH configuration has errors! Restoring backup..."
            cp "${BACKUP_DIR}${sshd_config}" "$sshd_config"
            print_warning "Original SSH configuration restored"
            log_action "SSH configuration error - backup restored"
        fi
    fi
    
    # Display connection information
    echo ""
    print_warning "IMPORTANT: Note your new SSH connection details!"
    echo ""
    echo "  ssh ${NEW_USERNAME:-root}@<your-server-ip> -p $SSH_PORT"
    echo ""
    print_warning "Test this connection in a NEW terminal before closing this session!"
    echo ""
    
    print_success "SSH hardening completed"
}


# ============================================================================
# SECTION: UFW FIREWALL CONFIGURATION
# ============================================================================
# PURPOSE: Block all incoming traffic except explicitly allowed services
#
# WHY THIS MATTERS:
#   A firewall is your server's first line of defense. Without it:
#   - Every running service is exposed to the internet
#   - Accidentally started services become attack vectors
#   - Port scanning reveals all listening services
#
# STRATEGY:
#   Default DENY incoming - block everything by default
#   Default ALLOW outgoing - server can reach the internet
#   Explicitly allow only required ports (SSH, web, etc.)
#
# UFW (Uncomplicated Firewall):
#   UFW is a user-friendly interface to iptables. It's included in Ubuntu
#   and provides simple commands for firewall management.
#
# RISK IF NOT CONFIGURED:
#   Any service listening on a port is accessible from the internet.
#   This includes development servers, databases, and debugging tools.
# ============================================================================

setup_firewall() {
    print_header "UFW FIREWALL CONFIGURATION"
    
    echo "# ---------------------------------------------------------------"
    echo "# The firewall blocks all incoming traffic except what you allow."
    echo "# This prevents attackers from reaching services you didn't intend to expose."
    echo "# ---------------------------------------------------------------"
    echo ""
    
    # Install UFW if not present
    install_package "ufw"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would configure UFW with the following rules:"
        echo ""
        echo "  - Default deny incoming"
        echo "  - Default allow outgoing"
        echo "  - Allow SSH on port $SSH_PORT"
        
        # Prompt for extra ports
        EXTRA_PORTS=$(prompt_input "Additional ports to open (comma-separated, e.g., 80,443)" "")
        if [[ -n "$EXTRA_PORTS" ]]; then
            echo "  - Allow additional ports: $EXTRA_PORTS"
        fi
        echo ""
    else
        # Reset UFW to defaults
        # REASONING: Start with a clean slate to ensure no unexpected rules exist
        print_info "Resetting UFW to default configuration..."
        ufw --force reset &>/dev/null
        
        # Set default policies
        # REASONING: Deny all incoming by default - whitelist approach is more secure
        #            Allow outgoing so server can reach internet (updates, APIs, etc.)
        ufw default deny incoming &>/dev/null
        ufw default allow outgoing &>/dev/null
        print_success "Default policies set: deny incoming, allow outgoing"
        
        # Allow SSH port FIRST before enabling firewall
        # WARNING: Enabling UFW without allowing SSH will lock you out!
        # REASONING: This is the most critical rule - always allow your SSH port
        print_info "Allowing SSH on port $SSH_PORT..."
        ufw allow "$SSH_PORT/tcp" comment 'SSH Access' &>/dev/null
        print_success "SSH (port $SSH_PORT) allowed through firewall"
        log_action "UFW: Allowed SSH on port $SSH_PORT"
        
        # Prompt for additional ports
        echo ""
        print_info "Common ports: 80 (HTTP), 443 (HTTPS), 3000 (Node), 5432 (PostgreSQL)"
        EXTRA_PORTS=$(prompt_input "Additional ports to open (comma-separated, or press Enter for none)" "")
        
        if [[ -n "$EXTRA_PORTS" ]]; then
            # Parse comma-separated ports
            IFS=',' read -ra PORTS <<< "$EXTRA_PORTS"
            for port in "${PORTS[@]}"; do
                # Trim whitespace
                port=$(echo "$port" | xargs)
                
                # Validate port
                if [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 ]] && [[ "$port" -le 65535 ]]; then
                    ufw allow "$port/tcp" &>/dev/null
                    print_success "Allowed port $port"
                    log_action "UFW: Allowed port $port"
                else
                    print_warning "Invalid port skipped: $port"
                fi
            done
        fi
        
        # Enable UFW
        # REASONING: --force flag prevents interactive prompt
        print_info "Enabling UFW firewall..."
        ufw --force enable &>/dev/null
        print_success "UFW firewall is now active"
        log_action "UFW enabled"
        
        # Show current rules
        echo ""
        print_info "Current firewall rules:"
        ufw status numbered
    fi
    
    print_success "Firewall configuration completed"
}


# ============================================================================
# SECTION: FAIL2BAN INSTALLATION
# ============================================================================
# PURPOSE: Automatically block IPs that show malicious behavior
#
# WHY THIS MATTERS:
#   Even with SSH hardening, attackers will continue trying to brute-force
#   their way in. Fail2ban monitors log files and automatically bans IPs
#   that fail authentication too many times.
#
# HOW IT WORKS:
#   1. Monitors /var/log/auth.log for failed SSH attempts
#   2. Counts failures per IP address
#   3. After X failures in Y minutes, blocks the IP using iptables
#   4. Automatically unbans after the ban period expires
#
# CONFIGURATION:
#   - maxretry: Number of failures before ban (default: 5)
#   - findtime: Time window to count failures (default: 10 minutes)
#   - bantime: How long to ban the IP (default: 1 hour)
#
# RISK IF NOT CONFIGURED:
#   Attackers can try unlimited passwords from the same IP address.
#   Without fail2ban, brute-force attacks continue indefinitely.
# ============================================================================

setup_fail2ban() {
    print_header "FAIL2BAN INSTALLATION"
    
    echo "# ---------------------------------------------------------------"
    echo "# Fail2ban automatically blocks IPs after repeated failed logins."
    echo "# This stops brute-force attacks by banning attacking IPs."
    echo "# ---------------------------------------------------------------"
    echo ""
    
    # Install fail2ban
    install_package "fail2ban"
    
    # Prompt for ban time
    BAN_TIME=$(prompt_input "Ban duration for attackers (e.g., 1h, 24h, 1d)" "1h")
    
    # Jail configuration
    local jail_local="/etc/fail2ban/jail.local"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would create fail2ban configuration:"
        echo ""
        echo "  SSH jail enabled on port $SSH_PORT"
        echo "  Ban time: $BAN_TIME"
        echo "  Max retry: 5 attempts"
        echo "  Find time: 10 minutes"
        echo ""
    else
        # Backup existing jail.local if it exists
        backup_file "$jail_local"
        
        # Create jail.local with our configuration
        # REASONING: jail.local overrides jail.conf and survives package updates
        #            Never edit jail.conf directly - it gets overwritten on update
        print_info "Creating fail2ban configuration..."
        
        cat > "$jail_local" << EOF
# ============================================================================
# FAIL2BAN CONFIGURATION
# ============================================================================
# This file configures fail2ban to protect SSH from brute-force attacks.
# 
# HOW IT WORKS:
#   When an IP address fails to authenticate 'maxretry' times within
#   'findtime', it gets banned for 'bantime' duration.
#
# CUSTOMIZATION:
#   - Increase bantime for repeat offenders
#   - Decrease maxretry for stricter protection
#   - Add additional jails for other services (nginx, apache, etc.)
# ============================================================================

[DEFAULT]
# bantime - Duration of IP ban
# REASONING: 1 hour is enough to stop most automated attacks while not
#            permanently blocking legitimate users who mistype passwords
bantime = $BAN_TIME

# findtime - Time window to count failures
# REASONING: 10 minutes catches both fast automated attacks and slower
#            manual attempts. Failures older than this are forgotten.
findtime = 10m

# maxretry - Number of failures before ban
# REASONING: 5 attempts allows for typos while catching brute-force.
#            Combined with SSH's MaxAuthTries=3, attacker gets 1-2 connections.
maxretry = 5

# Backend for log monitoring
# REASONING: systemd is the default on Ubuntu 25.04 and provides better
#            integration than polling log files
backend = systemd

# ============================================================================
# SSH JAIL
# ============================================================================
# Protects SSH from brute-force password attacks
# ============================================================================
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = $BAN_TIME

# EXPLANATION:
#   enabled = true     -> This jail is active
#   port = $SSH_PORT   -> Matches our configured SSH port
#   filter = sshd      -> Uses built-in pattern for SSH failures
#   logpath            -> Where to look for failure messages
#   maxretry = 5       -> Ban after 5 failed attempts
#   bantime = $BAN_TIME -> How long to ban the IP
EOF
        
        print_success "Fail2ban configuration created"
        log_action "Created fail2ban jail.local with SSH protection"
        
        # Enable and start fail2ban
        print_info "Starting fail2ban service..."
        systemctl enable fail2ban &>/dev/null
        systemctl restart fail2ban
        
        # Verify fail2ban is running
        if systemctl is-active --quiet fail2ban; then
            print_success "Fail2ban is running and protecting SSH"
            
            # Show current status
            echo ""
            print_info "Fail2ban status:"
            fail2ban-client status sshd 2>/dev/null || print_info "SSH jail will activate on first log entry"
        else
            print_error "Fail2ban failed to start - check logs with: journalctl -u fail2ban"
        fi
    fi
    
    print_success "Fail2ban installation completed"
}


# ============================================================================
# SECTION: AUTOMATIC SECURITY UPDATES
# ============================================================================
# PURPOSE: Automatically install security patches to prevent exploits
#
# WHY THIS MATTERS:
#   New vulnerabilities are discovered constantly. When a security flaw
#   is found in Linux packages, patches are released quickly - but only
#   protect you if you install them. Manual updates often get neglected.
#
# UNATTENDED-UPGRADES:
#   This package automatically downloads and installs security updates.
#   It runs daily and only installs security-related patches, not all updates.
#
# AUTO-REBOOT CONSIDERATION:
#   Some updates (kernel, glibc) require a reboot to take effect.
#   - Enabled: System stays fully patched but may reboot unexpectedly
#   - Disabled: You must manually reboot after kernel updates
#
# RISK IF NOT CONFIGURED:
#   Known vulnerabilities remain unpatched. Attackers actively scan for
#   systems running outdated software with known exploits.
# ============================================================================

setup_auto_updates() {
    print_header "AUTOMATIC SECURITY UPDATES"
    
    echo "# ---------------------------------------------------------------"
    echo "# Automatic updates keep your system patched against vulnerabilities."
    echo "# Only security updates are installed automatically."
    echo "# ---------------------------------------------------------------"
    echo ""
    
    # Install unattended-upgrades
    install_package "unattended-upgrades"
    install_package "apt-listchanges"
    
    # Configuration files
    local auto_upgrades_conf="/etc/apt/apt.conf.d/20auto-upgrades"
    local unattended_conf="/etc/apt/apt.conf.d/50unattended-upgrades"
    
    # Prompt for auto-reboot
    echo ""
    print_info "Some updates require a reboot to take effect (kernel, glibc)."
    print_warning "Auto-reboot means your server may restart without warning."
    echo ""
    
    if prompt_yes_no "Enable automatic reboot after updates if required?" "n"; then
        AUTO_REBOOT=true
        local reboot_time
        reboot_time=$(prompt_input "Preferred reboot time (24h format, e.g., 03:00)" "03:00")
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would configure automatic security updates:"
        echo ""
        echo "  - Enable daily security update checks"
        echo "  - Auto-download and install security patches"
        echo "  - Auto-reboot: $AUTO_REBOOT"
        [[ "$AUTO_REBOOT" == true ]] && echo "  - Reboot time: $reboot_time"
        echo ""
    else
        # Backup existing configs
        backup_file "$auto_upgrades_conf"
        backup_file "$unattended_conf"
        
        # Configure automatic updates
        print_info "Configuring automatic updates..."
        
        # Create 20auto-upgrades
        cat > "$auto_upgrades_conf" << 'EOF'
// ============================================================================
// AUTOMATIC UPDATES CONFIGURATION
// ============================================================================
// This file enables the automatic update system.
//
// APT::Periodic::Update-Package-Lists
//   How often to refresh package lists (days). 1 = daily.
//
// APT::Periodic::Unattended-Upgrade
//   How often to run unattended-upgrades (days). 1 = daily.
// ============================================================================

APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF
        
        print_success "Auto-upgrades configuration created"
        
        # Configure unattended-upgrades
        # Start with default and modify specific settings
        if [[ "$AUTO_REBOOT" == true ]]; then
            # Enable auto-reboot
            if [[ -f "$unattended_conf" ]]; then
                # Modify existing config
                sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false"|Unattended-Upgrade::Automatic-Reboot "true"|' "$unattended_conf"
                sed -i 's|//Unattended-Upgrade::Automatic-Reboot-Time "02:00"|Unattended-Upgrade::Automatic-Reboot-Time "'"$reboot_time"'"|' "$unattended_conf"
                
                # Handle case where lines aren't commented
                sed -i 's|Unattended-Upgrade::Automatic-Reboot "false"|Unattended-Upgrade::Automatic-Reboot "true"|' "$unattended_conf"
            fi
            print_success "Auto-reboot enabled at $reboot_time"
            log_action "Automatic updates configured with auto-reboot at $reboot_time"
        else
            print_info "Auto-reboot disabled - manually reboot after kernel updates"
            log_action "Automatic updates configured without auto-reboot"
        fi
        
        # Enable the service
        print_info "Enabling unattended-upgrades service..."
        systemctl enable unattended-upgrades &>/dev/null
        systemctl restart unattended-upgrades
        
        print_success "Automatic security updates enabled"
        
        # Run a dry-run to verify configuration
        echo ""
        print_info "Verifying configuration (this may take a moment)..."
        unattended-upgrade --dry-run --debug 2>&1 | head -20 || true
    fi
    
    print_success "Automatic updates configuration completed"
}


# ============================================================================
# SECTION: SECURITY AUDITING TOOLS
# ============================================================================
# PURPOSE: Install tools to monitor and audit system security
#
# WHY THIS MATTERS:
#   Security isn't "set and forget." You need tools to:
#   - Detect if your system has been compromised
#   - Identify configuration weaknesses
#   - Monitor for rootkits and malware
#
# TOOLS INSTALLED:
#   rkhunter (Rootkit Hunter):
#     Scans for known rootkits, backdoors, and suspicious files.
#     Compares critical system files against known-good signatures.
#
#   lynis:
#     Comprehensive security auditing tool. Checks hundreds of security
#     settings and provides recommendations for hardening.
#
# SCHEDULED SCANS:
#   Weekly cron job runs both tools and logs results for review.
#
# RISK IF NOT CONFIGURED:
#   Compromises may go undetected. Attackers often install rootkits that
#   hide their presence from normal system tools.
# ============================================================================

setup_security_auditing() {
    print_header "SECURITY AUDITING TOOLS"
    
    echo "# ---------------------------------------------------------------"
    echo "# Security auditing tools help detect compromises and weaknesses."
    echo "# Regular scans catch problems before they become disasters."
    echo "# ---------------------------------------------------------------"
    echo ""
    
    # Create audit log directory
    if [[ "$DRY_RUN" == false ]]; then
        mkdir -p "$AUDIT_LOG_DIR"
        chmod 700 "$AUDIT_LOG_DIR"
        print_success "Created audit log directory: $AUDIT_LOG_DIR"
    else
        print_info "Would create audit log directory: $AUDIT_LOG_DIR"
    fi
    
    # Install rkhunter
    # REASONING: Rootkit Hunter detects known rootkits and suspicious file changes
    print_info "Installing rkhunter (Rootkit Hunter)..."
    install_package "rkhunter"
    
    if [[ "$DRY_RUN" == false ]]; then
        # Update rkhunter database
        print_info "Updating rkhunter database..."
        rkhunter --update &>/dev/null || true
        
        # Set baseline
        print_info "Creating rkhunter baseline (this takes a moment)..."
        rkhunter --propupd &>/dev/null || true
        
        print_success "rkhunter installed and configured"
        log_action "Installed and configured rkhunter"
    fi
    
    # Install lynis
    # REASONING: Lynis provides comprehensive security auditing and recommendations
    print_info "Installing lynis (Security Auditing)..."
    install_package "lynis"
    
    if [[ "$DRY_RUN" == false ]]; then
        print_success "lynis installed"
        log_action "Installed lynis"
    fi
    
    # Create weekly scan script
    # REASONING: Regular automated scans catch issues you might miss
    local scan_script="/etc/cron.weekly/security-audit"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would create weekly security scan cron job"
    else
        print_info "Creating weekly security scan schedule..."
        
        cat > "$scan_script" << 'EOF'
#!/bin/bash
# ============================================================================
# WEEKLY SECURITY AUDIT SCRIPT
# ============================================================================
# This script runs automatically every week to check for security issues.
# Results are logged to /var/log/security-audit/
#
# WHAT IT CHECKS:
#   - Rootkit Hunter: Known rootkits, backdoors, suspicious files
#   - Lynis: System hardening, configuration issues, best practices
# ============================================================================

AUDIT_DIR="/var/log/security-audit"
DATE=$(date +%Y%m%d)

# Run rkhunter scan
# REASONING: Detects rootkits and compares system files against known-good values
echo "Running rkhunter scan..."
rkhunter --check --skip-keypress --report-warnings-only > "$AUDIT_DIR/rkhunter-$DATE.log" 2>&1

# Run lynis audit
# REASONING: Comprehensive security audit with hardening recommendations  
echo "Running lynis audit..."
lynis audit system --quiet > "$AUDIT_DIR/lynis-$DATE.log" 2>&1

# Keep only last 4 weeks of logs
# REASONING: Prevent disk space from filling up with old audit logs
find "$AUDIT_DIR" -name "*.log" -mtime +28 -delete

echo "Security audit completed. Check $AUDIT_DIR for results."
EOF
        
        chmod +x "$scan_script"
        print_success "Weekly security scan scheduled"
        log_action "Created weekly security audit cron job"
    fi
    
    # Offer to run initial scan
    echo ""
    if prompt_yes_no "Run initial security scan now? (takes 2-5 minutes)" "n"; then
        if [[ "$DRY_RUN" == false ]]; then
            print_info "Running lynis audit (this takes a few minutes)..."
            echo ""
            
            # Run lynis with limited output
            lynis audit system --quick 2>/dev/null | tail -30
            
            echo ""
            print_success "Initial scan complete"
            print_info "Full report saved to: /var/log/lynis-report.dat"
        else
            print_info "Would run initial security scan"
        fi
    fi
    
    print_success "Security auditing tools installation completed"
}


# ============================================================================
# SECTION: SUMMARY AND COMPLETION
# ============================================================================
# PURPOSE: Display summary of all changes made and next steps
#
# WHY THIS MATTERS:
#   Users need to know exactly what changed and how to access their server.
#   This section provides a clear summary and important reminders.
# ============================================================================

show_summary() {
    print_header "SECURITY HARDENING COMPLETE"
    
    echo "All security configurations have been applied to your system."
    echo ""
    
    # Summary of changes
    echo -e "${GREEN}Summary of Changes:${NC}"
    echo "─────────────────────────────────────────────────────────────"
    
    [[ "$CREATED_USER" == true ]] && echo "  ✓ Created sudo user: $NEW_USERNAME"
    echo "  ✓ SSH hardened on port: $SSH_PORT"
    [[ -n "$SSH_KEY_PATH" ]] && echo "  ✓ Password authentication disabled (key-based only)"
    echo "  ✓ UFW firewall enabled"
    echo "  ✓ Fail2ban protecting SSH (ban time: $BAN_TIME)"
    echo "  ✓ Automatic security updates enabled"
    echo "  ✓ Security auditing tools installed"
    echo ""
    
    # Connection information
    echo -e "${YELLOW}Connection Information:${NC}"
    echo "─────────────────────────────────────────────────────────────"
    echo ""
    echo "  SSH Command:"
    echo "    ssh ${NEW_USERNAME:-root}@<your-server-ip> -p $SSH_PORT"
    echo ""
    
    # Important reminders
    echo -e "${YELLOW}Important Reminders:${NC}"
    echo "─────────────────────────────────────────────────────────────"
    echo ""
    echo "  1. TEST SSH access in a NEW terminal before closing this session!"
    echo ""
    echo "  2. Backup location: $BACKUP_DIR"
    echo "     (Contains original configs if you need to rollback)"
    echo ""
    echo "  3. View logs: $LOG_FILE"
    echo ""
    echo "  4. Check fail2ban status: sudo fail2ban-client status sshd"
    echo ""
    echo "  5. View firewall rules: sudo ufw status"
    echo ""
    echo "  6. Run security audit: sudo lynis audit system"
    echo ""
    
    # Final warning
    print_warning "Do NOT close this terminal until you've verified SSH access!"
    echo ""
}


# ============================================================================
# SECTION: COMMAND LINE ARGUMENT PARSING
# ============================================================================
# PURPOSE: Handle --dry-run and --quiet flags
#
# WHY THIS MATTERS:
#   - --dry-run: Preview all changes without applying them (safe testing)
#   - --quiet: Use all defaults for automated/scripted deployments
#   - --help: Show usage information
# ============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                print_warning "DRY-RUN MODE: No changes will be made"
                shift
                ;;
            --quiet)
                QUIET_MODE=true
                print_info "QUIET MODE: Using all default values"
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    echo ""
    echo "Ubuntu 25.04 VPS Security Hardening Script v$SCRIPT_VERSION"
    echo ""
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --dry-run    Preview all changes without applying them"
    echo "  --quiet      Use default values for all prompts (unattended mode)"
    echo "  --help, -h   Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0              # Interactive mode (recommended)"
    echo "  sudo $0 --dry-run    # Preview changes"
    echo "  sudo $0 --quiet      # Automated deployment with defaults"
    echo ""
}


# ============================================================================
# SECTION: MAIN EXECUTION
# ============================================================================
# PURPOSE: Orchestrate all security hardening steps in the correct order
#
# ORDER MATTERS:
#   1. Pre-flight checks first (verify we can proceed)
#   2. User management (create user before SSH lockdown)
#   3. SSH hardening (secure remote access)
#   4. Firewall (allow SSH before enabling)
#   5. Fail2ban (protect the services we've exposed)
#   6. Auto-updates (keep everything patched)
#   7. Auditing (monitor for problems)
#   8. Summary (show what changed)
# ============================================================================

main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Display welcome message
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║          Ubuntu 25.04 VPS Security Hardening Script                ║"
    echo "║                        Version $SCRIPT_VERSION                            ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Initialize logging
    init_logging
    
    # Create backup directory
    create_backup_dir
    
    # Run all hardening steps in order
    preflight_checks
    setup_user_management
    setup_ssh_hardening
    setup_firewall
    setup_fail2ban
    setup_auto_updates
    setup_security_auditing
    
    # Show completion summary
    show_summary
    
    log_action "Security hardening session completed successfully"
}

# Run main function with all arguments
main "$@"
