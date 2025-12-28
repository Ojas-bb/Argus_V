#!/usr/bin/env bash
#
# ARGUS_V Raspberry Pi Installation Script
#
# This script installs and configures the ARGUS_V security telemetry and response stack
# on Raspberry Pi OS (or other Debian-based systems).
#
# Usage:
#   sudo ./install.sh                    # Interactive installation
#   sudo ./install.sh --non-interactive  # Non-interactive with defaults
#   sudo ./install.sh --help            # Show help
#

set -e  # Exit on error
set -u  # Exit on undefined variable

# Color output for better visibility
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Installation configuration
INSTALL_DIR="/opt/argus_v"
CONFIG_DIR="/etc/argus_v"
DATA_DIR="/var/lib/argus_v"
LOG_DIR="/var/log/argus_v"
RUN_DIR="/var/run/argus_v"
VENV_DIR="${INSTALL_DIR}/venv"
SYSTEMD_DIR="/etc/systemd/system"

# Script/runtime metadata
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Repository settings (used when install.sh is run standalone)
REPO_URL_DEFAULT="https://github.com/Ojas-bb/Argus_V.git"
REPO_REF_DEFAULT="main"
REPO_URL="${ARGUS_REPO_URL:-$REPO_URL_DEFAULT}"
REPO_REF="${ARGUS_REPO_REF:-$REPO_REF_DEFAULT}"

# Selected python interpreter (resolved during checks)
PYTHON_BIN="python3"

# Runtime files
RETINA_LOG_FILE="$LOG_DIR/retina.log"
RETINA_ERR_FILE="$LOG_DIR/retina.err"
MNEMOSYNE_LOG_FILE="$LOG_DIR/mnemosyne.log"
MNEMOSYNE_ERR_FILE="$LOG_DIR/mnemosyne.err"
AEGIS_LOG_FILE="$LOG_DIR/aegis.log"
AEGIS_ERR_FILE="$LOG_DIR/aegis.err"

CRON_MNEMOSYNE_WEEKLY="/etc/cron.weekly/argus-v-mnemosyne-train"

# Installation defaults
DEFAULT_INTERFACE="eth0"
DEFAULT_ENABLE_FIREBASE="false"
DEFAULT_ENABLE_RETINA="true"
DEFAULT_ENABLE_MNEMOSYNE="false"
DEFAULT_ENABLE_AEGIS="false"
DEFAULT_INSTALL_USER="argus"
DEFAULT_RETINA_OUTPUT_DIR="${DATA_DIR}/retina"
DEFAULT_MODELS_DIR="${DATA_DIR}/models"
DEFAULT_SCALERS_DIR="${DATA_DIR}/scalers"

# Command line flags
NON_INTERACTIVE=false
SKIP_DEPENDENCIES=false
SKIP_SERVICES=false
UNINSTALL=false

# Helper functions
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

die() {
    error "$1"
    exit 1
}

# Print banner
print_banner() {
    cat << "EOF"
    ___    ____  ____________  _______   __
   /   |  / __ \/ ____/ / / / / ___/ | / /
  / /| | / /_/ / / __/ / / / /\__ \| |/ / 
 / ___ |/ _, _/ /_/ / /_/ /_____/ /|   /  
/_/  |_/_/ |_|\____/\____(_)____/_/ |_/   
                                           
Security Telemetry and Response Stack
Installation Script for Raspberry Pi
EOF
    echo ""
}

# Show help
show_help() {
    cat << EOF
ARGUS_V Installation Script

Usage: sudo ./install.sh [OPTIONS]

Options:
  --non-interactive    Run installation without prompts (use defaults)
  --skip-dependencies  Skip dependency installation
  --skip-services      Skip systemd service installation
  --repo URL           Git repository to clone (default: $REPO_URL_DEFAULT)
  --ref REF            Git ref/branch/tag to checkout (default: $REPO_REF_DEFAULT)
  --uninstall          Uninstall ARGUS_V
  --help               Show this help message

Interactive Installation:
  The script will prompt for configuration options including:
  - Network interface to monitor
  - Firebase integration settings
  - Which components to enable (Retina, Mnemosyne, Aegis)

Non-interactive Installation:
  Uses default values for all configuration options.
  Suitable for automated deployments.

Examples:
  # Interactive installation
  sudo ./install.sh

  # Automated installation with defaults
  sudo ./install.sh --non-interactive

  # Uninstall ARGUS_V
  sudo ./install.sh --uninstall

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --non-interactive)
                NON_INTERACTIVE=true
                shift
                ;;
            --skip-dependencies)
                SKIP_DEPENDENCIES=true
                shift
                ;;
            --skip-services)
                SKIP_SERVICES=true
                shift
                ;;
            --repo)
                REPO_URL="$2"
                shift 2
                ;;
            --ref)
                REPO_REF="$2"
                shift 2
                ;;
            --uninstall)
                UNINSTALL=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)"
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME=$NAME
        OS_VERSION=$VERSION_ID
        info "Detected OS: $OS_NAME $OS_VERSION"
        
        # Check if Debian-based
        if [[ ! "$ID_LIKE" =~ "debian" ]] && [[ "$ID" != "debian" ]] && [[ "$ID" != "raspbian" ]]; then
            warn "This script is designed for Debian-based systems (Raspberry Pi OS)"
            warn "Your system: $OS_NAME"
            if [[ "$NON_INTERACTIVE" == "false" ]]; then
                read -p "Continue anyway? (y/N): " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    exit 1
                fi
            fi
        fi
    else
        warn "Unable to detect OS. Proceeding with caution..."
    fi
}

# Check Python version
check_python() {
    info "Checking Python version..."

    local candidates=()
    if command -v python3.11 &>/dev/null; then
        candidates+=("python3.11")
    fi
    if command -v python3 &>/dev/null; then
        candidates+=("python3")
    fi

    if [[ ${#candidates[@]} -eq 0 ]]; then
        die "Python 3 is not installed. Please install Python 3.11 or later."
    fi

    PYTHON_BIN="${candidates[0]}"

    local major minor
    major=$($PYTHON_BIN -c 'import sys; print(sys.version_info[0])')
    minor=$($PYTHON_BIN -c 'import sys; print(sys.version_info[1])')
    PYTHON_VERSION=$($PYTHON_BIN -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')

    info "Found Python ${PYTHON_VERSION} ($PYTHON_BIN)"

    if [[ $major -lt 3 ]] || [[ $major -eq 3 && $minor -lt 8 ]]; then
        die "Python 3.8 or later is required. Found: ${PYTHON_VERSION}"
    fi

    if [[ $minor -lt 11 ]]; then
        warn "ARGUS_V requires Python 3.11+ (your system has ${PYTHON_VERSION})."

        if [[ "$SKIP_DEPENDENCIES" == "false" ]]; then
            info "Attempting to install Python 3.11 via apt..."
            apt-get update -qq
            if apt-get install -y -qq python3.11 python3.11-venv python3.11-dev; then
                if command -v python3.11 &>/dev/null; then
                    PYTHON_BIN="python3.11"
                    major=$($PYTHON_BIN -c 'import sys; print(sys.version_info[0])')
                    minor=$($PYTHON_BIN -c 'import sys; print(sys.version_info[1])')
                    PYTHON_VERSION=$($PYTHON_BIN -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
                    info "Using Python ${PYTHON_VERSION} ($PYTHON_BIN)"
                fi
            else
                warn "Unable to install python3.11 packages from apt repositories."
            fi
        fi
    fi

    major=$($PYTHON_BIN -c 'import sys; print(sys.version_info[0])')
    minor=$($PYTHON_BIN -c 'import sys; print(sys.version_info[1])')

    if [[ $major -ne 3 ]] || [[ $minor -lt 11 ]]; then
        die "Python 3.11+ is required to run this ARGUS_V build. Please upgrade Python and re-run the installer."
    fi

    success "Python version check passed (${PYTHON_BIN})"
}

# Install system dependencies
install_dependencies() {
    if [[ "$SKIP_DEPENDENCIES" == "true" ]]; then
        info "Skipping dependency installation"
        return
    fi
    
    info "Installing system dependencies..."
    
    apt-get update -qq
    
    # Essential build tools
    apt-get install -y -qq \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        git \
        curl \
        iptables \
        libpcap-dev \
        tcpdump \
        || die "Failed to install system dependencies"
    
    success "System dependencies installed"
}

# Detect available network interfaces
detect_interfaces() {
    info "Detecting network interfaces..."
    
    INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' || echo "eth0")
    
    if [[ -z "$INTERFACES" ]]; then
        warn "No network interfaces detected (excluding loopback)"
        INTERFACES="eth0"
    fi
    
    echo "Available interfaces:"
    echo "$INTERFACES" | while read -r iface; do
        echo "  - $iface"
    done
}

# Get configuration interactively
get_interactive_config() {
    info "Starting interactive configuration..."
    echo ""
    
    # Detect interfaces first
    detect_interfaces
    echo ""
    
    # Network interface
    read -p "Network interface to monitor [$DEFAULT_INTERFACE]: " INTERFACE
    INTERFACE=${INTERFACE:-$DEFAULT_INTERFACE}
    
    # Enable components
    read -p "Enable Retina (packet capture)? (Y/n): " ENABLE_RETINA_INPUT
    if [[ "$ENABLE_RETINA_INPUT" =~ ^[Nn]$ ]]; then
        ENABLE_RETINA="false"
    else
        ENABLE_RETINA="true"
    fi
    
    read -p "Enable Mnemosyne (model training)? (y/N): " ENABLE_MNEMOSYNE_INPUT
    if [[ "$ENABLE_MNEMOSYNE_INPUT" =~ ^[Yy]$ ]]; then
        ENABLE_MNEMOSYNE="true"
    else
        ENABLE_MNEMOSYNE="false"
    fi
    
    read -p "Enable Aegis (enforcement)? (y/N): " ENABLE_AEGIS_INPUT
    if [[ "$ENABLE_AEGIS_INPUT" =~ ^[Yy]$ ]]; then
        ENABLE_AEGIS="true"
    else
        ENABLE_AEGIS="false"
    fi
    
    # Firebase configuration
    read -p "Enable Firebase integration? (y/N): " ENABLE_FIREBASE_INPUT
    if [[ "$ENABLE_FIREBASE_INPUT" =~ ^[Yy]$ ]]; then
        ENABLE_FIREBASE="true"
        read -p "Firebase Project ID: " FIREBASE_PROJECT_ID
        read -p "Firebase Storage Bucket: " FIREBASE_STORAGE_BUCKET
        read -p "Firebase Service Account JSON path: " FIREBASE_SERVICE_ACCOUNT
    else
        ENABLE_FIREBASE="false"
        FIREBASE_PROJECT_ID=""
        FIREBASE_STORAGE_BUCKET=""
        FIREBASE_SERVICE_ACCOUNT=""
    fi
    
    # IP salt for anonymization
    RANDOM_SALT=$(openssl rand -hex 32 2>/dev/null || echo "change_this_salt_in_production_$(date +%s)")
    read -p "IP anonymization salt [randomly generated]: " IP_SALT
    IP_SALT=${IP_SALT:-$RANDOM_SALT}
    
    echo ""
    info "Configuration summary:"
    echo "  Interface: $INTERFACE"
    echo "  Retina: $ENABLE_RETINA"
    echo "  Mnemosyne: $ENABLE_MNEMOSYNE"
    echo "  Aegis: $ENABLE_AEGIS"
    echo "  Firebase: $ENABLE_FIREBASE"
    echo ""
    
    read -p "Proceed with installation? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        info "Installation cancelled"
        exit 0
    fi
}

# Get configuration non-interactively
get_noninteractive_config() {
    info "Using non-interactive configuration (defaults)"
    
    INTERFACE=$DEFAULT_INTERFACE
    ENABLE_FIREBASE=$DEFAULT_ENABLE_FIREBASE
    ENABLE_RETINA=$DEFAULT_ENABLE_RETINA
    ENABLE_MNEMOSYNE=$DEFAULT_ENABLE_MNEMOSYNE
    ENABLE_AEGIS=$DEFAULT_ENABLE_AEGIS
    FIREBASE_PROJECT_ID=""
    FIREBASE_STORAGE_BUCKET=""
    FIREBASE_SERVICE_ACCOUNT=""
    IP_SALT=$(openssl rand -hex 32 2>/dev/null || echo "change_this_salt_in_production_$(date +%s)")
}

# Create system user
create_user() {
    if id "$DEFAULT_INSTALL_USER" &>/dev/null; then
        info "User $DEFAULT_INSTALL_USER already exists"
    else
        info "Creating system user: $DEFAULT_INSTALL_USER"
        useradd --system --no-create-home --shell /bin/false "$DEFAULT_INSTALL_USER" \
            || die "Failed to create user $DEFAULT_INSTALL_USER"
        success "User created"
    fi
}

# Create directory structure
create_directories() {
    info "Creating directory structure..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"/{retina,models,scalers,aegis}
    mkdir -p "$LOG_DIR"
    mkdir -p "$RUN_DIR"
    
    # Set permissions
    chown -R "$DEFAULT_INSTALL_USER:$DEFAULT_INSTALL_USER" "$DATA_DIR"
    chown -R "$DEFAULT_INSTALL_USER:$DEFAULT_INSTALL_USER" "$LOG_DIR"
    chown -R "$DEFAULT_INSTALL_USER:$DEFAULT_INSTALL_USER" "$RUN_DIR"
    chmod 755 "$CONFIG_DIR"
    chmod 750 "$DATA_DIR"
    chmod 750 "$LOG_DIR"
    chmod 755 "$RUN_DIR"

    # Pre-create log files for systemd file logging
    touch "$RETINA_LOG_FILE" "$RETINA_ERR_FILE" \
          "$MNEMOSYNE_LOG_FILE" "$MNEMOSYNE_ERR_FILE" \
          "$AEGIS_LOG_FILE" "$AEGIS_ERR_FILE"

    chown root:root "$RETINA_LOG_FILE" "$RETINA_ERR_FILE" "$AEGIS_LOG_FILE" "$AEGIS_ERR_FILE"
    chown "$DEFAULT_INSTALL_USER:$DEFAULT_INSTALL_USER" "$MNEMOSYNE_LOG_FILE" "$MNEMOSYNE_ERR_FILE"
    chmod 0640 "$RETINA_LOG_FILE" "$RETINA_ERR_FILE" "$MNEMOSYNE_LOG_FILE" "$MNEMOSYNE_ERR_FILE" "$AEGIS_LOG_FILE" "$AEGIS_ERR_FILE"
    
    success "Directories created"
}

# Install Python package
install_package() {
    info "Installing ARGUS_V Python package..."
    
    # Determine if we're in a git repo or extracted tarball
    if [[ -f "$SCRIPT_DIR/pyproject.toml" ]]; then
        PACKAGE_DIR="$SCRIPT_DIR"
    elif [[ -f "pyproject.toml" ]]; then
        PACKAGE_DIR=$(pwd)
    else
        info "Cannot find local source tree - cloning from GitHub..."
        local clone_dir="$INSTALL_DIR/source"
        rm -rf "$clone_dir"
        git clone "$REPO_URL" "$clone_dir" || die "Failed to clone repository: $REPO_URL"
        if [[ -n "$REPO_REF" ]]; then
            git -C "$clone_dir" checkout "$REPO_REF" || die "Failed to checkout ref: $REPO_REF"
        fi
        PACKAGE_DIR="$clone_dir"
    fi
    
    info "Using package directory: $PACKAGE_DIR"
    
    # Create virtual environment
    info "Creating Python virtual environment with $PYTHON_BIN..."
    "$PYTHON_BIN" -m venv "$VENV_DIR" || die "Failed to create virtual environment"
    
    # Activate venv and install
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    pip install --quiet --upgrade pip setuptools wheel
    
    # Install package
    info "Installing ARGUS_V package (this may take a few minutes)..."
    pip install --quiet -e "$PACKAGE_DIR" || die "Failed to install ARGUS_V package"
    
    # Install additional production dependencies
    pip install --quiet joblib || warn "Failed to install joblib"
    
    success "ARGUS_V package installed"
}

# Generate Retina configuration
generate_retina_config() {
    info "Generating Retina configuration..."
    
    cat > "$CONFIG_DIR/retina.yaml" << EOF
# ARGUS_V Retina Configuration
# Auto-generated on $(date)

retina:
  enabled: $ENABLE_RETINA
  
  # Capture settings
  capture:
    interface: "$INTERFACE"
    snaplen: 65535
    promiscuous: true
    timeout_ms: 100
    buffer_size_mb: 10
    use_scapy: true
  
  # Aggregation settings
  aggregation:
    window_seconds: 5
    output_dir: "$DEFAULT_RETINA_OUTPUT_DIR"
    max_rows_per_file: 10000
    file_rotation_count: 10
  
  # Health monitoring
  health:
    max_drop_rate_percent: 1.0
    max_flow_queue_size: 1000
    alert_cooldown_seconds: 300
    enable_drop_monitoring: true
    enable_queue_monitoring: true
  
  # Anonymization - IMPORTANT: Keep this secret!
  ip_salt: "$IP_SALT"
EOF
    
    chmod 600 "$CONFIG_DIR/retina.yaml"
    chown root:root "$CONFIG_DIR/retina.yaml"
    
    success "Retina configuration created"
}

# Generate Mnemosyne configuration
generate_mnemosyne_config() {
    info "Generating Mnemosyne configuration..."
    
    cat > "$CONFIG_DIR/mnemosyne.yaml" << EOF
# ARGUS_V Mnemosyne Configuration
# Auto-generated on $(date)

EOF
    
    if [[ "$ENABLE_FIREBASE" == "true" ]]; then
        cat >> "$CONFIG_DIR/mnemosyne.yaml" << EOF
# Firebase Configuration
firebase:
  project_id: "$FIREBASE_PROJECT_ID"
  storage_bucket: "$FIREBASE_STORAGE_BUCKET"
  service_account_path: "$FIREBASE_SERVICE_ACCOUNT"
  training_data_path: "flows/training"
  model_output_path: "models"
  cleanup_threshold_hours: 24
  request_timeout_seconds: 30

EOF
    else
        cat >> "$CONFIG_DIR/mnemosyne.yaml" << EOF
# Firebase Configuration (disabled)
# Uncomment and configure to enable Firebase integration
# firebase:
#   project_id: "your-firebase-project-id"
#   storage_bucket: "your-project-id.appspot.com"
#   service_account_path: "~/.config/gcloud/service-account.json"
#   training_data_path: "flows/training"
#   model_output_path: "models"
#   cleanup_threshold_hours: 24
#   request_timeout_seconds: 30

EOF
    fi
    
    cat >> "$CONFIG_DIR/mnemosyne.yaml" << EOF
# Preprocessing Configuration
preprocessing:
  log_transform_features:
    - bytes_in
    - bytes_out
    - packets_in
    - packets_out
    - duration
  
  feature_normalization_method: standard
  contamination_auto_tune: true
  contamination_range: [0.01, 0.1]
  min_samples_for_training: 1000
  max_model_size_mb: 100

# Model Training Configuration
training:
  random_state: 42
  n_estimators_range: [50, 200]
  max_samples_range: [0.5, 1.0]
  bootstrap_options: [true, false]
  validation_split: 0.2
  cross_validation_folds: 3
EOF
    
    chmod 600 "$CONFIG_DIR/mnemosyne.yaml"
    chown root:root "$CONFIG_DIR/mnemosyne.yaml"
    
    success "Mnemosyne configuration created"
}

# Generate Aegis configuration
generate_aegis_config() {
    info "Generating Aegis configuration..."
    
    cat > "$CONFIG_DIR/aegis.yaml" << EOF
# ARGUS_V Aegis Configuration
# Auto-generated on $(date)

# Model Management Configuration
model:
  model_local_path: "$DEFAULT_MODELS_DIR"
  scaler_local_path: "$DEFAULT_SCALERS_DIR"
  min_model_age_hours: 1
  max_model_age_days: 30
  use_fallback_model: true
  fallback_prediction_threshold: 0.7
  model_download_timeout: 300
  scaler_download_timeout: 60

# Retina CSV Polling Configuration
polling:
  poll_interval_seconds: 5
  csv_directory: "$DEFAULT_RETINA_OUTPUT_DIR"
  batch_size: 100
  processed_file_suffix: ".processed"
  max_poll_errors: 5
  poll_retry_delay: 30

# Prediction and Scoring Configuration
prediction:
  feature_columns:
    - bytes_in
    - bytes_out
    - packets_in
    - packets_out
    - duration
    - src_port
    - dst_port
    - protocol
  
  anomaly_threshold: 0.7
  high_risk_threshold: 0.9
  max_flows_per_batch: 1000
  prediction_timeout: 30
  use_gpu: false
  enable_parallel_processing: true
  max_workers: 4

# Blacklist Enforcement Configuration  
enforcement:
  dry_run_duration_days: 7
  enforce_after_dry_run: false
  iptables_chain_name: "AEGIS-DROP"
  iptables_table: "filter"
  iptables_chain_position: 1
  blacklist_default_ttl_hours: 24
  max_blacklist_entries: 10000
  blacklist_cleanup_interval: 3600
  emergency_stop_file: "$RUN_DIR/aegis.emergency"
  allow_manual_overrides: true

# Runtime Service Configuration
runtime:
  log_level: "INFO"
  state_file: "$DATA_DIR/aegis/state.json"
  stats_file: "$DATA_DIR/aegis/stats.json"
  pid_file: "$RUN_DIR/aegis.pid"
  health_check_port: 8080
  shutdown_timeout: 30

# Interface Configuration
interfaces:
  firebase:
    enabled: $ENABLE_FIREBASE
EOF
    
    if [[ "$ENABLE_FIREBASE" == "true" ]]; then
        cat >> "$CONFIG_DIR/aegis.yaml" << EOF

# Firebase Configuration
firebase:
  project_id: "$FIREBASE_PROJECT_ID"
  storage_bucket: "$FIREBASE_STORAGE_BUCKET"
  service_account_path: "$FIREBASE_SERVICE_ACCOUNT"
EOF
    fi
    
    chmod 600 "$CONFIG_DIR/aegis.yaml"
    chown root:root "$CONFIG_DIR/aegis.yaml"
    
    success "Aegis configuration created"
}

# Create systemd service for Retina
create_retina_service() {
    if [[ "$SKIP_SERVICES" == "true" ]] || [[ "$ENABLE_RETINA" != "true" ]]; then
        return
    fi
    
    info "Creating Retina systemd service..."
    
    cat > "$SYSTEMD_DIR/argus-retina.service" << EOF
[Unit]
Description=ARGUS_V Retina - Network Packet Capture Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$VENV_DIR/bin/python -m argus_v.retina.cli --config $CONFIG_DIR/retina.yaml daemon
Restart=always
RestartSec=10
EnvironmentFile=-$CONFIG_DIR/secrets.env
StandardOutput=append:$RETINA_LOG_FILE
StandardError=append:$RETINA_ERR_FILE
SyslogIdentifier=argus-retina

# Security settings
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR $RUN_DIR

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    success "Retina service created"
}

# Create systemd service for Mnemosyne (weekly training)
create_mnemosyne_service() {
    if [[ "$SKIP_SERVICES" == "true" ]] || [[ "$ENABLE_MNEMOSYNE" != "true" ]]; then
        return
    fi
    
    info "Creating Mnemosyne systemd service..."
    
    # Create service
    cat > "$SYSTEMD_DIR/argus-mnemosyne.service" << EOF
[Unit]
Description=ARGUS_V Mnemosyne - Model Training Pipeline
After=network.target

[Service]
Type=oneshot
User=$DEFAULT_INSTALL_USER
Group=$DEFAULT_INSTALL_USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$VENV_DIR/bin/python -m argus_v.mnemosyne.cli --config $CONFIG_DIR/mnemosyne.yaml train
EnvironmentFile=-$CONFIG_DIR/secrets.env
StandardOutput=append:$MNEMOSYNE_LOG_FILE
StandardError=append:$MNEMOSYNE_ERR_FILE
SyslogIdentifier=argus-mnemosyne

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR

[Install]
WantedBy=multi-user.target
EOF
    
    # Create weekly retraining cron job
    cat > "$CRON_MNEMOSYNE_WEEKLY" << 'CRONEOF'
#!/bin/sh
set -e

# Trigger weekly training via systemd service
systemctl start argus-mnemosyne.service >/dev/null 2>&1 || true
CRONEOF
    chmod 0755 "$CRON_MNEMOSYNE_WEEKLY"
    
    systemctl daemon-reload
    success "Mnemosyne service created (weekly training via cron)"
}

# Create systemd service for Aegis
create_aegis_service() {
    if [[ "$SKIP_SERVICES" == "true" ]] || [[ "$ENABLE_AEGIS" != "true" ]]; then
        return
    fi
    
    info "Creating Aegis systemd service..."
    
    cat > "$SYSTEMD_DIR/argus-aegis.service" << EOF
[Unit]
Description=ARGUS_V Aegis - Security Enforcement Service
After=network.target argus-retina.service
Wants=network-online.target
Requires=argus-retina.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$VENV_DIR/bin/python -m argus_v.aegis.cli --config $CONFIG_DIR/aegis.yaml start
ExecStop=$VENV_DIR/bin/python -m argus_v.aegis.cli --config $CONFIG_DIR/aegis.yaml stop
Restart=always
RestartSec=10
EnvironmentFile=-$CONFIG_DIR/secrets.env
StandardOutput=append:$AEGIS_LOG_FILE
StandardError=append:$AEGIS_ERR_FILE
SyslogIdentifier=argus-aegis

# Security settings (needs root for iptables)
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR $RUN_DIR

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    success "Aegis service created"
}

# Setup log rotation
setup_logrotate() {
    info "Setting up log rotation..."
    
    cat > "/etc/logrotate.d/argus_v" << EOF
$LOG_DIR/*.log $LOG_DIR/*.err {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    create 0640 $DEFAULT_INSTALL_USER $DEFAULT_INSTALL_USER
}
EOF
    
    success "Log rotation configured"
}

# Enable and start services
enable_services() {
    if [[ "$SKIP_SERVICES" == "true" ]]; then
        return
    fi
    
    info "Enabling and starting services..."
    
    if [[ "$ENABLE_RETINA" == "true" ]]; then
        systemctl enable argus-retina.service
        systemctl start argus-retina.service || warn "Failed to start Retina service"
        success "Retina service enabled and started"
    fi
    
    if [[ "$ENABLE_MNEMOSYNE" == "true" ]]; then
        success "Mnemosyne weekly training scheduled via cron: $CRON_MNEMOSYNE_WEEKLY"
    fi
    
    if [[ "$ENABLE_AEGIS" == "true" ]]; then
        systemctl enable argus-aegis.service
        systemctl start argus-aegis.service || warn "Failed to start Aegis service"
        success "Aegis service enabled and started"
    fi
}

# Show status
show_status() {
    echo ""
    info "Installation Status:"
    echo ""
    
    if [[ "$ENABLE_RETINA" == "true" ]]; then
        echo "Retina Service:"
        systemctl status argus-retina.service --no-pager -l || true
        echo ""
    fi
    
    if [[ "$ENABLE_MNEMOSYNE" == "true" ]]; then
        echo "Mnemosyne Training:"
        echo "  Scheduled weekly via $CRON_MNEMOSYNE_WEEKLY"
        echo ""
    fi
    
    if [[ "$ENABLE_AEGIS" == "true" ]]; then
        echo "Aegis Service:"
        systemctl status argus-aegis.service --no-pager -l || true
        echo ""
    fi
}

# Main installation
main_install() {
    print_banner
    
    check_root
    detect_os
    check_python
    install_dependencies
    
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        get_noninteractive_config
    else
        get_interactive_config
    fi
    
    create_user
    create_directories
    install_package
    
    generate_retina_config
    generate_mnemosyne_config
    generate_aegis_config
    
    create_retina_service
    create_mnemosyne_service
    create_aegis_service
    
    setup_logrotate
    enable_services
    
    echo ""
    success "======================================"
    success "ARGUS_V Installation Complete!"
    success "======================================"
    echo ""
    info "Configuration files: $CONFIG_DIR"
    info "Data directory: $DATA_DIR"
    info "Log directory: $LOG_DIR"
    echo ""
    info "Useful commands:"
    echo "  sudo systemctl status argus-retina"
    echo "  sudo systemctl status argus-aegis"
    echo "  sudo systemctl list-timers argus-*"
    echo "  sudo journalctl -u argus-retina -f"
    echo ""
    
    if [[ "$SKIP_SERVICES" != "true" ]]; then
        show_status
    fi
    
    if [[ "$ENABLE_AEGIS" == "true" ]]; then
        warn "Aegis is in DRY RUN mode for 7 days by default"
        warn "No enforcement will occur until you explicitly enable it"
    fi
}

# Uninstall
main_uninstall() {
    print_banner
    check_root
    
    warn "This will uninstall ARGUS_V and remove all services"
    
    if [[ "$NON_INTERACTIVE" == "false" ]]; then
        read -p "Are you sure you want to continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Uninstall cancelled"
            exit 0
        fi
    fi
    
    info "Stopping and disabling services..."
    systemctl stop argus-retina.service 2>/dev/null || true
    systemctl stop argus-aegis.service 2>/dev/null || true
    systemctl stop argus-mnemosyne.timer 2>/dev/null || true
    systemctl disable argus-retina.service 2>/dev/null || true
    systemctl disable argus-aegis.service 2>/dev/null || true
    systemctl disable argus-mnemosyne.timer 2>/dev/null || true
    
    info "Removing systemd service files..."
    rm -f "$SYSTEMD_DIR/argus-retina.service"
    rm -f "$SYSTEMD_DIR/argus-aegis.service"
    rm -f "$SYSTEMD_DIR/argus-mnemosyne.service"
    rm -f "$SYSTEMD_DIR/argus-mnemosyne.timer"
    systemctl daemon-reload
    
    info "Removing logrotate configuration..."
    rm -f "/etc/logrotate.d/argus_v"
    
    read -p "Remove configuration files from $CONFIG_DIR? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        success "Configuration removed"
    else
        info "Configuration preserved"
    fi
    
    read -p "Remove data directory $DATA_DIR? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$DATA_DIR"
        success "Data directory removed"
    else
        info "Data directory preserved"
    fi
    
    info "Removing installation directory..."
    rm -rf "$INSTALL_DIR"
    
    info "Removing runtime directory..."
    rm -rf "$RUN_DIR"
    
    info "Removing log directory..."
    rm -rf "$LOG_DIR"
    
    success "ARGUS_V uninstalled successfully"
}

# Main entry point
main() {
    parse_args "$@"
    
    if [[ "$UNINSTALL" == "true" ]]; then
        main_uninstall
    else
        main_install
    fi
}

# Run main
main "$@"
