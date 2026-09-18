#!/usr/bin/env bash
#
# setup-wazuh.sh
# Wazuh SIEM/XDR Lab Setup Wizard
#
# Interactive wrapper around Wazuh's official all-in-one installer
# (wazuh-install.sh) that adds: pre-flight OS/hardware checks, a
# confirmation summary before anything is installed, idempotency
# (detects an existing install instead of blindly re-running), safe
# credential handling, UFW firewall rules scoped to what Wazuh actually
# needs, and honest post-install validation (service state + listening
# ports + a real HTTPS check against the dashboard).
#
# This installs Wazuh Indexer + Wazuh Manager (server) + Wazuh Dashboard
# on a SINGLE host ("all-in-one"), which is the right topology for a lab,
# a small fleet, or a proof of concept. It does not set up a multi-node
# cluster.
#
# Run as root:  sudo ./setup-wazuh.sh
#   or with CLI pre-fill: sudo ./setup-wazuh.sh --version 4.14 --no-ufw
#
# Companion to setup-lab-server.sh. Run them on separate hosts (or at
# least be aware both scripts may want port 443 -- see the note in the
# summary step below).

set -uo pipefail
# Same error-handling philosophy as setup-lab-server.sh: no bare 'set -e'.
# Each stage checks the exit status of the commands that matter and
# records failures, so the wizard always finishes with an honest report
# rather than dying silently partway through a 15-minute install.

# =============================================================================
# GLOBAL STATE
# =============================================================================
SCRIPT_VERSION="1.0"
LOG_FILE="/var/log/wazuh-lab-setup.log"
WORK_DIR="/opt/wazuh-lab-setup"
CRED_FILE="/root/wazuh-credentials.txt"
MARKER_FILE="/etc/wazuh-lab-setup.installed"

WAZUH_VERSION=""        # e.g. 4.14  (major.minor -- matches packages.wazuh.com path layout)
REPORT_HOST=""          # IP/hostname shown in the final report links (display only)
ENABLE_UFW=""           # yes/no
FORCE_REINSTALL="no"

ALREADY_INSTALLED="no"

CLI_VERSION=""; CLI_UFW=""; CLI_HOST=""; CLI_FORCE="no"

FAILURES=()
declare -A VALIDATION
declare -A SERVICE_STATE

# =============================================================================
# LOGGING HELPERS  (identical convention to setup-lab-server.sh)
# =============================================================================
log()   { echo -e "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE" >/dev/null; echo -e "$*"; }
info()  { log "\e[36m[INFO]\e[0m $*"; }
ok()    { log "\e[32m[ OK ]\e[0m $*"; }
warn()  { log "\e[33m[WARN]\e[0m $*"; }
err()   { log "\e[31m[ERROR]\e[0m $*"; FAILURES+=("$*"); }
stage() { echo; log "\e[35m$*\e[0m"; }
# secret() writes to the terminal ONLY -- never to the log file, so
# credentials never end up on disk in plaintext logs.
secret() { echo -e "$*"; }

# =============================================================================
# BASIC SAFETY CHECKS
# =============================================================================
require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Please run this script with sudo." >&2
        exit 1
    fi
}

check_os() {
    info "Checking operating system..."
    local id="" ver=""
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        id="${ID:-unknown}"
        ver="${VERSION_ID:-unknown}"
    fi

    case "$id-$ver" in
        ubuntu-20.04|ubuntu-22.04|ubuntu-24.04)
            ok "Ubuntu ${ver} is officially supported by Wazuh."
            return 0
            ;;
    esac

    warn "This script targets Ubuntu 20.04 / 22.04 / 24.04 LTS, which Wazuh officially supports."
    warn "Detected: ID='${id}' VERSION='${ver}'."
    read -r -p "Continue anyway on this unsupported OS? [y/N]: " ans
    if [[ "${ans,,}" != "y" ]]; then
        echo "Aborting. Re-run on a supported Ubuntu LTS release."
        exit 1
    fi
}

check_resources() {
    info "Checking hardware resources against Wazuh's minimums..."
    local ram_mb cpu_cores disk_gb
    ram_mb=$(free -m | awk '/^Mem:/{print $2}')
    cpu_cores=$(nproc)
    disk_gb=$(df -BG --output=avail / | tail -n1 | tr -dc '0-9')

    echo "  RAM:    ${ram_mb} MB   (minimum: 4096 MB, recommended: 8192 MB)"
    echo "  CPU:    ${cpu_cores} cores (minimum: 2, recommended: 4)"
    echo "  Disk:   ${disk_gb} GB free on / (minimum: 50 GB)"

    local short=0
    (( ram_mb < 4096 ))  && { warn "RAM is below the 4 GB minimum."; short=1; }
    (( cpu_cores < 2 ))  && { warn "CPU core count is below the 2-core minimum."; short=1; }
    (( disk_gb < 50 ))   && { warn "Free disk space is below the 50 GB minimum -- the vulnerability"; \
                               warn "detection database alone can use ~7.5 GB during initial import."; short=1; }

    if [[ "$short" -eq 1 ]]; then
        read -r -p "Resources are below Wazuh's stated minimums. Continue anyway? [y/N]: " ans
        if [[ "${ans,,}" != "y" ]]; then
            echo "Aborting. Provision a larger host and re-run."
            exit 1
        fi
    else
        ok "Hardware resources meet Wazuh's minimum requirements."
    fi
}

# =============================================================================
# IDEMPOTENCY: detect an existing install instead of blindly re-running
# =============================================================================
detect_existing_install() {
    if [[ -f "$MARKER_FILE" ]] || systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-manager\.service'; then
        ALREADY_INSTALLED="yes"
    fi
}

# =============================================================================
# CLI ARGUMENT PARSING
# =============================================================================
print_help() {
    cat <<EOF
Wazuh SIEM/XDR Lab Setup Wizard v${SCRIPT_VERSION}

Usage: sudo ./setup-wazuh.sh [options]

Options (all optional -- omitted values are collected interactively):
  --version X.Y        Wazuh major.minor version to install (default: 4.14)
  --host NAME           IP/hostname to show in the final report links only
  --ufw / --no-ufw      Enable/disable UFW firewall rules for Wazuh ports
  --force                Reinstall even if Wazuh is already detected on this host
  -h, --help             Show this help and exit

Even with flags supplied, the wizard still shows a full summary and
requires explicit confirmation before installing anything.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version) CLI_VERSION="${2:-}"; shift 2 ;;
            --host) CLI_HOST="${2:-}"; shift 2 ;;
            --ufw) CLI_UFW="yes"; shift ;;
            --no-ufw) CLI_UFW="no"; shift ;;
            --force) CLI_FORCE="yes"; shift ;;
            -h|--help) print_help; exit 0 ;;
            *) echo "Unknown option: $1"; print_help; exit 1 ;;
        esac
    done
}

# =============================================================================
# GENERIC PROMPT HELPERS  (same pattern as setup-lab-server.sh)
# =============================================================================
prompt_value() {
    local prompt="$1" default="$2" __outvar="$3" validator="${4:-}"
    local input
    while true; do
        if [[ -n "$default" ]]; then
            read -r -p "${prompt} [${default}]: " input
            input="${input:-$default}"
        else
            read -r -p "${prompt}: " input
        fi
        if [[ -n "$validator" ]] && [[ -n "$input" ]] && ! "$validator" "$input"; then
            echo "  -> Invalid value. Please try again."
            continue
        fi
        printf -v "$__outvar" '%s' "$input"
        break
    done
}

prompt_yn() {
    local prompt="$1" default="${2:-N}" input suffix
    suffix="[y/N]"; [[ "${default^^}" == "Y" ]] && suffix="[Y/n]"
    read -r -p "${prompt} ${suffix}: " input
    input="${input:-$default}"
    [[ "${input,,}" == "y" ]]
}

is_valid_wazuh_version() { [[ "$1" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; }

# =============================================================================
# WIZARD
# =============================================================================
show_banner() {
    cat <<'EOF'
===============================================
 Wazuh SIEM/XDR Lab Setup Wizard
===============================================

This wizard installs (all-in-one, single host):

  - Wazuh Indexer   (OpenSearch-based storage/search)
  - Wazuh Manager   (analysis engine + agent enrollment)
  - Wazuh Dashboard (HTTPS web UI on port 443)

All configuration values will be collected first.

No installation happens until you confirm.

Press ENTER to use the default value.
EOF
    echo
}

wizard_collect() {
    echo "--- Wazuh Version ---"
    prompt_value "Wazuh major.minor version to install" "${CLI_VERSION:-4.14}" WAZUH_VERSION is_valid_wazuh_version
    # normalize a full x.y.z down to x.y for the packages.wazuh.com path
    if [[ "$WAZUH_VERSION" =~ ^([0-9]+\.[0-9]+)\.[0-9]+$ ]]; then
        WAZUH_VERSION="${BASH_REMATCH[1]}"
    fi
    echo

    echo "--- Reporting ---"
    local detected_ip
    detected_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    prompt_value "IP/hostname to show in the final report (display only, does not change binding)" "${CLI_HOST:-${detected_ip:-localhost}}" REPORT_HOST
    echo

    echo "--- Firewall ---"
    if [[ "$CLI_UFW" == "yes" ]]; then ENABLE_UFW="yes";
    elif [[ "$CLI_UFW" == "no" ]]; then ENABLE_UFW="no";
    elif prompt_yn "Enable UFW firewall rules for Wazuh (443, 1514, 1515, 55000)?" "Y"; then ENABLE_UFW="yes"; else ENABLE_UFW="no"; fi
    echo

    if [[ "$ALREADY_INSTALLED" == "yes" ]]; then
        warn "An existing Wazuh installation was detected on this host (wazuh-manager.service or ${MARKER_FILE} found)."
        if [[ "$CLI_FORCE" == "yes" ]]; then
            FORCE_REINSTALL="yes"
            warn "--force was supplied: will re-run the installer anyway. This can regenerate certificates"
            warn "and passwords, breaking already-enrolled agents."
        elif prompt_yn "Skip installation and just re-run validation against the existing install?" "Y"; then
            FORCE_REINSTALL="no"
        else
            if prompt_yn "Are you SURE you want to force a reinstall? This can break existing agents." "N"; then
                FORCE_REINSTALL="yes"
            else
                FORCE_REINSTALL="no"
            fi
        fi
    fi
}

show_summary() {
    cat <<EOF

===============================================
 Configuration Summary
===============================================

Wazuh version        : ${WAZUH_VERSION} (all-in-one: indexer + manager + dashboard)
Existing install      : $( [[ "$ALREADY_INSTALLED" == "yes" ]] && echo "DETECTED" || echo "none detected" )
Action                : $( if [[ "$ALREADY_INSTALLED" == "yes" && "$FORCE_REINSTALL" == "no" ]]; then echo "validate existing install only"; else echo "install"; fi )
Report host label     : ${REPORT_HOST}
UFW firewall rules     : $( [[ "$ENABLE_UFW" == "yes" ]] && echo Enabled || echo Disabled )

Ports this installs/uses:
  443    Dashboard HTTPS (web UI)
  1514   Agent event traffic
  1515   Agent enrollment
  55000  Wazuh API
  9200   Indexer (loopback only -- not opened externally)

Note: if this host is also running setup-lab-server.sh's Apache HTTPS
vhost, both services will want port 443 -- run them on separate hosts,
or disable HTTPS in one of them.

===============================================
EOF
}

confirm_or_exit() {
    read -r -p "Continue? [y/N]: " ans
    if [[ "${ans,,}" != "y" ]]; then
        echo "No changes have been made. Exiting."
        exit 0
    fi
}

# =============================================================================
# INSTALL
# =============================================================================
download_installer() {
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR" || { err "Could not enter $WORK_DIR"; return 1; }

    local url="https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
    info "Downloading Wazuh installer from $url ..."
    rm -f wazuh-install.sh
    if ! curl -fsSL -o wazuh-install.sh "$url"; then
        err "Failed to download $url -- check the version number and network access."
        return 1
    fi

    # Basic sanity check before executing anything as root: it should be a
    # non-trivial shell script, not an HTML error page or empty file.
    if [[ ! -s wazuh-install.sh ]] || ! head -n1 wazuh-install.sh | grep -q '^#!'; then
        err "Downloaded file does not look like a valid shell script -- refusing to execute it."
        return 1
    fi
    chmod 750 wazuh-install.sh
    ok "Installer downloaded and passed a basic sanity check."
}

run_installer() {
    info "Running the Wazuh all-in-one installer (this typically takes 10-20 minutes)..."
    cd "$WORK_DIR" || { err "Could not enter $WORK_DIR"; return 1; }

    if bash ./wazuh-install.sh -a 2>&1 | tee -a "$LOG_FILE"; then
        ok "wazuh-install.sh completed."
        SERVICE_STATE[install]="ok"
        date > "$MARKER_FILE"
    else
        err "wazuh-install.sh exited with an error -- see $LOG_FILE."
        SERVICE_STATE[install]="failed"
        return 1
    fi
}

save_credentials() {
    info "Extracting generated admin credentials..."
    cd "$WORK_DIR" || return 1

    if [[ ! -f wazuh-install-files.tar ]]; then
        warn "wazuh-install-files.tar not found -- cannot extract credentials automatically."
        warn "If this was a fresh install, check the installer output above for the admin password."
        return 0
    fi

    local tmp
    tmp=$(mktemp)
    if tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt > "$tmp" 2>>"$LOG_FILE"; then
        install -m 600 -o root -g root "$tmp" "$CRED_FILE"
        rm -f "$tmp"
        ok "Credentials saved to ${CRED_FILE} (root-readable only)."
        local admin_line
        admin_line=$(grep -A1 "'admin'" "$CRED_FILE" 2>/dev/null | tr '\n' ' ')
        secret ""
        secret "=========================================================="
        secret " Wazuh dashboard admin credentials (also saved to ${CRED_FILE})"
        secret "=========================================================="
        secret "  URL:  https://${REPORT_HOST}"
        if [[ -n "$admin_line" ]]; then
            secret "  ${admin_line}"
        else
            secret "  (could not parse the admin line automatically -- see ${CRED_FILE})"
        fi
        secret "=========================================================="
        secret "Retrieve it again later with:"
        secret "  sudo cat ${CRED_FILE}"
        secret ""
    else
        rm -f "$tmp"
        err "Could not extract wazuh-passwords.txt from wazuh-install-files.tar."
    fi

    # wazuh-install-files.tar itself contains all the generated
    # certs/passwords in the clear; move it out of the world's way.
    mkdir -p /root/wazuh-install-files
    mv -f wazuh-install-files.tar /root/wazuh-install-files/ 2>/dev/null || true
    chmod 700 /root/wazuh-install-files
}

# =============================================================================
# FIREWALL
# =============================================================================
configure_firewall() {
    if [[ "$ENABLE_UFW" != "yes" ]]; then
        info "UFW configuration skipped (disabled in wizard)."
        SERVICE_STATE[ufw]="skipped"
        return 0
    fi
    if ! command -v ufw >/dev/null 2>&1; then
        warn "ufw is not installed on this host; skipping firewall configuration."
        SERVICE_STATE[ufw]="skipped (ufw not installed)"
        return 0
    fi

    info "Configuring UFW firewall for Wazuh..."

    ufw allow 22/tcp comment 'SSH' >/dev/null
    if ufw status | grep -qw "22/tcp"; then
        ok "SSH rule confirmed present in UFW ruleset."
    else
        err "SSH rule could not be confirmed — refusing to enable UFW to avoid lockout."
        SERVICE_STATE[ufw]="failed"
        return 1
    fi

    ufw allow 443/tcp comment 'Wazuh dashboard' >/dev/null
    ufw allow 1514/tcp comment 'Wazuh agent events' >/dev/null
    ufw allow 1515/tcp comment 'Wazuh agent enrollment' >/dev/null
    ufw allow 55000/tcp comment 'Wazuh API' >/dev/null
    # 9200 (indexer) is intentionally NOT opened: it should only ever be
    # reached from the manager on the same host in a single-node install.

    if ufw status | grep -q "Status: active"; then
        ok "UFW already active; rules updated."
    else
        ufw --force enable
        ok "UFW enabled with Wazuh service rules."
    fi
    SERVICE_STATE[ufw]="configured"
}

# =============================================================================
# VALIDATION
# =============================================================================
check_service() {
    local svc="$1" label="$2"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        ok "$label ($svc) is active."
        VALIDATION["svc_${svc}"]="PASS"
    else
        err "$label ($svc) is NOT active. Check 'journalctl -u ${svc}'."
        VALIDATION["svc_${svc}"]="FAIL"
    fi
}

check_listening() {
    local port="$1" label="$2" scope="${3:-any}"
    local pattern="[.:]${port}[[:space:]]"
    if [[ "$scope" == "loopback" ]]; then
        if ss -tuln 2>/dev/null | grep -E "127\.0\.0\.1[.:]${port}[[:space:]]" >/dev/null; then
            ok "Port ${port} (${label}) is listening on loopback, as expected for a single-node install."
            VALIDATION["port_${port}"]="PASS"
        else
            err "Port ${port} (${label}) is NOT listening on loopback."
            VALIDATION["port_${port}"]="FAIL"
        fi
    else
        if ss -tuln 2>/dev/null | grep -qE "$pattern"; then
            ok "Port ${port} (${label}) is listening."
            VALIDATION["port_${port}"]="PASS"
        else
            err "Port ${port} (${label}) is NOT listening."
            VALIDATION["port_${port}"]="FAIL"
        fi
    fi
}

check_dashboard_https() {
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -k --max-time 10 "https://localhost" 2>/dev/null || echo "000")
    if [[ "$code" == "200" || "$code" == "302" ]]; then
        ok "Dashboard responded with HTTP $code over HTTPS."
        VALIDATION[dashboard_https]="PASS"
    else
        err "Dashboard HTTPS check returned HTTP $code (expected 200 or 302)."
        VALIDATION[dashboard_https]="FAIL"
    fi
}

run_validation() {
    stage "===== Running validation tests ====="

    echo "--- Services ---"
    check_service wazuh-indexer "Wazuh Indexer"
    check_service wazuh-manager "Wazuh Manager"
    check_service wazuh-dashboard "Wazuh Dashboard"
    check_service filebeat "Filebeat"

    echo "--- Ports ---"
    check_listening 9200 "Indexer" loopback
    check_listening 1514 "Agent events"
    check_listening 1515 "Agent enrollment"
    check_listening 55000 "Wazuh API"
    check_listening 443 "Dashboard HTTPS"

    echo "--- Dashboard HTTPS ---"
    check_dashboard_https

    echo "--- Firewall ---"
    if [[ "$ENABLE_UFW" == "yes" ]] && command -v ufw >/dev/null 2>&1; then
        ufw status verbose | tee -a "$LOG_FILE"
    else
        echo "UFW rules not configured by this script -- skipped."
    fi
}

# =============================================================================
# FINAL REPORT
# =============================================================================
print_summary() {
    cat <<EOF

===============================================
 WAZUH SETUP COMPLETE
===============================================

Dashboard:
  https://${REPORT_HOST}

Credentials:
  ${CRED_FILE}  (root-readable only; retrieve with: sudo cat ${CRED_FILE})

Certificates / install artifacts:
  /root/wazuh-install-files/wazuh-install-files.tar

Enroll an agent (run on the endpoint you want to monitor, adjust for its OS):
  curl -so wazuh-agent.deb https://packages.wazuh.com/${WAZUH_VERSION}/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}.0-1_amd64.deb
  sudo WAZUH_MANAGER='${REPORT_HOST}' dpkg -i ./wazuh-agent.deb
  sudo systemctl enable --now wazuh-agent
  (check the exact current package filename on the Wazuh downloads page --
   patch versions change; the manager address above is what matters.)

Service status:
EOF
    printf "  %-18s %s\n" "wazuh-indexer" "${VALIDATION[svc_wazuh-indexer]:-not tested}"
    printf "  %-18s %s\n" "wazuh-manager" "${VALIDATION[svc_wazuh-manager]:-not tested}"
    printf "  %-18s %s\n" "wazuh-dashboard" "${VALIDATION[svc_wazuh-dashboard]:-not tested}"
    printf "  %-18s %s\n" "filebeat" "${VALIDATION[svc_filebeat]:-not tested}"

    echo
    echo "Validation test results:"
    local key
    for key in "${!VALIDATION[@]}"; do
        printf "  %-20s %s\n" "$key" "${VALIDATION[$key]}"
    done | sort

    echo
    echo "==============================================="
    if [[ ${#FAILURES[@]} -gt 0 ]]; then
        echo "The following issues were detected during setup:"
        for f in "${FAILURES[@]}"; do
            echo "  - $f"
        done
        echo
        echo "Full log: $LOG_FILE"
        echo "Review the sections above before considering this deployment ready."
    else
        echo "No failures reported."
        echo "Full log: $LOG_FILE"
    fi
    echo "==============================================="
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    parse_args "$@"

    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    require_root
    check_os
    check_resources
    detect_existing_install

    show_banner
    wizard_collect
    show_summary
    confirm_or_exit

    if [[ "$ALREADY_INSTALLED" == "yes" && "$FORCE_REINSTALL" == "no" ]]; then
        stage "[1/3] Existing install detected -- skipping installation."
        info "Re-running validation and firewall configuration against the current install."
    else
        stage "[1/3] Downloading and running the Wazuh all-in-one installer..."
        if download_installer; then
            run_installer
            save_credentials
        fi
    fi

    stage "[2/3] Configuring firewall..."
    configure_firewall

    stage "[3/3] Running validation tests..."
    run_validation

    print_summary
}

main "$@"
