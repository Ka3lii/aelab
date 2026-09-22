#!/usr/bin/env bash
#
# setup-lab-server.sh
# Linux Lab Server Setup Wizard
#
# Interactive, reusable installer/configurator for a private cybersecurity /
# networking lab server: DNS (BIND9) + Web (Apache2) + Mail (Postfix/Dovecot)
# + UFW firewall on Ubuntu Server 24.04 LTS.
#
# This is a refactor of an earlier single-environment script ("setup-aelab.sh")
# that was hard-coded for one lab (10.10.0.1 / aelab.com). Every environment
# -specific value now comes from an interactive wizard (or CLI flags), and the
# security issues found in the original (open recursive DNS, open relay risk,
# plaintext mail auth, unconditional port 443) have been fixed.
#
# Run as root:  sudo ./setup-lab-server.sh
#   or with CLI pre-fill: sudo ./setup-lab-server.sh --ip 192.168.50.10 --cidr 24 \
#                              --gateway 192.168.50.1 --domain cyberlab.local
#
# This script is intended for an isolated, private lab network only.

set -uo pipefail
# NOTE ON ERROR HANDLING:
# We deliberately do NOT use a bare 'set -e'. Each configuration stage below
# checks the exit status of the commands that matter (named-checkconf,
# postfix check, doveconf -n, apache2ctl configtest, systemctl is-active,
# etc.) and records failures in the FAILURES array / VALIDATION map instead
# of dying mid-script. This lets the wizard finish all stages, run full
# validation, and print an honest final report that distinguishes
# "configured" from "validated" -- rather than either silently continuing
# after a real failure (bare set -uo) or aborting halfway through leaving
# services in a partially-configured state (bare set -e).

# =============================================================================
# GLOBAL STATE
# =============================================================================
SCRIPT_VERSION="2.0"
LOG_FILE="/var/log/lab-server-setup.log"
BACKUP_ROOT="/var/backups/lab-server-setup"
BACKUP_DIR=""   # set once we know the run timestamp, in main()

# Environment-specific values. ALL of these are populated by the wizard
# and/or CLI flags below -- nothing here is used directly as configuration.
SERVER_IP=""
NETWORK_CIDR=""
GATEWAY=""
NETWORK_INTERFACE=""

DOMAIN=""
HOSTNAME_FQDN=""
NS_HOSTNAME=""
WWW_HOSTNAME=""
MAIL_HOSTNAME=""

MAIL_TEST_USER=""
MAIL_TEST_USER_PASSWORD=""

ENABLE_HTTPS=""
ENABLE_UFW=""
CONFIGURE_LOCAL_RESOLVER=""

# Derived values (computed after the wizard, never hard-coded)
NETWORK_ADDR=""
REVERSE_ZONE=""
REVERSE_ZONE_FILE_NAME=""
OCT1=""; OCT2=""; OCT3=""; OCT4=""

# CLI pre-fill values (empty = not supplied; wizard will still prompt,
# using these as the shown default so advanced users can just press Enter)
CLI_IP=""; CLI_CIDR=""; CLI_GATEWAY=""; CLI_DOMAIN=""; CLI_IFACE=""
CLI_MAIL_USER=""; CLI_HTTPS=""; CLI_UFW=""; CLI_RESOLVER=""

FAILURES=()
declare -A VALIDATION      # test-name -> PASS/FAIL/SKIP
declare -A SERVICE_STATE   # service-name -> configured/validated status text

# =============================================================================
# LOGGING HELPERS
# =============================================================================
log()   { echo -e "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE" >/dev/null; echo -e "$*"; }
info()  { log "\e[36m[INFO]\e[0m $*"; }
ok()    { log "\e[32m[ OK ]\e[0m $*"; }
warn()  { log "\e[33m[WARN]\e[0m $*"; }
err()   { log "\e[31m[ERROR]\e[0m $*"; FAILURES+=("$*"); }
stage() { echo; log "\e[35m$*\e[0m"; }

# =============================================================================
# BASIC SAFETY CHECKS
# =============================================================================
require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Please run this script with sudo." >&2
        exit 1
    fi
}

OS_ID=""; OS_VERSION=""

check_os() {
    info "Checking operating system..."
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
    fi

    case "${OS_ID}-${OS_VERSION}" in
        ubuntu-24.04)
            ok "Ubuntu 24.04 LTS confirmed."
            return 0
            ;;
        debian-12)
            ok "Debian 12 (bookworm) confirmed."
            return 0
            ;;
        ubuntu-22.04|ubuntu-20.04)
            ok "Ubuntu ${OS_VERSION} confirmed (older LTS -- primarily tested on 24.04, but this"
            ok "should work: package names and service units are unchanged)."
            return 0
            ;;
    esac

    warn "This script is designed and tested for Ubuntu Server 24.04 LTS and Debian 12 (bookworm)."
    warn "Detected: ID='${OS_ID}' VERSION='${OS_VERSION}'."
    warn "Running on an unsupported OS may produce broken or inconsistent results."
    read -r -p "Continue anyway on this unsupported OS? [y/N]: " ans
    if [[ "${ans,,}" != "y" ]]; then
        echo "Aborting. Re-run on Ubuntu Server 24.04 LTS or Debian 12."
        exit 1
    fi
}

# =============================================================================
# GENERIC VALIDATION HELPERS
# =============================================================================
is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local o
    for o in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
        (( o >= 0 && o <= 255 )) || return 1
    done
    return 0
}

is_valid_cidr() {
    local c="$1"
    [[ "$c" =~ ^[0-9]{1,2}$ ]] || return 1
    (( c >= 1 && c <= 32 ))
}

is_valid_domain() {
    local d="$1"
    # dot-separated labels, alnum + hyphen, last label alphabetic, min 2 chars
    # accepts real TLDs as well as lab-style names like .local/.lab/.internal/.test
    [[ "$d" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]
}

is_valid_hostname_label() {
    local h="$1"
    [[ "$h" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]
}

is_valid_username() {
    local u="$1"
    [[ "$u" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

# =============================================================================
# IP MATH (pure bash -- no external ipcalc dependency)
# =============================================================================
ip_to_int() {
    local IFS=.
    local -a o
    read -r -a o <<< "$1"
    echo $(( (o[0] << 24) + (o[1] << 16) + (o[2] << 8) + o[3] ))
}

int_to_ip() {
    local i="$1"
    echo "$(( (i >> 24) & 255 )).$(( (i >> 16) & 255 )).$(( (i >> 8) & 255 )).$(( i & 255 ))"
}

cidr_to_mask_int() {
    local c="$1"
    if (( c == 0 )); then
        echo 0
    else
        echo $(( (0xFFFFFFFF << (32 - c)) & 0xFFFFFFFF ))
    fi
}

compute_network_address() {
    local ip="$1" cidr="$2"
    local ipi maski
    ipi=$(ip_to_int "$ip")
    maski=$(cidr_to_mask_int "$cidr")
    int_to_ip $(( ipi & maski ))
}

cidr_to_netmask() {
    local cidr="$1"
    int_to_ip "$(cidr_to_mask_int "$cidr")"
}

# =============================================================================
# FILE HELPERS (backups + idempotent key/value config editing)
# =============================================================================
backup_file() {
    # backup_file <path>  -- copies into $BACKUP_DIR preserving the path, if it exists
    local f="$1"
    if [[ -e "$f" ]]; then
        mkdir -p "$BACKUP_DIR$(dirname "$f")"
        cp -a "$f" "$BACKUP_DIR$f"
        info "Backed up $f -> $BACKUP_DIR$f"
    fi
}

# set_or_append <file> <key> <value> [separator, default " = "]
# Idempotently sets "key = value" in a simple config file: replaces the line
# if the key already exists (anchored, whole-line match), otherwise appends
# it. Safe to run repeatedly without creating duplicate directives.
set_or_append() {
    local file="$1" key="$2" value="$3" sep="${4:- = }"
    touch "$file"
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
        sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key}${sep}${value}|" "$file"
    else
        echo "${key}${sep}${value}" >> "$file"
    fi
}

pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }

# =============================================================================
# CLI ARGUMENT PARSING
# =============================================================================
print_help() {
    cat <<EOF
Linux Lab Server Setup Wizard v${SCRIPT_VERSION}

Usage: sudo ./setup-lab-server.sh [options]

Options (all optional -- omitted values are collected interactively):
  --ip ADDRESS          Server IPv4 address              (e.g. 192.168.50.10)
  --cidr LENGTH         Network prefix length             (e.g. 24)
  --gateway ADDRESS     Default gateway (blank = isolated lab)
  --interface NAME      Network interface to configure    (e.g. eth0)
  --domain NAME         Lab domain name                   (e.g. cyberlab.local)
  --mail-user NAME      Mail test username                (default: labuser)
  --https / --no-https  Enable/disable HTTPS
  --ufw / --no-ufw      Enable/disable UFW firewall configuration
  --resolver / --no-resolver
                         Enable/disable local DNS resolver configuration
  -h, --help            Show this help and exit

Even when flags are supplied, the wizard still shows the values it will use,
requires explicit confirmation, and never applies network changes without a
separate confirmation. Nothing destructive happens silently.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ip) CLI_IP="${2:-}"; shift 2 ;;
            --cidr) CLI_CIDR="${2:-}"; shift 2 ;;
            --gateway) CLI_GATEWAY="${2:-}"; shift 2 ;;
            --interface) CLI_IFACE="${2:-}"; shift 2 ;;
            --domain) CLI_DOMAIN="${2:-}"; shift 2 ;;
            --mail-user) CLI_MAIL_USER="${2:-}"; shift 2 ;;
            --https) CLI_HTTPS="yes"; shift ;;
            --no-https) CLI_HTTPS="no"; shift ;;
            --ufw) CLI_UFW="yes"; shift ;;
            --no-ufw) CLI_UFW="no"; shift ;;
            --resolver) CLI_RESOLVER="yes"; shift ;;
            --no-resolver) CLI_RESOLVER="no"; shift ;;
            -h|--help) print_help; exit 0 ;;
            *) echo "Unknown option: $1"; print_help; exit 1 ;;
        esac
    done
}

# =============================================================================
# GENERIC PROMPT HELPERS
# =============================================================================
# prompt_value <prompt text> <default (may be empty)> <out var name> [validator fn]
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

# prompt_yn <prompt text> <default Y|N>  -- returns 0 for yes, 1 for no
prompt_yn() {
    local prompt="$1" default="${2:-N}" input suffix
    suffix="[y/N]"; [[ "${default^^}" == "Y" ]] && suffix="[Y/n]"
    read -r -p "${prompt} ${suffix}: " input
    input="${input:-$default}"
    [[ "${input,,}" == "y" ]]
}

# =============================================================================
# WIZARD: BANNER
# =============================================================================
show_banner() {
    cat <<'EOF'
===============================================
 Linux Lab Server Setup Wizard
===============================================

This wizard will configure:

  - BIND9 DNS
  - Apache2 Web Server
  - Postfix SMTP
  - Dovecot IMAP
  - UFW Firewall
  - Optional HTTPS

All configuration values will be collected first.

No system changes will be made until you confirm.

Press ENTER to use the default value.
EOF
    echo
}

# =============================================================================
# WIZARD: NETWORK
# =============================================================================
list_interfaces() {
    ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$'
}

detect_default_interface() {
    local iface
    iface=$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -n1)
    if [[ -z "$iface" ]]; then
        iface=$(list_interfaces | head -n1)
    fi
    echo "$iface"
}

wizard_select_interface() {
    local detected chosen
    detected=$(detect_default_interface)

    mapfile -t IFACES < <(list_interfaces)
    if [[ ${#IFACES[@]} -eq 0 ]]; then
        err "No usable network interfaces detected."
        exit 1
    fi

    if [[ -n "$CLI_IFACE" ]]; then
        detected="$CLI_IFACE"
    fi

    if [[ ${#IFACES[@]} -eq 1 ]]; then
        echo "Detected network interface: ${IFACES[0]}"
        prompt_value "Use this interface" "${IFACES[0]}" NETWORK_INTERFACE
        return
    fi

    echo "Detected network interface: ${detected:-unknown}"
    echo "Multiple network interfaces were found:"
    local i=1
    for iface in "${IFACES[@]}"; do
        echo "  $i) $iface"
        ((i++))
    done
    while true; do
        read -r -p "Select interface to configure [default: ${detected}]: " choice
        if [[ -z "$choice" ]]; then
            NETWORK_INTERFACE="$detected"
            break
        elif [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#IFACES[@]} )); then
            NETWORK_INTERFACE="${IFACES[$((choice-1))]}"
            break
        elif printf '%s\n' "${IFACES[@]}" | grep -qx "$choice"; then
            NETWORK_INTERFACE="$choice"
            break
        else
            echo "  -> Please enter a listed number or interface name."
        fi
    done
}

wizard_network() {
    echo "--- Network Configuration ---"
    wizard_select_interface

    prompt_value "Server IPv4 address" "${CLI_IP:-10.10.0.1}" SERVER_IP is_valid_ipv4
    prompt_value "Network prefix length" "${CLI_CIDR:-24}" NETWORK_CIDR is_valid_cidr
    prompt_value "Default gateway (leave blank for isolated lab)" "${CLI_GATEWAY:-}" GATEWAY
    if [[ -n "$GATEWAY" ]] && ! is_valid_ipv4 "$GATEWAY"; then
        warn "Gateway '$GATEWAY' does not look like a valid IPv4 address; clearing it."
        GATEWAY=""
    fi
    echo
}

# =============================================================================
# WIZARD: DOMAIN + HOSTNAMES
# =============================================================================
wizard_domain_and_hosts() {
    echo "--- Domain Configuration ---"
    if [[ -n "$CLI_DOMAIN" ]]; then
        prompt_value "Domain name" "$CLI_DOMAIN" DOMAIN is_valid_domain
    else
        # No stand-in default here on purpose: this value flows into every
        # BIND zone, vhost, and mail hostname below, so we require the
        # person to actually type their own domain rather than risk them
        # hitting Enter and accepting an unrelated example domain.
        while true; do
            read -r -p "Domain name (e.g. domain.com): " DOMAIN
            if [[ -z "$DOMAIN" ]]; then
                echo "  -> This field is required. Enter the domain name for this lab."
                continue
            fi
            if ! is_valid_domain "$DOMAIN"; then
                echo "  -> Invalid value. Please try again."
                continue
            fi
            break
        done
    fi

    echo
    echo "--- Hostname Configuration ---"
    prompt_value "Server FQDN" "mail.${DOMAIN}" HOSTNAME_FQDN
    prompt_value "DNS hostname" "ns1.${DOMAIN}" NS_HOSTNAME
    prompt_value "Web hostname" "www.${DOMAIN}" WWW_HOSTNAME
    prompt_value "Mail hostname" "mail.${DOMAIN}" MAIL_HOSTNAME
    echo
}

# =============================================================================
# WIZARD: MAIL TEST USER
# =============================================================================
wizard_mail_user() {
    echo "--- Mail Test User ---"
    prompt_value "Mail test username" "${CLI_MAIL_USER:-labuser}" MAIL_TEST_USER is_valid_username

    local pw1 pw2
    while true; do
        read -r -s -p "Mail test user password: " pw1; echo
        if [[ -z "$pw1" ]]; then
            echo "  -> Password cannot be empty."
            continue
        fi
        if (( ${#pw1} < 8 )); then
            echo "  -> Warning: password is shorter than 8 characters."
        fi
        read -r -s -p "Confirm password: " pw2; echo
        if [[ "$pw1" != "$pw2" ]]; then
            echo "  -> Passwords do not match. Try again."
            continue
        fi
        MAIL_TEST_USER_PASSWORD="$pw1"
        break
    done
    pw1=""; pw2=""   # scrub from shell memory as soon as possible
    echo
}

# =============================================================================
# WIZARD: OPTIONAL FEATURES
# =============================================================================
wizard_features() {
    echo "--- Optional Features ---"

    if [[ "$CLI_HTTPS" == "yes" ]]; then ENABLE_HTTPS="yes";
    elif [[ "$CLI_HTTPS" == "no" ]]; then ENABLE_HTTPS="no";
    elif prompt_yn "Configure HTTPS with a self-signed certificate?" "Y"; then ENABLE_HTTPS="yes"; else ENABLE_HTTPS="no"; fi

    if [[ "$CLI_UFW" == "yes" ]]; then ENABLE_UFW="yes";
    elif [[ "$CLI_UFW" == "no" ]]; then ENABLE_UFW="no";
    elif prompt_yn "Enable UFW firewall configuration?" "Y"; then ENABLE_UFW="yes"; else ENABLE_UFW="no"; fi

    if [[ "$CLI_RESOLVER" == "yes" ]]; then CONFIGURE_LOCAL_RESOLVER="yes";
    elif [[ "$CLI_RESOLVER" == "no" ]]; then CONFIGURE_LOCAL_RESOLVER="no";
    elif prompt_yn "Configure this server as the local DNS resolver?" "Y"; then CONFIGURE_LOCAL_RESOLVER="yes"; else CONFIGURE_LOCAL_RESOLVER="no"; fi
    echo
}

# =============================================================================
# DERIVED VALUES
# =============================================================================
compute_derived_values() {
    IFS='.' read -r OCT1 OCT2 OCT3 OCT4 <<< "$SERVER_IP"
    NETWORK_ADDR=$(compute_network_address "$SERVER_IP" "$NETWORK_CIDR")

    # The reverse (PTR) zone is scoped to the /24 that contains SERVER_IP,
    # regardless of what NETWORK_CIDR you chose (/30, /28, /24, /16 ...).
    # This is not an approximation: this script only ever publishes ONE PTR
    # record -- for the server's own address -- and a standard /24
    # in-addr.arpa zone is the correct, valid place to publish it no matter
    # how large or small your actual subnet is. Classless (sub-/24) reverse
    # delegation via RFC 2317 only matters when multiple separate
    # organizations need to split authority over one /24, which doesn't
    # apply here since this server is the sole authority for its own lab.
    REVERSE_ZONE="${OCT3}.${OCT2}.${OCT1}.in-addr.arpa"
    REVERSE_ZONE_FILE_NAME="db.${OCT1}.${OCT2}.${OCT3}"
}

# =============================================================================
# SUMMARY + CONFIRMATION
# =============================================================================
show_summary() {
    cat <<EOF

===============================================
 Configuration Summary
===============================================

Network Interface  : ${NETWORK_INTERFACE}
Server IP           : ${SERVER_IP}/${NETWORK_CIDR}
Gateway              : ${GATEWAY:-<none - isolated lab>}
Computed Network     : ${NETWORK_ADDR}/${NETWORK_CIDR}

Domain              : ${DOMAIN}
Server FQDN         : ${HOSTNAME_FQDN}
DNS Hostname        : ${NS_HOSTNAME}
Web Hostname        : ${WWW_HOSTNAME}
Mail Hostname       : ${MAIL_HOSTNAME}

Mail Test User      : ${MAIL_TEST_USER}@${DOMAIN}

DNS                  : Enabled (BIND9, authoritative + restricted recursion)
Web Server           : Apache2
SMTP                 : Postfix
IMAP                 : Dovecot
HTTPS                : $( [[ "$ENABLE_HTTPS" == "yes" ]] && echo Enabled || echo Disabled )
UFW                  : $( [[ "$ENABLE_UFW" == "yes" ]] && echo Enabled || echo Disabled )
Local DNS Resolver   : $( [[ "$CONFIGURE_LOCAL_RESOLVER" == "yes" ]] && echo Enabled || echo Disabled )

Expected ports:
  22   SSH
  53   DNS TCP/UDP
  80   HTTP
$( [[ "$ENABLE_HTTPS" == "yes" ]] && echo "  443  HTTPS" )
  25   SMTP
  587  SMTP Submission
  993  IMAPS

===============================================
EOF
}

confirm_or_exit() {
    read -r -p "Continue with installation? [y/N]: " ans
    if [[ "${ans,,}" != "y" ]]; then
        echo "No changes have been made. Exiting."
        exit 0
    fi
}

# =============================================================================
# PACKAGE INSTALLATION
# =============================================================================
install_packages() {
    info "Running apt update..."
    apt-get update -qq || { err "apt-get update failed"; return 1; }

    local packages=(bind9 bind9utils bind9-dnsutils apache2 postfix dovecot-core
                     dovecot-imapd ufw dnsutils curl mailutils openssl iproute2)
    local to_install=()
    for p in "${packages[@]}"; do
        if pkg_installed "$p"; then
            ok "$p already installed."
        else
            to_install+=("$p")
        fi
    done

    if [[ ${#to_install[@]} -gt 0 ]]; then
        info "Installing: ${to_install[*]}"
        debconf-set-selections <<< "postfix postfix/main_mailer_type select Internet Site"
        debconf-set-selections <<< "postfix postfix/mailname string ${DOMAIN}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${to_install[@]}" \
            || { err "Package installation failed"; return 1; }
    fi
    ok "All required packages present."
}

# =============================================================================
# NETWORK CONFIGURATION (safe: detect, show, warn, confirm)
# =============================================================================
# Detects which network configuration system is actually in use, since this
# script now targets both Ubuntu (netplan) and Debian (ifupdown by default,
# NetworkManager on some installs). Nothing below assumes one specific tool.
detect_netconf_backend() {
    if command -v netplan >/dev/null 2>&1 && [[ -d /etc/netplan ]]; then
        echo "netplan"
    elif command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager 2>/dev/null; then
        echo "networkmanager"
    elif [[ -d /etc/network ]] && command -v ifup >/dev/null 2>&1; then
        echo "ifupdown"
    else
        echo "unknown"
    fi
}

apply_netplan() {
    local netplan_file="/etc/netplan/90-lab-server.yaml"
    backup_file "$netplan_file"

    {
        echo "network:"
        echo "  version: 2"
        echo "  ethernets:"
        echo "    ${NETWORK_INTERFACE}:"
        echo "      dhcp4: no"
        echo "      addresses: [${SERVER_IP}/${NETWORK_CIDR}]"
        if [[ -n "$GATEWAY" ]]; then
            echo "      routes:"
            echo "        - to: default"
            echo "          via: ${GATEWAY}"
        fi
        echo "      nameservers:"
        echo "        addresses: [127.0.0.1]"
    } > "$netplan_file"
    chmod 600 "$netplan_file"
    ok "Netplan file written to $netplan_file."

    if [[ -t 0 ]]; then
        info "Applying with 'netplan try' (auto-reverts in 45s if not confirmed)..."
        if netplan try --timeout 45; then
            ok "Network configuration applied and confirmed."
            SERVICE_STATE[network]="configured"
        else
            err "netplan try failed or was reverted. Network NOT changed."
            SERVICE_STATE[network]="failed"
            return 1
        fi
    else
        warn "No interactive TTY detected; using 'netplan apply' directly (no auto-revert safety net)."
        if netplan apply; then
            ok "Netplan applied."
            SERVICE_STATE[network]="configured"
        else
            err "netplan apply failed."
            SERVICE_STATE[network]="failed"
            return 1
        fi
    fi
}

# Debian's default (non-cloud) install uses ifupdown with /etc/network/interfaces,
# which -- unlike netplan -- has no built-in "try/auto-revert" safety net.
apply_ifupdown() {
    local if_file="/etc/network/interfaces.d/90-lab-server"
    local main_if="/etc/network/interfaces"

    if [[ -f "$main_if" ]] && ! grep -q "source.*interfaces\.d" "$main_if"; then
        backup_file "$main_if"
        echo "source /etc/network/interfaces.d/*" >> "$main_if"
        info "Added 'source /etc/network/interfaces.d/*' to $main_if so drop-in files are used."
    fi

    mkdir -p /etc/network/interfaces.d
    backup_file "$if_file"
    local netmask
    netmask=$(cidr_to_netmask "$NETWORK_CIDR")
    {
        echo "auto ${NETWORK_INTERFACE}"
        echo "iface ${NETWORK_INTERFACE} inet static"
        echo "    address ${SERVER_IP}"
        echo "    netmask ${netmask}"
        if [[ -n "$GATEWAY" ]]; then
            echo "    gateway ${GATEWAY}"
        fi
        echo "    dns-nameservers 127.0.0.1"
    } > "$if_file"
    ok "ifupdown config written to $if_file (address ${SERVER_IP}, netmask ${netmask})."

    warn "ifupdown has no automatic rollback like 'netplan try'. If this disconnects your"
    warn "SSH session and the new address is unreachable, use console/VM access to restore"
    warn "the backup from $BACKUP_DIR or edit $if_file directly."

    ifdown "$NETWORK_INTERFACE" >>"$LOG_FILE" 2>&1 || warn "ifdown reported an issue (continuing) -- see $LOG_FILE."
    if ifup "$NETWORK_INTERFACE" >>"$LOG_FILE" 2>&1; then
        ok "Interface $NETWORK_INTERFACE brought up with the new address."
        SERVICE_STATE[network]="configured"
    else
        err "ifup failed to bring $NETWORK_INTERFACE up with the new address -- see $LOG_FILE."
        SERVICE_STATE[network]="failed"
        return 1
    fi
}

apply_networkmanager() {
    local con_name
    con_name=$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: -v d="$NETWORK_INTERFACE" '$2==d{print $1; exit}')
    if [[ -z "$con_name" ]]; then
        con_name="lab-server-${NETWORK_INTERFACE}"
        nmcli con add type ethernet ifname "$NETWORK_INTERFACE" con-name "$con_name" >>"$LOG_FILE" 2>&1
    fi

    nmcli con mod "$con_name" ipv4.addresses "${SERVER_IP}/${NETWORK_CIDR}" >>"$LOG_FILE" 2>&1
    nmcli con mod "$con_name" ipv4.method manual >>"$LOG_FILE" 2>&1
    nmcli con mod "$con_name" ipv4.dns "127.0.0.1" >>"$LOG_FILE" 2>&1
    if [[ -n "$GATEWAY" ]]; then
        nmcli con mod "$con_name" ipv4.gateway "$GATEWAY" >>"$LOG_FILE" 2>&1
    else
        nmcli con mod "$con_name" ipv4.gateway "" >>"$LOG_FILE" 2>&1
    fi

    if nmcli con up "$con_name" >>"$LOG_FILE" 2>&1; then
        ok "NetworkManager connection '$con_name' brought up with the new address."
        SERVICE_STATE[network]="configured"
    else
        err "nmcli failed to bring up '$con_name' with the new address -- see $LOG_FILE."
        SERVICE_STATE[network]="failed"
        return 1
    fi
}

configure_network() {
    local current_ip backend
    current_ip=$(ip -o -4 addr show dev "$NETWORK_INTERFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
    backend=$(detect_netconf_backend)

    echo
    echo "=========================================================="
    echo " Interface          : $NETWORK_INTERFACE"
    echo " Current IPv4 on it : ${current_ip:-none}"
    echo " Requested Address  : ${SERVER_IP}/${NETWORK_CIDR}"
    echo " Requested Gateway  : ${GATEWAY:-<none>}"
    echo " Network backend    : ${backend}"
    echo "=========================================================="

    if [[ "$current_ip" == "$SERVER_IP" ]]; then
        ok "Interface $NETWORK_INTERFACE already has the required IP. No network change needed."
        SERVICE_STATE[network]="already configured"
        return 0
    fi

    if [[ "$backend" == "unknown" ]]; then
        err "Could not detect a supported network backend (netplan, ifupdown, or NetworkManager) on this host."
        if [[ "$current_ip" != "$SERVER_IP" ]]; then
            err "Required IP ${SERVER_IP} is not configured on ${NETWORK_INTERFACE}, and it cannot be set automatically."
            echo "Please manually configure ${SERVER_IP}/${NETWORK_CIDR} on ${NETWORK_INTERFACE}, then re-run this script."
            exit 1
        fi
        return 0
    fi

    case "$backend" in
        netplan)
            local other_files
            other_files=$(grep -rl "$NETWORK_INTERFACE" /etc/netplan/*.yaml 2>/dev/null || true)
            if [[ -n "$other_files" ]]; then
                warn "Existing netplan file(s) already reference '$NETWORK_INTERFACE':"
                echo "$other_files" | sed 's/^/    /'
                warn "Review these manually if you see conflicting configuration after applying."
            fi
            ;;
        ifupdown)
            local other_refs
            other_refs=$(grep -rl "$NETWORK_INTERFACE" /etc/network/interfaces /etc/network/interfaces.d/* 2>/dev/null | grep -v "90-lab-server" || true)
            if [[ -n "$other_refs" ]]; then
                warn "Existing ifupdown configuration already references '$NETWORK_INTERFACE':"
                echo "$other_refs" | sed 's/^/    /'
                warn "Review these manually if you see conflicting configuration after applying."
            fi
            ;;
    esac

    echo
    echo "WARNING:"
    echo "Changing the network configuration may disconnect your SSH session."
    echo
    echo "Interface: $NETWORK_INTERFACE"
    echo "Address:   ${SERVER_IP}/${NETWORK_CIDR}"
    echo "Gateway:   ${GATEWAY:-<none - isolated lab>}"
    echo "Backend:   $backend"
    echo
    if ! prompt_yn "Apply this network configuration?" "N"; then
        warn "Automatic network configuration skipped by user."
        if [[ "$current_ip" != "$SERVER_IP" ]]; then
            err "Required IP ${SERVER_IP} is not configured on ${NETWORK_INTERFACE}, and automatic"
            err "network configuration was declined. Continuing would leave DNS/Apache/Postfix"
            err "bound to an address that does not exist on this host."
            echo
            echo "Please either:"
            echo "  1) Manually configure ${SERVER_IP}/${NETWORK_CIDR} on ${NETWORK_INTERFACE}, then re-run this script, or"
            echo "  2) Re-run the wizard and enter the IP address actually assigned to this host."
            exit 1
        fi
        return 0
    fi

    case "$backend" in
        netplan) apply_netplan ;;
        ifupdown) apply_ifupdown ;;
        networkmanager) apply_networkmanager ;;
    esac
}

# =============================================================================
# HOSTNAME / /etc/hosts (kept minimal -- BIND is the source of truth for
# www/mail/ns1 records; /etc/hosts only pins this host's own FQDN so local
# tools like `hostname -f` and Postfix/Dovecot work before BIND is even up)
# =============================================================================
configure_hostname() {
    info "Configuring hostname..."
    backup_file /etc/hostname
    backup_file /etc/hosts

    hostnamectl set-hostname "$HOSTNAME_FQDN"

    local short_name="${HOSTNAME_FQDN%%.*}"
    local marker="# lab-server-setup: primary host entry"
    if grep -q "$marker" /etc/hosts; then
        sed -i "\|$marker|c\\${SERVER_IP} ${HOSTNAME_FQDN} ${short_name} ${marker}" /etc/hosts
    else
        echo "${SERVER_IP} ${HOSTNAME_FQDN} ${short_name} ${marker}" >> /etc/hosts
    fi
    ok "Hostname set to $HOSTNAME_FQDN. /etc/hosts updated with a single, minimal entry."
    SERVICE_STATE[hostname]="configured"
}

# =============================================================================
# TLS CERTIFICATE (shared self-signed cert used by Apache HTTPS, Dovecot
# IMAPS, and Postfix submission STARTTLS -- generated once, reused, and
# scoped with SANs for all the lab hostnames)
# =============================================================================
CERT_DIR="/etc/ssl/lab-server"
CERT_KEY=""
CERT_CRT=""

generate_tls_cert() {
    CERT_KEY="${CERT_DIR}/lab-server.key"
    CERT_CRT="${CERT_DIR}/lab-server.crt"
    mkdir -p "$CERT_DIR"
    chmod 700 "$CERT_DIR"

    if [[ -f "$CERT_KEY" && -f "$CERT_CRT" ]]; then
        ok "TLS certificate already exists at $CERT_CRT -- reusing it (not regenerated)."
        SERVICE_STATE[tls]="already present"
        return 0
    fi

    info "Generating self-signed TLS certificate for ${MAIL_HOSTNAME} / ${WWW_HOSTNAME}..."
    local san_cfg
    san_cfg=$(mktemp)
    cat > "$san_cfg" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = ${MAIL_HOSTNAME}
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${MAIL_HOSTNAME}
DNS.2 = ${WWW_HOSTNAME}
DNS.3 = ${NS_HOSTNAME}
DNS.4 = ${DOMAIN}
DNS.5 = ${HOSTNAME_FQDN}
EOF

    if openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
        -keyout "$CERT_KEY" -out "$CERT_CRT" -config "$san_cfg" >>"$LOG_FILE" 2>&1; then
        chmod 600 "$CERT_KEY"
        chmod 644 "$CERT_CRT"
        ok "TLS certificate generated at $CERT_CRT."
        SERVICE_STATE[tls]="configured"
    else
        err "TLS certificate generation failed -- see $LOG_FILE."
        SERVICE_STATE[tls]="failed"
    fi
    rm -f "$san_cfg"
}

# =============================================================================
# BIND9 (DNS) -- authoritative for the lab domain, with recursion locked
# down to localhost + the configured lab network (never an open resolver)
# =============================================================================
configure_bind9() {
    info "Configuring BIND9..."

    backup_file /etc/bind/named.conf.options
    backup_file /etc/bind/named.conf.local

    cat > /etc/bind/named.conf.options <<EOF
acl "lab-trusted" {
    127.0.0.1;
    ${NETWORK_ADDR}/${NETWORK_CIDR};
};

options {
    directory "/var/cache/bind";

    // Lab resolver: forward anything we're not authoritative for
    forwarders {
        8.8.8.8;
        1.1.1.1;
    };

    listen-on { ${SERVER_IP}; 127.0.0.1; };
    listen-on-v6 { none; };

    // SECURITY: this server answers authoritative queries for the lab
    // domain from anyone, but only performs recursive resolution (and
    // serves its query cache) for localhost and the configured lab
    // network. This prevents it from being abused as an open resolver.
    allow-query { any; };
    allow-recursion { lab-trusted; };
    allow-query-cache { lab-trusted; };
    recursion yes;

    allow-transfer { none; };

    dnssec-validation auto;
};
EOF

    cat > /etc/bind/named.conf.local <<EOF
zone "${DOMAIN}" {
    type master;
    file "/etc/bind/db.${DOMAIN}";
};

zone "${REVERSE_ZONE}" {
    type master;
    file "/etc/bind/${REVERSE_ZONE_FILE_NAME}";
};
EOF

    backup_file "/etc/bind/db.${DOMAIN}"
    local serial
    serial=$(date +%Y%m%d%H)
    cat > "/etc/bind/db.${DOMAIN}" <<EOF
\$TTL    604800
@       IN      SOA     ${NS_HOSTNAME}. admin.${DOMAIN}. (
                              ${serial}   ; Serial (yyyymmddhh)
                              604800      ; Refresh
                              86400       ; Retry
                              2419200     ; Expire
                              604800 )    ; Negative Cache TTL
;
@       IN      NS      ${NS_HOSTNAME}.
@       IN      MX      10 ${MAIL_HOSTNAME}.

@       IN      A       ${SERVER_IP}
ns1     IN      A       ${SERVER_IP}
www     IN      A       ${SERVER_IP}
mail    IN      A       ${SERVER_IP}
EOF

    backup_file "/etc/bind/${REVERSE_ZONE_FILE_NAME}"
    cat > "/etc/bind/${REVERSE_ZONE_FILE_NAME}" <<EOF
\$TTL    604800
@       IN      SOA     ${NS_HOSTNAME}. admin.${DOMAIN}. (
                              ${serial}   ; Serial
                              604800      ; Refresh
                              86400       ; Retry
                              2419200     ; Expire
                              604800 )    ; Negative Cache TTL
;
@       IN      NS      ${NS_HOSTNAME}.

${OCT4}     IN      PTR     ${MAIL_HOSTNAME}.
EOF

    chown -R bind:bind /etc/bind
    chmod 644 "/etc/bind/db.${DOMAIN}" "/etc/bind/${REVERSE_ZONE_FILE_NAME}"

    local cfg_ok=1
    if named-checkconf; then
        ok "named-checkconf passed."
    else
        err "named-checkconf failed — check /etc/bind/named.conf.local and options."
        cfg_ok=0
    fi

    if named-checkzone "${DOMAIN}" "/etc/bind/db.${DOMAIN}" >>"$LOG_FILE" 2>&1; then
        ok "Forward zone validated."
    else
        err "Forward zone validation failed — see $LOG_FILE."
        cfg_ok=0
    fi

    if named-checkzone "${REVERSE_ZONE}" "/etc/bind/${REVERSE_ZONE_FILE_NAME}" >>"$LOG_FILE" 2>&1; then
        ok "Reverse zone validated."
    else
        err "Reverse zone validation failed — see $LOG_FILE."
        cfg_ok=0
    fi

    SERVICE_STATE[bind_configured]="yes"

    if [[ "$cfg_ok" -eq 0 ]]; then
        err "BIND configuration failed validation. Refusing to restart with a bad config."
        SERVICE_STATE[bind_validated]="no"
        return 1
    fi
    SERVICE_STATE[bind_validated]="yes"

    systemctl enable named >/dev/null 2>&1 || systemctl enable bind9 >/dev/null 2>&1
    systemctl restart named 2>/dev/null || systemctl restart bind9 2>/dev/null
    if systemctl is-active --quiet named 2>/dev/null || systemctl is-active --quiet bind9 2>/dev/null; then
        ok "BIND9 restarted and active."
        SERVICE_STATE[bind]="active"
    else
        err "BIND9 failed to start. Check 'journalctl -u bind9' or 'journalctl -u named'."
        SERVICE_STATE[bind]="failed"
    fi
}

configure_local_resolver() {
    if [[ "$CONFIGURE_LOCAL_RESOLVER" != "yes" ]]; then
        info "Local DNS resolver configuration skipped (disabled in wizard)."
        SERVICE_STATE[resolver]="skipped"
        return 0
    fi

    info "Configuring local DNS resolution to point at this server..."
    if [[ -f /etc/systemd/resolved.conf ]]; then
        backup_file /etc/systemd/resolved.conf
        set_or_append /etc/systemd/resolved.conf "DNS" "127.0.0.1"
        set_or_append /etc/systemd/resolved.conf "Domains" "${DOMAIN}"
        # Ensure the [Resolve] header exists (set_or_append just appends key=value
        # lines; systemd-resolved tolerates keys before the header being ignored,
        # so make sure a [Resolve] section header is present at least once).
        grep -q '^\[Resolve\]' /etc/systemd/resolved.conf || sed -i '1i [Resolve]' /etc/systemd/resolved.conf
        if systemctl restart systemd-resolved 2>/dev/null; then
            ok "Local resolution configured (systemd-resolved -> 127.0.0.1, search domain ${DOMAIN})."
            SERVICE_STATE[resolver]="configured"
        else
            warn "Could not restart systemd-resolved; you may need to reboot for local resolution to take effect."
            SERVICE_STATE[resolver]="restart-pending"
        fi
    else
        warn "systemd-resolved not present; skipping local resolver configuration."
        SERVICE_STATE[resolver]="skipped"
    fi
}

# =============================================================================
# APACHE (Web)
# =============================================================================
configure_apache() {
    info "Configuring Apache2..."

    local webroot="/var/www/${DOMAIN}"
    mkdir -p "$webroot"
    cat > "${webroot}/index.html" <<EOF
<!DOCTYPE html>
<html>
<head><title>${DOMAIN} Lab Server</title></head>
<body style="font-family: sans-serif;">
  <h1>${DOMAIN} Lab Server</h1>
  <p>DNS: OK</p>
  <p>Web Server: OK</p>
  <p>Mail Server: OK</p>
</body>
</html>
EOF
    chown -R www-data:www-data "$webroot"

    local site_name="${DOMAIN}"
    backup_file "/etc/apache2/sites-available/${site_name}.conf"
    cat > "/etc/apache2/sites-available/${site_name}.conf" <<EOF
<VirtualHost *:80>
    ServerName ${DOMAIN}
    ServerAlias ${WWW_HOSTNAME}
    DocumentRoot ${webroot}

    ErrorLog \${APACHE_LOG_DIR}/${site_name}-error.log
    CustomLog \${APACHE_LOG_DIR}/${site_name}-access.log combined

    <Directory ${webroot}>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF

    a2dissite 000-default >/dev/null 2>&1 || true
    a2ensite "${site_name}" >/dev/null 2>&1

    if [[ "$ENABLE_HTTPS" == "yes" ]]; then
        a2enmod ssl >/dev/null 2>&1
        backup_file "/etc/apache2/sites-available/${site_name}-ssl.conf"
        cat > "/etc/apache2/sites-available/${site_name}-ssl.conf" <<EOF
<VirtualHost *:443>
    ServerName ${WWW_HOSTNAME}
    ServerAlias ${DOMAIN}
    DocumentRoot ${webroot}

    SSLEngine on
    SSLCertificateFile ${CERT_CRT}
    SSLCertificateKeyFile ${CERT_KEY}

    ErrorLog \${APACHE_LOG_DIR}/${site_name}-ssl-error.log
    CustomLog \${APACHE_LOG_DIR}/${site_name}-ssl-access.log combined

    <Directory ${webroot}>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF
        a2ensite "${site_name}-ssl" >/dev/null 2>&1
        SERVICE_STATE[https]="configured"
    else
        a2dissite "${site_name}-ssl" >/dev/null 2>&1 || true
        SERVICE_STATE[https]="disabled"
    fi

    SERVICE_STATE[apache_configured]="yes"
    if apache2ctl configtest 2>&1 | tee -a "$LOG_FILE" | grep -q "Syntax OK"; then
        ok "Apache configtest passed."
        SERVICE_STATE[apache_validated]="yes"
    else
        err "Apache configtest failed — see $LOG_FILE."
        SERVICE_STATE[apache_validated]="no"
        return 1
    fi

    systemctl enable apache2 >/dev/null 2>&1
    systemctl restart apache2
    if systemctl is-active --quiet apache2; then
        ok "Apache2 restarted and active."
        SERVICE_STATE[apache]="active"
    else
        err "Apache2 failed to start. Check 'journalctl -u apache2'."
        SERVICE_STATE[apache]="failed"
    fi
}

# =============================================================================
# POSTFIX (SMTP) -- explicit anti-relay restrictions, submission on 587
# =============================================================================
configure_postfix() {
    info "Configuring Postfix..."
    backup_file /etc/postfix/main.cf

    postconf -e "myhostname = ${MAIL_HOSTNAME}"
    postconf -e "mydomain = ${DOMAIN}"
    postconf -e "myorigin = \$mydomain"
    postconf -e "inet_interfaces = all"
    postconf -e "inet_protocols = ipv4"
    postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain"
    postconf -e "mynetworks = 127.0.0.0/8, ${NETWORK_ADDR}/${NETWORK_CIDR}"
    postconf -e "home_mailbox = Maildir/"
    postconf -e "smtpd_banner = \$myhostname ESMTP"

    # SECURITY: never become an open relay. Only our own trusted lab network
    # or SASL-authenticated clients may relay; everyone else is restricted
    # to mail destined for domains we actually host.
    postconf -e "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"
    postconf -e "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"

    postconf -e "smtpd_sasl_type = dovecot"
    postconf -e "smtpd_sasl_path = private/auth"
    postconf -e "smtpd_sasl_auth_enable = yes"

    if [[ -f "$CERT_CRT" && -f "$CERT_KEY" ]]; then
        postconf -e "smtpd_tls_cert_file = ${CERT_CRT}"
        postconf -e "smtpd_tls_key_file = ${CERT_KEY}"
        postconf -e "smtpd_tls_security_level = may"
        postconf -e "smtp_tls_security_level = may"
    fi

    backup_file /etc/postfix/master.cf
    if ! grep -q "^submission inet" /etc/postfix/master.cf; then
        cat >> /etc/postfix/master.cf <<EOF

submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject_unauth_destination
EOF
        ok "Submission (587) service added to master.cf."
    else
        info "Submission (587) service already present in master.cf -- left as-is."
    fi

    SERVICE_STATE[postfix_configured]="yes"
    if postfix check 2>&1 | tee -a "$LOG_FILE"; then
        ok "Postfix config check passed."
        SERVICE_STATE[postfix_validated]="yes"
    else
        err "Postfix check reported issues — see $LOG_FILE."
        SERVICE_STATE[postfix_validated]="no"
    fi

    systemctl enable postfix >/dev/null 2>&1
    systemctl restart postfix
    if systemctl is-active --quiet postfix; then
        ok "Postfix restarted and active."
        SERVICE_STATE[postfix]="active"
    else
        err "Postfix failed to start. Check 'journalctl -u postfix'."
        SERVICE_STATE[postfix]="failed"
    fi
}

# =============================================================================
# DOVECOT (IMAP) -- TLS required, plaintext auth disabled, idempotent
# auth-socket insertion for Postfix SASL
# =============================================================================
configure_dovecot() {
    info "Configuring Dovecot..."

    backup_file /etc/dovecot/conf.d/10-mail.conf
    set_or_append /etc/dovecot/conf.d/10-mail.conf "mail_location" "maildir:~/Maildir"

    backup_file /etc/dovecot/conf.d/10-auth.conf
    # SECURITY: require TLS for authentication. IMAPS (993) and STARTTLS on
    # submission (587) are how clients authenticate; plaintext auth over an
    # unencrypted channel is not permitted.
    set_or_append /etc/dovecot/conf.d/10-auth.conf "disable_plaintext_auth" "yes"

    backup_file /etc/dovecot/conf.d/10-ssl.conf
    if [[ -f "$CERT_CRT" && -f "$CERT_KEY" ]]; then
        set_or_append /etc/dovecot/conf.d/10-ssl.conf "ssl" "required"
        set_or_append /etc/dovecot/conf.d/10-ssl.conf "ssl_cert" "<${CERT_CRT}"
        set_or_append /etc/dovecot/conf.d/10-ssl.conf "ssl_key" "<${CERT_KEY}"
    fi

    # Idempotently ensure the Postfix SASL auth socket exists inside the
    # existing "service auth {" block. Uses a marker comment so re-running
    # this script never creates duplicate listener stanzas.
    backup_file /etc/dovecot/conf.d/10-master.conf
    if ! grep -q "LAB-SERVER-AUTH-SOCKET" /etc/dovecot/conf.d/10-master.conf; then
        awk '
            /service auth \{/ && !done {
                print
                print "  # LAB-SERVER-AUTH-SOCKET (added by lab setup wizard, do not duplicate)"
                print "  unix_listener /var/spool/postfix/private/auth {"
                print "    mode = 0666"
                print "    user = postfix"
                print "    group = postfix"
                print "  }"
                done=1
                next
            }
            { print }
        ' /etc/dovecot/conf.d/10-master.conf > /tmp/10-master.conf.new \
            && mv /tmp/10-master.conf.new /etc/dovecot/conf.d/10-master.conf
        ok "Postfix SASL auth socket added to Dovecot (service auth block)."
    else
        info "Postfix SASL auth socket already present in Dovecot config -- skipped."
    fi

    backup_file /etc/dovecot/dovecot.conf
    grep -q "^protocols" /etc/dovecot/dovecot.conf || echo "protocols = imap" >> /etc/dovecot/dovecot.conf

    SERVICE_STATE[dovecot_configured]="yes"
    if doveconf -n >/dev/null 2>>"$LOG_FILE"; then
        ok "Dovecot config check passed."
        SERVICE_STATE[dovecot_validated]="yes"
    else
        err "Dovecot config check failed — see $LOG_FILE."
        SERVICE_STATE[dovecot_validated]="no"
    fi

    systemctl enable dovecot >/dev/null 2>&1
    systemctl restart dovecot
    if systemctl is-active --quiet dovecot; then
        ok "Dovecot restarted and active."
        SERVICE_STATE[dovecot]="active"
    else
        err "Dovecot failed to start. Check 'journalctl -u dovecot'."
        SERVICE_STATE[dovecot]="failed"
    fi
}

create_mail_user() {
    info "Creating test mail user..."
    if id "$MAIL_TEST_USER" >/dev/null 2>&1; then
        ok "User $MAIL_TEST_USER already exists."
    else
        useradd -m -s /usr/sbin/nologin "$MAIL_TEST_USER"
        ok "User $MAIL_TEST_USER created."
    fi
    # Always (re)apply the configured password rather than only on first
    # creation, so re-running the wizard with a new password updates it.
    echo "${MAIL_TEST_USER}:${MAIL_TEST_USER_PASSWORD}" | chpasswd

    local home_dir
    home_dir=$(getent passwd "$MAIL_TEST_USER" | cut -d: -f6)
    if [[ ! -d "${home_dir}/Maildir" ]]; then
        maildirmake.dovecot "${home_dir}/Maildir" 2>/dev/null || mkdir -p "${home_dir}/Maildir"/{cur,new,tmp}
        chown -R "${MAIL_TEST_USER}:${MAIL_TEST_USER}" "${home_dir}/Maildir"
        ok "Maildir created for $MAIL_TEST_USER."
    else
        ok "Maildir already exists for $MAIL_TEST_USER."
    fi
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

    info "Configuring UFW firewall..."

    # Confirm SSH will remain reachable before touching anything else.
    ufw allow 22/tcp comment 'SSH' >/dev/null
    if ufw status | grep -qw "22/tcp"; then
        ok "SSH rule confirmed present in UFW ruleset."
    else
        err "SSH rule could not be confirmed — refusing to enable UFW to avoid lockout."
        SERVICE_STATE[ufw]="failed"
        return 1
    fi

    ufw allow 53/tcp comment 'DNS TCP' >/dev/null
    ufw allow 53/udp comment 'DNS UDP' >/dev/null
    ufw allow 80/tcp comment 'HTTP' >/dev/null
    ufw allow 25/tcp comment 'SMTP' >/dev/null
    ufw allow 587/tcp comment 'SMTP Submission' >/dev/null
    ufw allow 993/tcp comment 'IMAPS' >/dev/null

    if [[ "$ENABLE_HTTPS" == "yes" ]]; then
        ufw allow 443/tcp comment 'HTTPS' >/dev/null
        ok "443/tcp allowed (HTTPS enabled)."
    else
        ufw delete allow 443/tcp >/dev/null 2>&1 || true
        info "443/tcp not opened (HTTPS disabled)."
    fi
    # Plain IMAP (143) is intentionally NOT opened; this design only
    # exposes IMAPS (993) and submission (587) with TLS for authenticated
    # mail access.

    if ufw status | grep -q "Status: active"; then
        ok "UFW already active; rules updated."
    else
        ufw --force enable
        ok "UFW enabled with lab service rules."
    fi
    SERVICE_STATE[ufw]="configured"
}

# =============================================================================
# VALIDATION
# =============================================================================
check_dns_record() {
    local name="$1" type="$2" expected_substr="$3" label="$4"
    local result
    result=$(dig +short @127.0.0.1 "$name" "$type" 2>/dev/null | tr '\n' ' ')
    if [[ -n "$result" && "$result" == *"$expected_substr"* ]]; then
        ok "DNS $label: $name $type -> $result"
        VALIDATION["dns_${label}"]="PASS"
    else
        err "DNS $label: $name $type returned '$result' (expected to contain '$expected_substr')"
        VALIDATION["dns_${label}"]="FAIL"
    fi
}

check_http() {
    local url="$1" label="$2"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -k --max-time 5 "$url" 2>/dev/null || echo "000")
    if [[ "$code" == "200" ]]; then
        ok "$label -> HTTP $code"
        VALIDATION["$label"]="PASS"
    else
        err "$label -> HTTP $code (expected 200)"
        VALIDATION["$label"]="FAIL"
    fi
}

check_not_open_relay() {
    local rr
    rr=$(postconf -h smtpd_relay_restrictions 2>/dev/null)
    if echo "$rr" | grep -q "reject_unauth_destination"; then
        ok "Postfix relay restrictions include reject_unauth_destination (not an open relay)."
        VALIDATION[relay]="PASS"
    else
        err "Postfix smtpd_relay_restrictions do NOT include reject_unauth_destination!"
        VALIDATION[relay]="FAIL"
    fi
}

mail_delivery_test() {
    if [[ "${SERVICE_STATE[postfix]:-}" != "active" || "${SERVICE_STATE[dovecot]:-}" != "active" ]]; then
        warn "Skipping mail delivery test -- Postfix and/or Dovecot are not active."
        VALIDATION[mail_delivery]="SKIP"
        return
    fi
    if ! command -v mail >/dev/null 2>&1; then
        warn "mailutils 'mail' command not found; skipping delivery test."
        VALIDATION[mail_delivery]="SKIP"
        return
    fi

    local home_dir maildir_new subject
    home_dir=$(getent passwd "$MAIL_TEST_USER" | cut -d: -f6)
    maildir_new="${home_dir}/Maildir/new"
    subject="labtest-$(date +%s)"

    echo "This is an automated delivery test from the lab server setup wizard." \
        | mail -s "$subject" -r "root@${DOMAIN}" "${MAIL_TEST_USER}@${DOMAIN}" 2>>"$LOG_FILE"

    local waited=0
    while (( waited < 20 )); do
        if grep -rl "$subject" "$maildir_new" >/dev/null 2>&1; then
            ok "Mail delivery test passed — message reached ${maildir_new}."
            VALIDATION[mail_delivery]="PASS"
            return
        fi
        sleep 1
        ((waited++))
    done
    err "Mail delivery test failed — test message not found in ${maildir_new} after 20s."
    VALIDATION[mail_delivery]="FAIL"
}

check_listening() {
    local port="$1" label="$2"
    if ss -tuln 2>/dev/null | grep -qE "[.:]${port}[[:space:]]"; then
        ok "Port ${port} (${label}) is listening."
        VALIDATION["port_${port}"]="PASS"
    else
        err "Port ${port} (${label}) is NOT listening."
        VALIDATION["port_${port}"]="FAIL"
    fi
}

run_validation() {
    stage "===== Running validation tests ====="

    echo "--- DNS ---"
    check_dns_record "${DOMAIN}." "A" "${SERVER_IP}" "domain_a"
    check_dns_record "${WWW_HOSTNAME}." "A" "${SERVER_IP}" "www_a"
    check_dns_record "${MAIL_HOSTNAME}." "A" "${SERVER_IP}" "mail_a"
    check_dns_record "${DOMAIN}." "MX" "${MAIL_HOSTNAME}" "mx"
    check_dns_record "${OCT4}.${OCT3}.${OCT2}.${OCT1}.in-addr.arpa." "PTR" "${MAIL_HOSTNAME}" "ptr"

    echo "--- Web ---"
    check_http "http://${DOMAIN}" "http_domain"
    check_http "http://${WWW_HOSTNAME}" "http_www"
    if [[ "$ENABLE_HTTPS" == "yes" ]]; then
        check_http "https://${WWW_HOSTNAME}" "https_www"
    else
        VALIDATION[https_www]="SKIP"
    fi

    echo "--- Mail ---"
    check_not_open_relay
    mail_delivery_test

    echo "--- Ports ---"
    check_listening 22 SSH
    check_listening 53 DNS
    check_listening 80 HTTP
    if [[ "$ENABLE_HTTPS" == "yes" ]]; then check_listening 443 HTTPS; fi
    check_listening 25 SMTP
    check_listening 587 "SMTP Submission"
    check_listening 993 IMAPS

    echo "--- Firewall ---"
    if [[ "$ENABLE_UFW" == "yes" ]]; then
        ufw status verbose | tee -a "$LOG_FILE"
    else
        echo "UFW disabled by configuration -- skipped."
    fi
}

# =============================================================================
# FINAL REPORT
# =============================================================================
status_line() {
    # status_line <label> <configured yes/no/na> <validated PASS/FAIL/SKIP/na>
    local label="$1" cfg="$2" val="$3"
    printf "  %-22s configured: %-10s validated: %s\n" "$label" "$cfg" "$val"
}

print_summary() {
    cat <<EOF

===============================================
 LAB SERVER SETUP COMPLETE
===============================================

Domain:
  ${DOMAIN}

Server:
  ${HOSTNAME_FQDN}
  ${SERVER_IP}

DNS:
  ${NS_HOSTNAME}

Web:
  http://${WWW_HOSTNAME}
$( [[ "$ENABLE_HTTPS" == "yes" ]] && echo "  https://${WWW_HOSTNAME}" )

Mail:
  ${MAIL_TEST_USER}@${DOMAIN}

Services (configured vs. actually validated):
EOF
    status_line "BIND9"   "${SERVICE_STATE[bind_configured]:-no}"    "${SERVICE_STATE[bind]:-unknown} / checkconf:${SERVICE_STATE[bind_validated]:-no}"
    status_line "Apache2" "${SERVICE_STATE[apache_configured]:-no}"  "${SERVICE_STATE[apache]:-unknown} / configtest:${SERVICE_STATE[apache_validated]:-no}"
    status_line "Postfix" "${SERVICE_STATE[postfix_configured]:-no}" "${SERVICE_STATE[postfix]:-unknown} / check:${SERVICE_STATE[postfix_validated]:-no}"
    status_line "Dovecot" "${SERVICE_STATE[dovecot_configured]:-no}" "${SERVICE_STATE[dovecot]:-unknown} / doveconf:${SERVICE_STATE[dovecot_validated]:-no}"
    status_line "UFW"     "${SERVICE_STATE[ufw]:-skipped}"           "n/a"
    status_line "HTTPS"   "${SERVICE_STATE[https]:-disabled}"        "n/a"

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
        echo "Full log:    $LOG_FILE"
        echo "Backups of:  $BACKUP_DIR"
        echo "Review the sections above before considering this lab server ready."
    else
        echo "No failures reported."
        echo "Full log:    $LOG_FILE"
        echo "Backups of:  $BACKUP_DIR"
    fi
    echo "==============================================="
}

# =============================================================================
# OPTIONAL REBOOT
# =============================================================================
offer_reboot() {
    cat <<EOF

===============================================
 Reboot
===============================================
Nothing above strictly requires a reboot: netplan was applied live, and
every service (BIND9, Apache2, Postfix, Dovecot, UFW) was already
restarted and validated. A reboot is optional -- it's mainly useful to
confirm everything comes back up cleanly on a cold boot (all services
are enabled via systemd, so they should start automatically).
EOF
    if prompt_yn "Reboot now?" "N"; then
        warn "Rebooting in 5 seconds... (Ctrl+C to cancel)"
        sleep 5
        reboot
    else
        info "Skipping reboot. You can reboot later with: sudo reboot"
    fi
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    parse_args "$@"

    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"

    require_root
    check_os

    show_banner
    wizard_network
    wizard_domain_and_hosts
    wizard_mail_user
    wizard_features
    compute_derived_values

    show_summary
    confirm_or_exit

    BACKUP_DIR="${BACKUP_ROOT}/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    info "Backups for this run will be stored under: $BACKUP_DIR"

    stage "[1/7] Checking system and installing packages..."
    install_packages

    stage "[2/7] Configuring network..."
    configure_network
    configure_hostname

    stage "[3/7] Preparing TLS certificate..."
    generate_tls_cert

    stage "[4/7] Configuring DNS (BIND9)..."
    configure_bind9
    configure_local_resolver

    stage "[5/7] Configuring web server (Apache2)..."
    configure_apache

    stage "[6/7] Configuring mail server (Postfix + Dovecot)..."
    configure_postfix
    configure_dovecot
    create_mail_user
    configure_firewall

    stage "[7/7] Running validation tests..."
    run_validation

    print_summary
    offer_reboot
}

main "$@"