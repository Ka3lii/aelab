# Linux Lab Server Setup Wizard

`setup-lab-server.sh` is an interactive installer and configurator for an
isolated Ubuntu Server lab. It sets up DNS, web hosting, SMTP, IMAP, and an
optional firewall and self-signed HTTPS certificate.

This script is intended for a private cybersecurity or networking lab only.
Do not expose the resulting services directly to the public internet.

## Supported system

- Ubuntu Server 24.04 LTS is supported and tested.
- Run as `root`, normally with `sudo`.
- The host must have `apt`, `systemd`, `iproute2`, and a usable network
	interface.
- The script can continue on another OS only after an explicit warning; the
	result is unsupported.

## Quick start

Make the script executable and start the wizard:

```bash
chmod +x setup-lab-server.sh
sudo ./setup-lab-server.sh
```

The wizard collects the interface, IPv4 address, CIDR prefix, gateway, lab
domain, hostnames, mail test user, and optional features. It displays a full
summary and requires confirmation before making system changes.

Network changes receive an additional confirmation. When run from an
interactive terminal, Netplan uses `netplan try` with a 45-second rollback
window. Declining the network change stops the setup if the requested address
is not already assigned to the selected interface.

## Command-line options

All options are optional. Supplied values are used as wizard defaults, and the
wizard still asks for confirmation.

```text
--ip ADDRESS             Server IPv4 address
--cidr LENGTH            Network prefix length, such as 24
--gateway ADDRESS        Default gateway; omit for an isolated lab
--interface NAME         Network interface to configure
--domain NAME            Lab domain, such as cyberlab.local
--mail-user NAME         Mail test username; default: labuser
--https / --no-https     Enable or disable self-signed HTTPS
--ufw / --no-ufw         Enable or disable UFW configuration
--resolver / --no-resolver
												 Enable or disable local DNS resolver configuration
-h, --help               Show help and exit
```

Example:

```bash
sudo ./setup-lab-server.sh \
	--ip 192.168.50.10 \
	--cidr 24 \
	--gateway 192.168.50.1 \
	--interface eth0 \
	--domain cyberlab.local \
	--https \
	--ufw \
	--resolver
```

The mail test password is always entered interactively and is never accepted
as a command-line argument.

## What it configures

- **BIND9:** authoritative forward and reverse DNS for the selected lab
	domain. Recursive queries are restricted to localhost and the configured
	lab network, avoiding an open resolver.
- **Apache2:** an HTTP virtual host with a basic status page. HTTPS can be
	enabled with a shared self-signed certificate.
- **Postfix:** SMTP on port 25 and authenticated submission on port 587, with
	relay restrictions to prevent unauthenticated relaying.
- **Dovecot:** IMAP over TLS on port 993. Plaintext authentication is disabled.
- **Mail test account:** a local user with a Maildir and a password entered in
	the wizard.
- **UFW:** optional rules for SSH, DNS, HTTP, SMTP, submission, IMAPS, and
	HTTPS when enabled.
- **Local resolver:** optional `systemd-resolved` configuration pointing to
	`127.0.0.1`.

The setup is designed to be rerunnable. Existing configuration files are
backed up before being changed, and generated settings use idempotent updates
where practical.

## Expected ports

| Port | Service | Condition |
| --- | --- | --- |
| 22/tcp | SSH | Always expected to remain reachable |
| 53/tcp, 53/udp | DNS | Always configured |
| 80/tcp | HTTP | Always configured |
| 443/tcp | HTTPS | Only when enabled |
| 25/tcp | SMTP | Always configured |
| 587/tcp | SMTP submission | Always configured; TLS required for authentication |
| 993/tcp | IMAPS | Always configured |

Plain IMAP on port 143 is intentionally not opened.

## Backups, logs, and validation

At the end of setup, the script validates DNS records, HTTP/HTTPS responses,
mail delivery, relay restrictions, listening ports, and UFW status. It prints a
final report distinguishing configuration from successful validation.

- Log: `/var/log/lab-server-setup.log`
- Per-run backups: `/var/backups/lab-server-setup/<timestamp>/`
- TLS files when HTTPS is enabled: `/etc/ssl/lab-server/`

Review the final report and log before treating the lab server as ready. A
non-`/24` network is accepted, but reverse DNS generation is based on the
corresponding `/24` boundary and may require manual adjustment.

## Safety notes

The script changes network configuration, hostname, DNS, web, mail, resolver,
firewall, and local user settings. Test it on a disposable lab server or take
an appropriate backup first. Enabling UFW adds an SSH rule before enabling the
firewall, but you should still ensure that SSH access is available through the
selected interface.
