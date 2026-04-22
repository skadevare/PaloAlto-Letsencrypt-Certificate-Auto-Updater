# PAN-OS GlobalProtect Certificate Automation

This repository contains a standalone Python script for managing a certificate used by a Palo Alto GlobalProtect portal.

The main script is `renew_globalprotect_cert.py`.

It supports two modes:

1. Automated Certbot renewal mode.
2. Manual certificate import mode.

There is no separate config file. All runtime settings live at the top of `renew_globalprotect_cert.py`.

## What It Does
<img width="1002" height="507" alt="image" src="https://github.com/user-attachments/assets/39bdb94d-6f1f-41fa-a4ba-4ab606b57edd" />


In automated mode, the script:

1. Reads the current state of a predefined NAT rule and optional security rule on the firewall.
2. Enables those rules if they are disabled.
3. Commits the firewall so inbound `tcp/80` can reach the Certbot host.
4. Runs Certbot in `standalone` mode for HTTP-01 validation.
5. Restores the original rule state and commits again.
6. Builds a temporary PKCS#12 bundle from the local certificate.
7. Imports or reuses the matching certificate object in PAN-OS.
8. Updates the configured SSL/TLS service profile.
9. Commits the certificate change.

In manual mode, the script:

1. Reads a certificate PEM file and private key PEM file that you provide.
2. Builds a temporary PKCS#12 bundle.
3. Uploads it to the Palo Alto firewall.
4. Updates the configured SSL/TLS service profile.
5. Commits the change.

Manual mode does not run Certbot and does not touch NAT or security rules.

## Requirements

- Python 3.11 or newer
- `openssl`
- `certbot` for automated mode
- Network access from the script host to the Palo Alto management interface
- Internet reachability to the Certbot host on `tcp/80` for automated mode
- A pre-existing SSL/TLS service profile on the firewall
- A pre-created disabled NAT rule and, if needed, a pre-created disabled security rule for automated mode

Install the Python dependency:

```bash
pip install -r requirements.txt
```

## Configuration

Edit the variables at the top of `renew_globalprotect_cert.py`.

Important settings:

- `DOMAIN`: FQDN for the public certificate
- `PALO_ALTO_HOST`: Firewall management IP or hostname
- `PALO_ALTO_USERNAME`: PAN-OS username used for API key generation
- `PALO_ALTO_PASSWORD`: PAN-OS password used for API key generation
- `PALO_ALTO_API_KEY_ENV`: Optional environment variable name for a pre-generated API key
- `PALO_ALTO_VSYS`: Target vsys for rules
- `NAT_RULE_NAME`: Disabled NAT rule used to expose `tcp/80` during Certbot validation
- `SECURITY_RULE_NAME`: Disabled allow rule used during Certbot validation
- `SSL_TLS_PROFILE_NAME`: SSL/TLS service profile that GlobalProtect uses
- `SSL_TLS_PROFILE_XPATH`: Optional override if the profile is not under `/config/shared/ssl-tls-service-profile`
- `CERTIFICATE_NAME_PREFIX`: Prefix used when creating imported certificate object names in PAN-OS
- `CERTIFICATE_VSYS`: Leave blank for shared, or set a specific vsys if certificates are stored there
- `PALO_ALTO_VERIFY_TLS`: Set to `False` only if the firewall management certificate is not trusted by the host running the script
- `CERTBOT_EMAIL`: Let's Encrypt registration email
- `CERTBOT_CERT_NAME`: Certbot lineage name under `/etc/letsencrypt/live/`
- `CERTBOT_EXTRA_ARGS`: Optional extra Certbot arguments

If your environment does not need a separate temporary security policy rule, set:

```python
SECURITY_RULE_NAME = ""
```

## Authentication

By default, the script generates a PAN-OS API key from `PALO_ALTO_USERNAME` and `PALO_ALTO_PASSWORD`.

If you prefer to use a pre-generated API key instead, export it before running the script:

```bash
export PALOALTO_API_KEY='your-api-key'
```

If the environment variable exists, the script uses it instead of the username/password login flow.

## Automated Renewal Usage

Run the standard automated workflow with:

```bash
python3 renew_globalprotect_cert.py
```

This mode expects:

- Certbot to be installed
- The configured NAT rule to forward inbound `tcp/80` to the host running the script
- The domain to resolve publicly to the correct address
- The firewall commit to succeed before Certbot validation begins

To test the Certbot workflow against Let's Encrypt staging, temporarily set:

```python
CERTBOT_EXTRA_ARGS = ["--dry-run", "--server", "https://acme-staging-v02.api.letsencrypt.org/directory"]
```

Remove staging flags before production use.

## Manual Certificate Import Usage

Use manual mode when you already have a certificate and private key and only want to upload them to the firewall and switch the SSL/TLS profile.

Command:

```bash
python3 renew_globalprotect_cert.py --manual-cert --incert /path/to/fullchain.pem --inkey /path/to/privkey.pem
```

Short-option form also works:

```bash
python3 renew_globalprotect_cert.py --manual-cert -incert /path/to/fullchain.pem -inkey /path/to/privkey.pem
```

Notes:

- Use a fullchain-style PEM for `--incert` when intermediates are required.
- Manual mode does not touch NAT rules.
- Manual mode does not run Certbot.
- Manual mode still commits the SSL/TLS profile update on the firewall.

## Scheduling

Sample `systemd` files are included in `systemd/`.

The included timer uses:

```ini
OnCalendar=quarterly
```

Enable it with:

```bash
sudo cp systemd/globalprotect-cert-renew.service /etc/systemd/system/
sudo cp systemd/globalprotect-cert-renew.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now globalprotect-cert-renew.timer
```

Quarterly execution matches the original requirement, but monthly is safer for 90-day Let's Encrypt certificates.

## PAN-OS Objects Required

Before using automated mode, create these on the firewall:

- A disabled NAT rule that forwards inbound `tcp/80` on the correct external interface to the Certbot host
- A disabled security rule that allows the validation traffic if your policy requires one
- An existing SSL/TLS service profile already used by GlobalProtect

The script intentionally toggles existing rules instead of creating them, because NAT and security policy details are too environment-specific to infer safely.

## Common Pitfall: Certbot Symlinks

If you use manual mode with files copied from a Certbot `live` directory, be aware that `cert.pem`, `fullchain.pem`, and `privkey.pem` are usually symlinks to numbered files under an `archive` directory such as `fullchain1.pem` or `privkey1.pem`.

If you copied only the `live` directory and not the matching `archive` directory, the symlinks will be broken and manual mode will fail.

The safest manual-mode input is usually the real Let's Encrypt path:

```bash
python3 renew_globalprotect_cert.py --manual-cert --incert /etc/letsencrypt/live/example.com/fullchain.pem --inkey /etc/letsencrypt/live/example.com/privkey.pem
```

If you need local copies, copy the resolved files, not the symlinks.

## Operational Notes

- The script performs full firewall commits.
- If there are unrelated candidate changes pending on the firewall, account for that before running the script.
- Certificate object names are derived from the certificate fingerprint so the same local certificate can be reused cleanly.
- PKCS#12 import passphrases are kept within the PAN-OS length limit.

## Security Note

This repository is intended for GitHub, but the current script stores site-specific values directly at the top of `renew_globalprotect_cert.py`.

Do not publish real credentials in a public repository. Replace sensitive values before pushing, or refactor them to environment variables or a private deployment process.
