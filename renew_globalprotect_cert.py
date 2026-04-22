#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as xml_escape

import requests
import urllib3


DEVICE_ROOT = "/config/devices/entry[@name='localhost.localdomain']"

# Edit these values for your environment.
DOMAIN = "gpvpn.yourdomain.com"                  # Change This
PALO_ALTO_HOST = "https://your-firewall-address"
PALO_ALTO_USERNAME = "certbot-user"              # Change This
PALO_ALTO_PASSWORD = "Password-For-Certbot-User" # Change This
PALO_ALTO_API_KEY_ENV = "PALOALTO_API_KEY"       
PALO_ALTO_VSYS = "vsys1"
NAT_RULE_NAME = "CERTBOT-NAT-inbound-HTTP"          
SECURITY_RULE_NAME = "CERTBOT-security-inbound-http"
SSL_TLS_PROFILE_NAME = "CERTBOT-SSL-TLS-Profile"
SSL_TLS_PROFILE_XPATH = ""
CERTIFICATE_NAME_PREFIX = "gp-portal"
CERTIFICATE_VSYS = ""
PALO_ALTO_VERIFY_TLS = False
PALO_ALTO_REQUEST_TIMEOUT_SECONDS = 60
PALO_ALTO_POLL_INTERVAL_SECONDS = 10

CERTBOT_EMAIL = "admin@yourdomain.com"         # Change This
CERTBOT_CERT_NAME = DOMAIN
CERTBOT_PATH = "/usr/bin/certbot"
CERTBOT_CONFIG_DIR = "/etc/letsencrypt"
CERTBOT_WORK_DIR = ""
CERTBOT_LOGS_DIR = ""
CERTBOT_EXTRA_ARGS: list[str] = []

OPENSSL_PATH = "/usr/bin/openssl"


class WorkflowError(RuntimeError):
    pass


@dataclass(frozen=True)
class CertbotConfig:
    email: str
    cert_name: str
    path: str = "/usr/bin/certbot"
    config_dir: str = "/etc/letsencrypt"
    work_dir: str | None = None
    logs_dir: str | None = None
    extra_args: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PaloAltoConfig:
    host: str
    api_key_env: str | None
    username: str | None
    password: str | None
    vsys: str
    nat_rule_name: str
    security_rule_name: str | None
    ssl_tls_profile_name: str
    ssl_tls_profile_xpath: str | None
    certificate_name_prefix: str
    certificate_vsys: str | None
    verify_tls: bool
    request_timeout_seconds: int
    poll_interval_seconds: int


@dataclass(frozen=True)
class AppConfig:
    domain: str
    certbot: CertbotConfig
    palo_alto: PaloAltoConfig
    openssl_path: str = "/usr/bin/openssl"

    @property
    def certificate_directory(self) -> Path:
        return Path(self.certbot.config_dir) / "live" / self.certbot.cert_name


@dataclass(frozen=True)
class RuleState:
    rulebase: str
    rule_name: str
    disabled: bool


CERTIFICATE_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Renew a GlobalProtect certificate and switch the Palo Alto SSL/TLS profile.",
    )
    parser.add_argument(
        "--manual-cert",
        action="store_true",
        help="Skip Certbot and import the certificate and key provided with --incert and --inkey.",
    )
    parser.add_argument(
        "-incert",
        "--incert",
        type=Path,
        help="Path to the certificate PEM file for --manual-cert. Use a fullchain PEM if you need intermediates included.",
    )
    parser.add_argument(
        "-inkey",
        "--inkey",
        type=Path,
        help="Path to the private key PEM file for --manual-cert.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity.",
    )
    args = parser.parse_args()

    if args.manual_cert:
        if not args.incert or not args.inkey:
            parser.error("--manual-cert requires both --incert and --inkey")
    elif args.incert or args.inkey:
        parser.error("--incert and --inkey can only be used together with --manual-cert")

    return args


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s %(levelname)s %(message)s",
    )


def build_config() -> AppConfig:
    return AppConfig(
        domain=required_setting("DOMAIN", DOMAIN),
        certbot=CertbotConfig(
            email=required_setting("CERTBOT_EMAIL", CERTBOT_EMAIL),
            cert_name=required_setting("CERTBOT_CERT_NAME", CERTBOT_CERT_NAME),
            path=required_setting("CERTBOT_PATH", CERTBOT_PATH),
            config_dir=required_setting("CERTBOT_CONFIG_DIR", CERTBOT_CONFIG_DIR),
            work_dir=empty_to_none(CERTBOT_WORK_DIR),
            logs_dir=empty_to_none(CERTBOT_LOGS_DIR),
            extra_args=list(CERTBOT_EXTRA_ARGS),
        ),
        palo_alto=PaloAltoConfig(
            host=required_setting("PALO_ALTO_HOST", PALO_ALTO_HOST),
            api_key_env=empty_to_none(PALO_ALTO_API_KEY_ENV),
            username=empty_to_none(PALO_ALTO_USERNAME),
            password=empty_to_none(PALO_ALTO_PASSWORD),
            vsys=required_setting("PALO_ALTO_VSYS", PALO_ALTO_VSYS),
            nat_rule_name=required_setting("NAT_RULE_NAME", NAT_RULE_NAME),
            security_rule_name=empty_to_none(SECURITY_RULE_NAME),
            ssl_tls_profile_name=required_setting("SSL_TLS_PROFILE_NAME", SSL_TLS_PROFILE_NAME),
            ssl_tls_profile_xpath=empty_to_none(SSL_TLS_PROFILE_XPATH),
            certificate_name_prefix=required_setting("CERTIFICATE_NAME_PREFIX", CERTIFICATE_NAME_PREFIX),
            certificate_vsys=empty_to_none(CERTIFICATE_VSYS),
            verify_tls=bool(PALO_ALTO_VERIFY_TLS),
            request_timeout_seconds=int(PALO_ALTO_REQUEST_TIMEOUT_SECONDS),
            poll_interval_seconds=int(PALO_ALTO_POLL_INTERVAL_SECONDS),
        ),
        openssl_path=required_setting("OPENSSL_PATH", OPENSSL_PATH),
    )


def empty_to_none(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    return str(value)


def required_setting(name: str, value: str | None) -> str:
    if value is None:
        raise WorkflowError(f"Script setting {name} cannot be empty")
    value = value.strip()
    if not value:
        raise WorkflowError(f"Script setting {name} cannot be empty")
    return value


def require_binary(path_or_name: str) -> None:
    if Path(path_or_name).is_absolute():
        if not Path(path_or_name).exists():
            raise WorkflowError(f"Required binary not found: {path_or_name}")
        return
    if shutil.which(path_or_name) is None:
        raise WorkflowError(f"Required binary not found in PATH: {path_or_name}")


def certificate_fingerprint(cert_path: Path) -> str | None:
    if not cert_path.exists():
        return None
    pem_data = cert_path.read_text()
    der_bytes = ssl.PEM_cert_to_DER_cert(first_pem_certificate(pem_data))
    return hashlib.sha256(der_bytes).hexdigest()


def first_pem_certificate(pem_data: str) -> str:
    match = CERTIFICATE_BLOCK_RE.search(pem_data)
    if match is None:
        raise WorkflowError("No PEM certificate block was found in the provided certificate file")
    return match.group(0)


def build_certbot_command(config: AppConfig) -> list[str]:
    command = [
        config.certbot.path,
        "certonly",
        "--standalone",
        "--preferred-challenges",
        "http",
        "--non-interactive",
        "--agree-tos",
        "--keep-until-expiring",
        "--email",
        config.certbot.email,
        "--cert-name",
        config.certbot.cert_name,
        "-d",
        config.domain,
    ]

    if config.certbot.config_dir:
        command.extend(["--config-dir", config.certbot.config_dir])
    if config.certbot.work_dir:
        command.extend(["--work-dir", config.certbot.work_dir])
    if config.certbot.logs_dir:
        command.extend(["--logs-dir", config.certbot.logs_dir])

    command.extend(config.certbot.extra_args)
    return command


def run_command(command: list[str], description: str) -> subprocess.CompletedProcess[str]:
    logging.info("%s", description)
    result = subprocess.run(command, text=True, capture_output=True)

    if result.stdout.strip():
        logging.info(result.stdout.strip())
    if result.stderr.strip():
        logging.warning(result.stderr.strip())

    if result.returncode != 0:
        raise WorkflowError(f"{description} failed with exit code {result.returncode}")

    return result


def build_pkcs12(
    config: AppConfig,
    cert_name: str,
    cert_path: Path,
    key_path: Path,
    chain_path: Path | None = None,
) -> tuple[Path, str]:
    file_paths = [cert_path, key_path]
    if chain_path is not None:
        file_paths.append(chain_path)

    for file_path in file_paths:
        if not file_path.exists():
            raise WorkflowError(f"Missing certificate input file: {file_path}")

    temp_file = tempfile.NamedTemporaryFile(prefix="globalprotect-", suffix=".p12", delete=False)
    temp_file.close()
    output_path = Path(temp_file.name)
    # PAN-OS rejects PKCS#12 import passphrases longer than 31 characters.
    passphrase = secrets.token_hex(15)

    command = [
        config.openssl_path,
        "pkcs12",
        "-export",
        "-inkey",
        str(key_path),
        "-in",
        str(cert_path),
        "-name",
        cert_name,
        "-out",
        str(output_path),
        "-passout",
        f"pass:{passphrase}",
    ]

    if chain_path is not None:
        command[7:7] = ["-certfile", str(chain_path)]

    run_command(command, "Building PKCS#12 bundle")
    return output_path, passphrase


def build_certificate_name(prefix: str, fingerprint: str) -> str:
    name = f"{prefix}-{fingerprint[:16]}"
    return name[:63]


def is_duplicate_import_error(error: WorkflowError) -> bool:
    message = str(error).lower()
    patterns = (
        "already exists",
        "already in use",
        "is already configured",
        "duplicate",
    )
    return any(pattern in message for pattern in patterns)


def xpath_literal(value: str) -> str:
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    parts = value.split("'")
    return "concat(" + ", \"'\", ".join(f"'{part}'" for part in parts) + ")"


class PaloAltoClient:
    def __init__(self, config: PaloAltoConfig):
        host = config.host.rstrip("/")
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"

        self.api_url = f"{host}/api/"
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.verify_tls

        if not config.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.api_key = self.resolve_api_key()

    def resolve_api_key(self) -> str:
        if self.config.api_key_env:
            api_key = os.environ.get(self.config.api_key_env)
            if api_key:
                logging.info("Using Palo Alto API key from %s", self.config.api_key_env)
                return api_key

        if not self.config.username or not self.config.password:
            raise WorkflowError(
                "Palo Alto authentication requires either an API key environment variable or a username/password"
            )

        logging.info("Generating Palo Alto API key for user %s", self.config.username)
        response = self.session.post(
            self.api_url,
            params={
                "type": "keygen",
                "user": self.config.username,
                "password": self.config.password,
            },
            timeout=self.config.request_timeout_seconds,
        )
        response.raise_for_status()

        try:
            root = ET.fromstring(response.text)
        except ET.ParseError as exc:
            raise WorkflowError(f"Palo Alto API returned invalid XML during key generation: {exc}") from exc

        if root.attrib.get("status") != "success":
            raise WorkflowError(self.build_api_error({"type": "keygen"}, root))

        api_key = root.findtext(".//key")
        if not api_key:
            raise WorkflowError("Palo Alto API key generation succeeded but returned no key")
        return api_key

    @property
    def vsys_root(self) -> str:
        return f"{DEVICE_ROOT}/vsys/entry[@name={xpath_literal(self.config.vsys)}]"

    def rule_xpath(self, rulebase: str, rule_name: str) -> str:
        return f"{self.vsys_root}/rulebase/{rulebase}/rules/entry[@name={xpath_literal(rule_name)}]"

    def profile_xpath(self) -> str:
        if self.config.ssl_tls_profile_xpath:
            return self.config.ssl_tls_profile_xpath
        return (
            "/config/shared/ssl-tls-service-profile/"
            f"entry[@name={xpath_literal(self.config.ssl_tls_profile_name)}]"
        )

    def request_xml(self, params: dict[str, str], files: dict[str, Any] | None = None) -> ET.Element:
        payload = dict(params)
        payload["key"] = self.api_key

        response = self.session.post(
            self.api_url,
            params=payload,
            files=files,
            timeout=self.config.request_timeout_seconds,
        )
        response.raise_for_status()

        try:
            root = ET.fromstring(response.text)
        except ET.ParseError as exc:
            raise WorkflowError(f"Palo Alto API returned invalid XML: {exc}") from exc

        if root.attrib.get("status") != "success":
            raise WorkflowError(self.build_api_error(params, root))

        return root

    def build_api_error(self, params: dict[str, str], root: ET.Element) -> str:
        lines = [line.text.strip() for line in root.findall(".//line") if line.text and line.text.strip()]
        message = "; ".join(lines) or root.findtext(".//msg") or "Unknown API error"
        return f"PAN-OS API error during {params.get('type', 'request')}: {message}"

    def get_rule_disabled(self, rulebase: str, rule_name: str) -> bool:
        xpath = self.rule_xpath(rulebase, rule_name)
        root = self.request_xml({"type": "config", "action": "get", "xpath": xpath})
        entry = root.find(".//result/entry")
        if entry is None:
            raise WorkflowError(f"{rulebase} rule {rule_name!r} was not found on the firewall")
        return (entry.findtext("disabled") or "no").strip().lower() == "yes"

    def set_rule_disabled(self, rulebase: str, rule_name: str, disabled: bool) -> None:
        xpath = self.rule_xpath(rulebase, rule_name)
        element = f"<disabled>{'yes' if disabled else 'no'}</disabled>"
        self.request_xml({"type": "config", "action": "set", "xpath": xpath, "element": element})

    def import_keypair(self, certificate_name: str, pkcs12_path: Path, passphrase: str) -> None:
        params = {
            "type": "import",
            "category": "keypair",
            "certificate-name": certificate_name,
            "format": "pkcs12",
            "passphrase": passphrase,
        }
        if self.config.certificate_vsys:
            params["vsys"] = self.config.certificate_vsys

        with pkcs12_path.open("rb") as handle:
            files = {"file": (pkcs12_path.name, handle, "application/x-pkcs12")}
            self.request_xml(params, files=files)

    def get_ssl_tls_profile_certificate(self) -> str | None:
        xpath = self.profile_xpath()
        root = self.request_xml({"type": "config", "action": "get", "xpath": xpath})
        entry = root.find(".//result/entry")
        if entry is None:
            raise WorkflowError(
                f"SSL/TLS profile {self.config.ssl_tls_profile_name!r} was not found on the firewall"
            )
        return empty_to_none(entry.findtext("certificate"))

    def update_ssl_tls_profile(self, certificate_name: str) -> None:
        xpath = self.profile_xpath()
        self.request_xml({"type": "config", "action": "get", "xpath": xpath})
        element = f"<certificate>{xml_escape(certificate_name)}</certificate>"
        self.request_xml({"type": "config", "action": "set", "xpath": xpath, "element": element})

    def commit(self, reason: str) -> None:
        logging.info("Committing firewall changes: %s", reason)
        root = self.request_xml({"type": "commit", "cmd": "<commit></commit>"})
        job_id = root.findtext(".//job") or root.findtext(".//jobid")
        if not job_id:
            return

        while True:
            time.sleep(self.config.poll_interval_seconds)
            job_root = self.request_xml(
                {
                    "type": "op",
                    "cmd": f"<show><jobs><id>{job_id}</id></jobs></show>",
                }
            )
            job = job_root.find(".//job")
            if job is None:
                continue

            status = (job.findtext("status") or "").strip().upper()
            result = (job.findtext("result") or "").strip().upper()

            if status != "FIN":
                continue

            if result == "OK":
                logging.info("Commit job %s completed successfully", job_id)
                return

            details = [line.text.strip() for line in job.findall(".//details/line") if line.text and line.text.strip()]
            detail_text = "; ".join(details) or (job.findtext("details") or result or "Unknown commit error")
            raise WorkflowError(f"Commit job {job_id} failed while {reason}: {detail_text}")


def snapshot_rule_state(client: PaloAltoClient, config: AppConfig) -> list[RuleState]:
    states = [
        RuleState(
            rulebase="nat",
            rule_name=config.palo_alto.nat_rule_name,
            disabled=client.get_rule_disabled("nat", config.palo_alto.nat_rule_name),
        )
    ]

    if config.palo_alto.security_rule_name:
        states.append(
            RuleState(
                rulebase="security",
                rule_name=config.palo_alto.security_rule_name,
                disabled=client.get_rule_disabled("security", config.palo_alto.security_rule_name),
            )
        )

    return states


def enable_acme_path(client: PaloAltoClient, states: list[RuleState]) -> bool:
    changed = False
    for state in states:
        if not state.disabled:
            continue
        logging.info("Enabling %s rule %s", state.rulebase, state.rule_name)
        client.set_rule_disabled(state.rulebase, state.rule_name, False)
        changed = True

    if changed:
        client.commit("opening ACME validation path")

    return changed


def restore_rule_state(client: PaloAltoClient, states: list[RuleState], commit_changes: bool) -> bool:
    changed = False
    for state in states:
        if not state.disabled:
            continue
        logging.info("Restoring %s rule %s to disabled", state.rulebase, state.rule_name)
        client.set_rule_disabled(state.rulebase, state.rule_name, True)
        changed = True

    if changed and commit_changes:
        client.commit("restoring ACME validation path")

    return changed


def sync_certificate_to_paloalto(
    client: PaloAltoClient,
    config: AppConfig,
    cert_path: Path,
    key_path: Path,
    chain_path: Path | None = None,
) -> str:
    fingerprint = certificate_fingerprint(cert_path)
    if not fingerprint:
        raise WorkflowError(f"Certificate file not found: {cert_path}")

    certificate_name = build_certificate_name(config.palo_alto.certificate_name_prefix, fingerprint)
    current_profile_certificate = client.get_ssl_tls_profile_certificate()

    if current_profile_certificate == certificate_name:
        logging.info(
            "SSL/TLS profile %s already uses certificate %s",
            config.palo_alto.ssl_tls_profile_name,
            certificate_name,
        )
        return certificate_name

    pkcs12_path, passphrase = build_pkcs12(
        config,
        certificate_name,
        cert_path,
        key_path,
        chain_path,
    )

    try:
        try:
            logging.info("Importing certificate %s into Palo Alto", certificate_name)
            client.import_keypair(certificate_name, pkcs12_path, passphrase)
        except WorkflowError as exc:
            if not is_duplicate_import_error(exc):
                raise
            logging.info("Certificate %s already exists on Palo Alto; reusing it", certificate_name)

        client.update_ssl_tls_profile(certificate_name)
        client.commit("activating the new GlobalProtect certificate")
    finally:
        pkcs12_path.unlink(missing_ok=True)

    logging.info(
        "Updated SSL/TLS profile %s to use certificate %s",
        config.palo_alto.ssl_tls_profile_name,
        certificate_name,
    )
    return certificate_name


def run_manual_certificate_update(args: argparse.Namespace, config: AppConfig) -> int:
    cert_path = args.incert.expanduser().resolve()
    key_path = args.inkey.expanduser().resolve()

    if not cert_path.exists():
        raise WorkflowError(f"Manual certificate file not found: {cert_path}")
    if not key_path.exists():
        raise WorkflowError(f"Manual key file not found: {key_path}")

    require_binary(config.openssl_path)
    client = PaloAltoClient(config.palo_alto)

    logging.info("Manual certificate mode: syncing %s and %s to Palo Alto", cert_path, key_path)
    sync_certificate_to_paloalto(client, config, cert_path, key_path)
    return 0


def main() -> int:
    args = parse_args()
    configure_logging(args.log_level)

    config = build_config()
    if args.manual_cert:
        return run_manual_certificate_update(args, config)

    require_binary(config.certbot.path)
    require_binary(config.openssl_path)

    cert_dir = config.certificate_directory
    previous_fingerprint = certificate_fingerprint(cert_dir / "cert.pem")
    client = PaloAltoClient(config.palo_alto)

    rule_states = snapshot_rule_state(client, config)
    acme_path_committed = False

    try:
        acme_path_committed = enable_acme_path(client, rule_states)

        run_command(
            build_certbot_command(config),
            f"Running Certbot for {config.domain}",
        )

        cert_path = cert_dir / "cert.pem"
        key_path = cert_dir / "privkey.pem"
        chain_path = cert_dir / "chain.pem"

        current_fingerprint = certificate_fingerprint(cert_path)
        if not current_fingerprint:
            raise WorkflowError("Certbot completed, but no local certificate was found afterwards")

        renewed = current_fingerprint != previous_fingerprint

        restore_rule_state(client, rule_states, commit_changes=acme_path_committed)
        acme_path_committed = False

        certificate_name = build_certificate_name(config.palo_alto.certificate_name_prefix, current_fingerprint)
        current_profile_certificate = client.get_ssl_tls_profile_certificate()

        if not renewed and current_profile_certificate == certificate_name:
            logging.info(
                "Certbot did not issue a new certificate and SSL/TLS profile %s already uses %s",
                config.palo_alto.ssl_tls_profile_name,
                certificate_name,
            )
            return 0

        if renewed:
            logging.info("Certbot issued a new certificate; uploading it to Palo Alto as %s", certificate_name)
        else:
            logging.info(
                "Certbot did not issue a new certificate; syncing the current local certificate to Palo Alto as %s",
                certificate_name,
            )

        sync_certificate_to_paloalto(client, config, cert_path, key_path, chain_path)
        return 0
    except Exception as exc:
        try:
            restore_rule_state(client, rule_states, commit_changes=acme_path_committed)
        except Exception as restore_exc:
            raise WorkflowError(f"{exc}; additionally failed to restore ACME access rules: {restore_exc}") from restore_exc
        raise WorkflowError(str(exc)) from exc


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except WorkflowError as exc:
        logging.error("%s", exc)
        raise SystemExit(1) from exc
