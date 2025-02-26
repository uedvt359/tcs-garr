#!/usr/bin/env python

import argparse
import base64
import configparser
import getpass
import logging
import os
import re
from datetime import datetime, timedelta

import pytz
from colorama import Fore, Style
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from dateutil import parser
from packaging import version
from tabulate import tabulate

from .exceptions import NoHaricaAdminException, NoHaricaApproverException
from .harica_client import HaricaClient
from .utils import check_pypi_version, generate_otp, get_current_version, upgrade_package

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Handler console
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(console)

CONFIG_FILENAME = "tcs-garr.conf"
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".config", "tcs-garr", CONFIG_FILENAME)
OUTPUT_FOLDER = "harica_certificates"
OUTPUT_PATH = os.path.join(os.path.expanduser("~"), OUTPUT_FOLDER)
CONFIG_PATHS = [
    os.path.join(os.getcwd(), CONFIG_FILENAME),
    CONFIG_PATH,
]


def validate_config(config_data):
    """
    Validates that all required configuration fields are present and correct.

    :param config_data: Dictionary containing configuration values.
    """
    missing_fields = [key for key, value in config_data.items() if not value]
    if missing_fields:
        logger.error(f"❌ Missing configuration values for: {', '.join(missing_fields)}")
        exit(1)

    # Validate email
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    valid = re.match(pattern, config_data["username"])
    if not valid:
        logger.error(f"❌ Invalid email format for username: {config_data['username']}")
        exit(1)

    # Validate TOTP seed
    try:
        generate_otp(config_data["totp_seed"])
    except ValueError:
        logger.error(f"❌ Invalid TOTP seed: {config_data['totp_seed']}")
        exit(1)


def load_config(environment="production"):
    """
    Load Harica configuration based on the environment.
    """

    # Determine the section name based on the environment
    section_name = f"harica-{environment}" if environment != "production" else "harica"

    config_data = None

    for path in CONFIG_PATHS:
        if os.path.exists(path):
            config = configparser.RawConfigParser()
            config.read(path)

            if config.has_section(section_name):
                config_data = {
                    "username": config.get(section_name, "username"),
                    "password": config.get(section_name, "password"),
                    "totp_seed": config.get(section_name, "totp_seed"),
                    "output_folder": config.get(section_name, "output_folder"),
                }
            else:
                logger.error(f"No configuration found for environment '{environment}' in {path}")
                exit(1)
            break

    # Fallback to env variables if no config file
    if config_data is None:
        logger.info("No config file found. Falling back to environment variables.")
        config_data = {
            "username": os.getenv("HARICA_USERNAME"),
            "password": os.getenv("HARICA_PASSWORD"),
            "totp_seed": os.getenv("HARICA_TOTP_SEED"),
            "output_folder": os.getenv("HARICA_OUTPUT_FOLDER", OUTPUT_PATH),
        }

        # Ensure all required environment variables are set
        if not all([config_data["username"], config_data["password"], config_data["totp_seed"]]):
            logger.error(
                "Configuration file or environment variables missing. "
                "Generate config file with 'tcs-garr init' command or set "
                "HARICA_USERNAME, HARICA_PASSWORD and HARICA_TOTP_SEED "
                "environment variables."
            )
            exit(1)

    validate_config(config_data)

    # Set log file path
    log_file = os.path.join(config_data["output_folder"], "harica.log")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(file_handler)

    return (
        config_data["username"],
        config_data["password"],
        config_data["totp_seed"],
        config_data["output_folder"],
    )


def bc_move_previous_config():
    """
    Move an existing config file from the home directory to the new CONFIG_PATH.

    This function must be removed in future releases.
    """
    import shutil

    old_config_path = os.path.join(os.path.expanduser("~"), CONFIG_FILENAME)

    # Check if the old config file exists
    if os.path.exists(old_config_path):
        # Create directories that host config file
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)

        # Move the config file
        try:
            shutil.move(old_config_path, CONFIG_PATH)
            logger.debug("Moved existing config.")
        except Exception as e:
            logger.error(f"Failed to move config: {e}")
    else:
        logger.debug("No existing config file found to move.")


def create_config_file(environment="production", force=False):
    """
    Create or update the Harica configuration file in the user's home directory
    for the specified environment.
    """
    config = configparser.RawConfigParser()

    # Check if the configuration file exists
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)  # Read existing configuration file

    # Create directories that host config file
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)

    # Set the section name based on the environment
    section_name = f"harica-{environment}" if environment != "production" else "harica"

    # Check if section already exists
    if config.has_section(section_name) and not force:
        logger.warning(
            f"Configuration for '{environment}' environment already exists in {CONFIG_PATH}. "
            f"If you want to reinitialize the configuration, use the --force option."
        )
        return

    username = input(f"{Fore.GREEN}👤 Enter Harica email: {Style.RESET_ALL}")
    password = getpass.getpass(f"{Fore.GREEN}🔒 Enter Harica password: {Style.RESET_ALL}")
    totp_seed = getpass.getpass(f"{Fore.GREEN}🔒 Enter Harica TOTP Seed: {Style.RESET_ALL}")

    output_folder = input(f"{Fore.GREEN}📂 Enter output folder (default is '{OUTPUT_PATH}'): {Style.RESET_ALL}") or OUTPUT_PATH
    # Expand in case input was a relative path
    output_folder = os.path.abspath(os.path.expanduser(output_folder))

    config[section_name] = {
        "username": username,
        "password": password,
        "totp_seed": totp_seed,
        "output_folder": output_folder,
    }
    with open(CONFIG_PATH, "w") as configfile:
        config.write(configfile)

    os.chmod(CONFIG_PATH, 0o600)

    logger.info(f"✨ Configuration for '{environment}' environment updated at {CONFIG_PATH}")


def whoami(harica_client):
    user = harica_client.get_logged_in_user_profile()
    logger.info(f"{Fore.GREEN}👤 Logged in as {user['fullName']} ({user['email']}){Style.RESET_ALL}")


def self_upgrade_package():
    current_version = get_current_version()
    latest_version = check_pypi_version()

    if version.parse(latest_version) > version.parse(current_version):
        logger.info(f"Upgrading from {current_version} to {latest_version}...")
        upgrade_package()
        logger.info(f"Successfully upgraded to {latest_version}")
    else:
        logger.info(f"Already at the latest version: {current_version}")


def validate_domains(harica_client, domains):
    harica_client.validate_domains(domains)
    for domain in domains:
        logger.info(
            f"{Fore.GREEN}✅ Domain {domain} prevalidation submitted. You will receive an email soon with token to configure DNS.{Style.RESET_ALL}"
        )


def list_certificates(harica_client, expired_since=None, expiring_in=None):
    current_date = pytz.utc.localize(datetime.now())

    # Set from_date and to_date only if expired_since or expiring_in are provided
    from_date = current_date - timedelta(days=expired_since) if expired_since is not None else None
    to_date = current_date + timedelta(days=expiring_in) if expiring_in is not None else None

    certificates = harica_client.list_certificates()
    data = []

    # Sort certificates by "certificateValidTo"
    for item in sorted(certificates, key=lambda x: x["certificateValidTo"] if "certificateValidTo" in x else ""):
        expire_date_naive = parser.isoparse(item["certificateValidTo"])
        expire_date = pytz.utc.localize(expire_date_naive)

        # Check if the certificate's expiry date is within the range (if range is defined)
        if (from_date is None or expire_date <= from_date) and (to_date is None or expire_date < to_date):
            status_fields = {
                "isEidasValidated": item.get("isEidasValidated"),
                "isExpired": item.get("isExpired"),
                "isHighRisk": item.get("isHighRisk"),
                "isPaid": item.get("isPaid"),
                "isPendingP12": item.get("isPendingP12"),
                "isRevoked": item.get("isRevoked"),
            }

            # Filter out None or False values, and keep only the keys that are True
            status = [field for field, value in status_fields.items() if value]
            data.append(
                [
                    item["dN"],
                    item["certificateValidTo"],
                    ", ".join(status) if status else "",
                    ";".join([subjAltName["fqdn"] for subjAltName in item["domains"]]) if "domains" in item else "",
                    item["user"],
                ]
            )

    logger.info(
        tabulate(
            data,
            headers=[
                Fore.BLUE + "dN",
                "Expire at",
                "Status",
                "AltNames",
                "Requested by" + Style.RESET_ALL,
            ],
        )
    )


def list_domains(harica_client):
    current_time = datetime.now()
    for item in harica_client.list_domains():
        domain = item["domain"]
        validity = datetime.strptime(item["validity"], "%Y-%m-%dT%H:%M:%S.%f")
        remaining_days = (validity - current_time).days

        if remaining_days < 0:
            # If the domain has expired, log in RED
            logger.info(f"{Fore.RED}{domain} expired on {validity.date()}{Style.RESET_ALL}")
        elif remaining_days <= 30:
            # If the domain is expiring in the next 30 days, log in YELLOW
            logger.info(f"{Fore.YELLOW}{domain} expiring on {validity.date()} ({remaining_days} days left){Style.RESET_ALL}")
        else:
            # If the domain is valid and has more than 30 days left, log in GREEN
            logger.info(f"{Fore.GREEN}{domain} valid until {validity.date()} ({remaining_days} days left){Style.RESET_ALL}")


def download_certificate(
    harica_client, cert_id, download_type="pemBundle", output_folder=None, output_filename=None, force=False
):
    """
    Download the certificate and optionally save it to a file or print it to the console.

    Args:
        harica_client: The client used to interact with the Harica API.
        cert_id: The ID of the certificate to download.
        download_type: Type of download, either 'pemBundle' or 'certificate'. Default is 'pemBundle'.
        output_folder: Folder to save the certificate.
        output_filename: Filename to save the certificate.
        force: Flag to force overwrite if the file already exists.
    """
    certificate = harica_client.get_certificate(cert_id)
    data_to_write = certificate.get(download_type)

    if not data_to_write and download_type == "pemBundle":
        # Handle pKCS7 data
        p7b_data_string = certificate.get("pKCS7")
        p7b_base64 = p7b_data_string.replace("-----BEGIN PKCS7-----", "").replace("-----END PKCS7-----", "").strip()
        p7b_data = base64.b64decode(p7b_base64)

        if p7b_data:
            pkcs7_cert = pkcs7.load_der_pkcs7_certificates(p7b_data)
            if pkcs7_cert:
                data_to_write = "".join(cert.public_bytes(serialization.Encoding.PEM).decode("utf-8") for cert in pkcs7_cert)

    if data_to_write:
        if output_folder and output_filename:
            output_path = os.path.join(output_folder, output_filename)
            if os.path.exists(output_path) and not force:
                print(f"File {output_path} already exists. Use --force to overwrite.")
            else:
                # Write to the file with appropriate mode
                with open(output_path, "wb" if isinstance(data_to_write, bytes) else "w") as cert_file:
                    cert_file.write(data_to_write)
                print(f"Certificate saved to {output_path}")
        else:
            print(data_to_write)

    else:
        print(f"No data found for certificate ID {cert_id}.")


def list_pending_certificates(harica_client):
    transactions = harica_client.get_pending_transactions()

    data = []
    for item in transactions:
        data.append(
            [
                item["transactionId"],
                ",".join([domain["fqdn"] for domain in item["domains"]]),
                item["transactionStatus"],
                item["user"],
            ]
        )

    logger.info(
        tabulate(
            data,
            headers=[
                Fore.BLUE + "ID",
                "CN",
                "Status",
                "Requested by" + Style.RESET_ALL,
            ],
        )
    )


def approve_transactions(harica_client, ids=None):
    if ids is None:
        # If no IDs are provided, get the pending transactions
        transactions = harica_client.get_pending_transactions()
        ids = [transaction["transactionId"] for transaction in transactions]

    for id in ids:
        try:
            if harica_client.approve_transaction(id):
                logger.info(f"Certificate with ID {id} has been approved.")
                logger.info(
                    f"Requestor can download it with command: tcs-garr download --id {id} --output-filename <filename>.pem"
                )
            else:
                logger.error(f"Failed to approve certificate with ID {id}.")
        except PermissionError:
            logger.error(f"Failed to approve certificate with ID {id}. You cannot approve your own request.")


def cancel_transaction(harica_client, id):
    if harica_client.cancel_transaction(id):
        logger.info(f"Transaction with ID {id} has been canceled.")
    else:
        logger.error(f"Failed to cancel transaction with ID {id}.")


def generate_key_csr(harica_client, cn, alt_names, output_folder):
    domains = [cn]
    for alt_name in alt_names.split(","):
        if alt_name and alt_name not in domains:
            domains.append(alt_name)

    organizations = harica_client.get_matching_organizations(domains)

    if not organizations:
        logger.error("No available organization for this domain list")
        return

    if len(organizations) > 1:
        logger.error("Multiple orgs possible but no selection made (use -O org)")
        return

    organization = organizations[0]

    logger.info(
        f"{Fore.GREEN}Selected organization: {organization['organizationName']} ({organization['id']}){Style.RESET_ALL}"
    )

    # Generate the private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

    # Write the private key to disk
    os.makedirs(output_folder, exist_ok=True)
    key_path = os.path.join(output_folder, f"{cn}.key")
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    logger.info(f"{Fore.BLUE}Private key created in {key_path}{Style.RESET_ALL}")
    os.chmod(key_path, 0o600)

    # Prepare Subject Alternative Names
    subject_alt_names = {cn, *filter(None, alt_names.split(","))}

    # Generate a CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, organization["country"].upper()),
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                ]
            )
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(x) for x in subject_alt_names]),
            critical=False,
        )
        .sign(key, hashes.SHA512(), default_backend())
    )

    # Write the CSR to disk
    csr_path = os.path.join(output_folder, f"{cn}.csr")
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    logger.info(f"{Fore.BLUE}CSR created in {csr_path}{Style.RESET_ALL}")

    return csr_path


def issue_certificate(harica_client, csr_file, profile):
    try:
        with open(csr_file, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read(), default_backend())

            cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            alt_names = [x.value for x in csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]

            # Check if the number of SANs is 10 or more and print a warning
            if len(alt_names) >= 10:
                logger.warning(f"{Fore.RED}Warning: Certificates with more than 10 SANs might be refused.{Style.RESET_ALL}")

            domains = [cn]
            for alt_name in alt_names:
                if alt_name and alt_name not in domains:
                    domains.append(alt_name)

            logger.info(f"{Fore.YELLOW}Submitting CSR to Harica... Please wait...{Style.RESET_ALL}")

            cert_id = harica_client.request_certificate(
                domains, csr.public_bytes(serialization.Encoding.PEM).decode(), profile
            )

            logger.info(f"{Fore.GREEN}CSR submitted with certificate ID {cert_id}.{Style.RESET_ALL}")

            id_file = f"{csr_file}.id"
            with open(id_file, "w") as id_f:
                id_f.write(cert_id)
            logger.info(f"{Fore.GREEN}Certificate ID written to {id_file}.{Style.RESET_ALL}")

            logger.info(
                f"Ask another administrator to approve the certificate, using command: \n\ttcs-garr approve --id {cert_id}"
            )
            logger.info(
                f"After administrator approval, you will be able to download it using command: \n\tTo get fullchain: {Fore.BLUE}tcs-garr download --id {cert_id} --output-filename {cn}_fullchain.pem{Style.RESET_ALL}\n\tTo get only certificate: {Fore.BLUE}tcs-garr download --id {cert_id} --output-filename {cn}.pem --download-type certificate{Style.RESET_ALL}"
            )

    except FileNotFoundError:
        logger.error(f"{Fore.RED}CSR file {csr_file} not found.{Style.RESET_ALL}")
        exit(1)


def generate_k8s_secret(cert_path, key_path, namespace, output_folder):
    """
    Generates a Kubernetes secret YAML file for the given certificate and key files.
    """
    name = os.path.splitext(os.path.basename(key_path))[0]

    with open(cert_path, "r") as cert_file:
        cert_b64 = base64.b64encode(cert_file.read().encode("utf-8")).decode("utf-8")

    with open(key_path, "r") as key_file:
        key_b64 = base64.b64encode(key_file.read().encode("utf-8")).decode("utf-8")

    secret_yaml = f"""---
apiVersion: v1
kind: Secret
type: kubernetes.io/tls
metadata:
  name: {name}-tls
  namespace: {namespace}
data:
  tls.crt: >-
      {cert_b64}
  tls.key: >-
      {key_b64}
"""

    output_file = os.path.join(output_folder, f"{name}.yml")
    with open(output_file, "w") as f:
        f.write(secret_yaml)

    logger.info(f"{Fore.GREEN}Kubernetes secret YAML generated at {output_file}.{Style.RESET_ALL}")


def main():
    """
    Main function to handle command line arguments and initiate the certificate issuance or listing process.
    """
    parser = argparse.ArgumentParser(description="Harica Certificate Manager")

    parser.add_argument("--debug", action="store_true", default=False, help="Enable DEBUG logging.")
    parser.add_argument(
        "--version",
        action="version",
        version=get_current_version(),
    )
    subparser = parser.add_subparsers(dest="command")

    parser.add_argument(
        "--environment",
        choices=["production", "stg"],
        default="production",
        help="Specify the environment to use (default: production)",
    )

    # Command to self upgrade package
    subparser.add_parser("upgrade", help="Self-upgrade command for the app.")

    # Command to list certificates
    list_certificate_cmd = subparser.add_parser("list", help="Generate a report from Harica")
    list_certificate_cmd.add_argument(
        "--expired-since",
        type=int,
        help="List certificates which expiry date is X days before now.",
    )
    list_certificate_cmd.add_argument(
        "--expiring-in", type=int, help="List certificates which expiry date is X days after now."
    )

    # Command to create a certificate
    create_cmd = subparser.add_parser("request", help="Request a new certificate")

    create_cmd.add_argument(
        "--profile", default="OV", choices=["OV", "DV"], help="Profile to use between OV or DV. Default: OV"
    )

    # Create a mutually exclusive group for --csr and --cn (plus optional --alt_names)
    create_group = create_cmd.add_mutually_exclusive_group(required=True)
    create_group.add_argument("--csr", type=str, help="Path to an existing CSR file.")

    # When no --csr is provided, user must provide --cn (with optional --alt_names)
    create_group.add_argument("--cn", help="Common name of the certificate.")
    create_cmd.add_argument("--alt_names", default="", help="Comma-separated alternative names (only used with --cn).")

    # Command to generate config file
    init_cmd = subparser.add_parser("init", help="Generate Harica config file")
    init_cmd.add_argument("--force", "-f", action="store_true", help="Force overwrite configuration file.")

    # Command to download a certificate by ID
    get_certificate_cmd = subparser.add_parser("download", help="Download a certificate by ID")
    get_certificate_cmd.add_argument("--id", required=True, help="ID of the certificate to download.")
    get_certificate_cmd.add_argument(
        "--output-filename", default=None, help="Optional filename to save the certificate inside default output_folder."
    )
    get_certificate_cmd.add_argument(
        "--force", "-f", action="store_true", help="Force overwrite if the output file already exists."
    )
    get_certificate_cmd.add_argument(
        "--download-type",
        choices=["pemBundle", "certificate"],
        default="pemBundle",
        help="Type of download: 'pemBundle' or 'certificate'. Default is 'pemBundle'.",
    )

    # Command to approve certificate by ID
    approve_certificate_cmd = subparser.add_parser("approve", help="Approve a certificate by ID")

    # Create a mutually exclusive group
    approve_certificate_group = approve_certificate_cmd.add_mutually_exclusive_group(required=True)

    # Add --id and --list-pending as mutually exclusive arguments
    approve_certificate_group.add_argument("--id", help="ID of the certificates (comma separated) to approve.")
    approve_certificate_group.add_argument("--list-pending", action="store_true", help="List all pending requests.")
    approve_certificate_group.add_argument("--all", action="store_true", help="Approve all pending requests.")

    # Command to get user profile
    subparser.add_parser("whoami", help="Get logged in user profile")

    # Command to create validation token
    validate_domains_cmd = subparser.add_parser("validate", help="Create validation token for domains")
    validate_domains_cmd.add_argument("--domains", required=True, help="Comma separated list of domains.")

    # Command to list domains validation token
    subparser.add_parser("domains", help="List available domains")

    # Command to cancel pending request
    cancel_cmd = subparser.add_parser("cancel", help="Cancel a request by ID")
    cancel_cmd.add_argument("--id", required=True, help="ID of the request to cancel.")

    # Generate Kubernetes tls resource file
    k8s_cmd = subparser.add_parser("k8s", help="Generate Kubernetes tls resource file")
    k8s_cmd.add_argument("--cert", required=True, help="Path to the certificate file.")
    k8s_cmd.add_argument("--key", required=True, help="Path to the key file.")
    k8s_cmd.add_argument("--namespace", required=True, help="Kubernetes namespace for the secret.")

    args = parser.parse_args()

    bc_move_previous_config()

    if args.command == "init":
        create_config_file(args.environment, args.force)
        return

    if args.command == "upgrade":
        self_upgrade_package()
        return

    username, password, totp_seed, output_folder = load_config(args.environment)

    try:
        harica_client = HaricaClient(username, password, totp_seed, environment=args.environment)
    except NoHaricaAdminException:
        logger.error(f"{Fore.RED}No Harica Admin role found in the user profile.{Style.RESET_ALL}")
        exit(1)
    except NoHaricaApproverException:
        logger.error(f"{Fore.RED}No Harica Approver role found in the user profile.{Style.RESET_ALL}")
        exit(1)

    if args.command == "request":
        # Additional logic to ensure --alt_names is only used with --cn and not with --csr
        if args.csr and args.alt_names:
            parser.error("--alt_names cannot be used with --csr.")
            exit(1)

        if args.cn:
            csr_path = generate_key_csr(harica_client, args.cn, args.alt_names, output_folder)
            issue_certificate(harica_client, csr_path, args.profile)
        else:
            # CSR has been provided
            issue_certificate(harica_client, args.csr, args.profile)
    elif args.command == "list":
        list_certificates(harica_client, args.expired_since, args.expiring_in)
    elif args.command == "download":
        download_certificate(harica_client, args.id, args.download_type, output_folder, args.output_filename, args.force)
    elif args.command == "approve":
        if args.id:
            approve_transactions(harica_client, args.id.split(","))
        elif args.all:
            approve_transactions(harica_client)
        elif args.list_pending:
            list_pending_certificates(harica_client)
    elif args.command == "whoami":
        whoami(harica_client)
    elif args.command == "domains":
        list_domains(harica_client)
    elif args.command == "validate":
        validate_domains(harica_client, args.domains.split(","))
    elif args.command == "cancel":
        cancel_transaction(harica_client, args.id)
    elif args.command == "k8s":
        generate_k8s_secret(args.cert, args.key, args.namespace, output_folder)


if __name__ == "__main__":
    main()
