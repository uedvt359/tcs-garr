#!/usr/bin/env python

import argparse
import base64
import configparser
import getpass
import logging
import os
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
from tabulate import tabulate

from .harica_client import HaricaClient

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Handler console
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(console)

CONFIG_FILENAME = "tcs-garr.conf"
OUTPUT_FOLDER = "harica_certificates"


def load_config():
    """
    Load Harica configuration from a file in the current directory or the home directory.

    :return: (username, password, output_folder) tuple
    """
    paths = [
        os.path.join(os.getcwd(), CONFIG_FILENAME),
        os.path.join(os.path.expanduser("~"), CONFIG_FILENAME),
    ]
    for path in paths:
        if os.path.exists(path):
            config = configparser.RawConfigParser()
            config.read(path)
            username = config.get("harica", "username")
            password = config.get("harica", "password")
            totp_seed = config.get("harica", "totp_seed")
            output_folder = config.get("harica", "output_folder")

            # Set log file path
            log_file = os.path.join(output_folder, "harica.log")
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"))
            logger.addHandler(file_handler)

            return username, password, totp_seed, output_folder

    logger.error("Configuration file missing. You can generate it with 'tcs-garr init' command.")
    exit(1)


def create_config_file():
    """
    Create the Harica configuration file in the user's home directory.
    """
    paths = [
        os.path.join(os.getcwd(), CONFIG_FILENAME),
        os.path.join(os.path.expanduser("~"), CONFIG_FILENAME),
    ]
    for path in paths:
        if os.path.exists(path):
            logger.warning(
                f"Configuration file already exists at {path}. If you want to reinitialize TCS-GARR configuration, delete the file first."
            )
            return

    username = input(f"{Fore.GREEN}👤 Enter Harica email: {Style.RESET_ALL}")
    password = getpass.getpass(f"{Fore.GREEN}🔒 Enter Harica password: {Style.RESET_ALL}")
    totp_seed = getpass.getpass(f"{Fore.GREEN}🔒 Enter Harica TOTP Seed: {Style.RESET_ALL}")

    default_output_folder = os.path.join(os.path.expanduser("~"), OUTPUT_FOLDER)
    output_folder = (
        input(f"{Fore.GREEN}📂 Enter output folder (default is '{default_output_folder}'): {Style.RESET_ALL}")
        or default_output_folder
    )

    config_path = os.path.join(os.path.expanduser("~"), CONFIG_FILENAME)
    config = configparser.RawConfigParser()
    config["harica"] = {
        "username": username,
        "password": password,
        "totp_seed": totp_seed,
        "output_folder": output_folder,
    }
    with open(config_path, "w") as configfile:
        config.write(configfile)
    os.chmod(config_path, 0o400)
    logger.info(f"✨ Configuration file created at {config_path}")


def whoami(harica_client):
    user = harica_client.get_logged_in_user_profile()

    logger.info(f"{Fore.GREEN}👤 Logged in as {user['fullName']} ({user['email']}){Style.RESET_ALL}")


def validate_domains(harica_client, domains):
    harica_client.validate_domains(domains)
    for domain in domains:
        logger.info(
            f"{Fore.GREEN}✅ Domain {domain} prevalidation submitted. You will receive an email soon with token to configure DNS.{Style.RESET_ALL}"
        )


def list_certificates(harica_client, from_date, to_date):
    certificates = harica_client.list_certificates()
    data = []
    for item in sorted(certificates, key=lambda x: x["certificateValidTo"] if "certificateValidTo" in x else ""):
        expire_date_naive = parser.isoparse(item["certificateValidTo"])
        expire_date = pytz.utc.localize(expire_date_naive)
        if from_date < expire_date < to_date:
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
                data_to_write = "\n".join(cert.public_bytes(serialization.Encoding.PEM).decode("utf-8") for cert in pkcs7_cert)

    if data_to_write:
        if output_folder and output_filename:
            output_path = os.path.join(output_folder, output_filename)
            if os.path.exists(output_path) and not force:
                print(f"File {output_path} already exists. Use --force to overwrite.")
            else:
                with open(output_path, "w" if download_type != "pemBundle" else "wb") as cert_file:
                    cert_file.write(data_to_write if isinstance(data_to_write, bytes) else data_to_write.encode("utf-8"))
                print(f"Certificate saved to {output_path}")
        else:
            print(data_to_write)
    else:
        print(f"No data found for certificate ID {cert_id}.")


def approve_certificate(harica_client, id):
    if harica_client.approve_certificate(id):
        logger.info(f"Certificate with ID {id} has been approved.")
        logger.info(f"Requestor can download it with command: tcs-garr download --id {id} --output-filename <filename>.pem")
    else:
        logger.error(f"Failed to approve certificate with ID {id}.")


def issue_certificate(harica_client, cn, alt_names, output_folder):
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

    logger.info(f"{Fore.YELLOW}Submitting CSR to Harica... Please wait...{Style.RESET_ALL}")

    cert_id = harica_client.request_certificate(domains, csr.public_bytes(serialization.Encoding.PEM).decode())

    logger.info(f"{Fore.GREEN}CSR submitted with certificate ID {cert_id}.{Style.RESET_ALL}")
    logger.info(f"Ask another administrator to approve the certificate, using command: \n\ttcs-garr approve --id {cert_id}")
    logger.info(
        f"After administrator approve your request, you will able to download it using command: \n\tTo get fullchain: {Fore.BLUE}tcs-garr download --id {cert_id} --output-filename {cn}_fullchain.pem{Style.RESET_ALL}\n\tTo get only certificate: {Fore.BLUE}tcs-garr download --id {cert_id} --output-filename {cn}.pem --download-type certificate{Style.RESET_ALL}"
    )


def main():
    """
    Main function to handle command line arguments and initiate the certificate issuance or listing process.
    """
    parser = argparse.ArgumentParser(description="Harica Certificate Manager")

    parser.add_argument("--debug", action="store_true", default=False, help="Enable DEBUG logging.")

    subparser = parser.add_subparsers(dest="command")

    # Command to list certificates
    list_certificate_cmd = subparser.add_parser("list", help="Generate a report from Sectigo")
    list_certificate_cmd.add_argument(
        "--since",
        type=int,
        default=10,
        help="List certificates which expiry date is X days before now. Default is 10.",
    )
    list_certificate_cmd.add_argument(
        "--to", type=int, default=30, help="List certificates which expiry date is X days after now. Default is 30."
    )

    # Command to create a certificate
    create_cmd = subparser.add_parser("request", help="Request a new certificate")
    create_cmd.add_argument("--alt_names", default="", help="Comma separated alternative names.")
    create_cmd.add_argument("--cn", required=True, help="Common name of the certificate.")

    # Command to generate config file
    subparser.add_parser("init", help="Generate Sectigo config file")

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
    approve_certificate_cmd.add_argument("--id", required=True, help="ID of the certificate to approve.")

    # Command to get user profile
    subparser.add_parser("whoami", help="Get logged in user profile")

    # Command to create validation token
    validate_domains_cmd = subparser.add_parser("validate", help="Create validation token for domains")
    validate_domains_cmd.add_argument("--domains", required=True, help="Comma separated list of domains.")

    # Command to list domains validation token
    subparser.add_parser("domains", help="List available domains")

    args = parser.parse_args()

    if args.command == "init":
        create_config_file()
        return

    username, password, totp_seed, output_folder = load_config()

    harica_client = HaricaClient(username, password, totp_seed)

    if args.command == "request":
        issue_certificate(
            harica_client=harica_client,
            cn=args.cn,
            alt_names=args.alt_names,
            output_folder=output_folder,
        )
    elif args.command == "list":
        current_date = pytz.utc.localize(datetime.now())
        from_date = current_date - timedelta(days=args.since)
        to_date = current_date + timedelta(days=args.to)
        list_certificates(harica_client, from_date, to_date)
    elif args.command == "download":
        download_certificate(harica_client, args.id, args.download_type, output_folder, args.output_filename, args.force)
    elif args.command == "approve":
        approve_certificate(harica_client, args.id)
    elif args.command == "whoami":
        whoami(harica_client)
    elif args.command == "domains":
        list_domains(harica_client)
    elif args.command == "validate":
        validate_domains(harica_client, args.domains.split(","))


if __name__ == "__main__":
    main()
