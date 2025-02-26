from colorama import Fore, Style
from tcs_garr.commands.base import BaseCommand
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import os

from tcs_garr.utils import load_config


class RequestCommand(BaseCommand):
    """
    Command to request a new certificate by generating a CSR or submitting an existing one.

    This command allows the user to generate a Certificate Signing Request (CSR) or provide an existing CSR
    to request a new certificate from the Harica service. The user can choose between different certificate profiles
    (OV or DV), generate a CSR with a common name and alternative names, and submit the request for approval.

    Args:
        args (argparse.Namespace): The command-line arguments passed to the command.
    """

    def __init__(self, args):
        """
        Initializes the RequestCommand class.

        Args:
            args (argparse.Namespace): The command-line arguments passed to the command.
        """
        super().__init__(args)
        self.command_name = "request"
        self.help_text = "Request a new certificate"
        self.parser = None

    def configure_parser(self, parser):
        """
        Configures the argument parser for the request command.

        This method defines the arguments for requesting a new certificate:
        - --profile: Specifies the certificate profile (OV or DV).
        - --csr: Path to an existing CSR file.
        - --cn: Common Name for the certificate (used when no CSR is provided).
        - --alt_names: Comma-separated list of alternative names (used with --cn).

        Args:
            parser (argparse.ArgumentParser): The argument parser to configure.
        """
        self.parser = parser
        self.parser.add_argument(
            "--profile", default="OV", choices=["OV", "DV"], help="Profile to use between OV or DV. Default: OV"
        )

        # Create a mutually exclusive group for --csr and --cn (plus optional --alt_names)
        create_group = self.parser.add_mutually_exclusive_group(required=True)
        create_group.add_argument("--csr", type=str, help="Path to an existing CSR file.")

        # When no --csr is provided, user must provide --cn (with optional --alt_names)
        create_group.add_argument("--cn", help="Common name of the certificate.")
        self.parser.add_argument("--alt_names", default="", help="Comma-separated alternative names (only used with --cn).")

    def get_output_folder(self):
        """
        Retrieve the default output folder from the configuration.

        Args:
            args (argparse.Namespace): The command-line arguments passed to the command.

        Returns:
            str: The output folder path from the configuration.
        """
        # Load environment-specific configuration
        username, password, totp_seed, output_folder = load_config(self.args.environment)
        return output_folder

    def execute(self):
        """
        Executes the command to generate a CSR or request a certificate.

        This method handles the logic to either generate a CSR and submit it or submit an existing CSR.
        It also ensures that the --alt_names argument is only used with the --cn argument.
        """
        # Additional logic to ensure --alt_names is only used with --cn and not with --csr
        if self.args.csr and self.args.alt_names:
            self.parser.error("--alt_names cannot be used with --csr.")
            exit(1)

        harica_client = self.harica_client()
        output_folder = self.get_output_folder()

        if self.args.cn:
            # Generate a CSR and request a certificate
            csr_path = self.__generate_key_csr(harica_client, self.args.cn, self.args.alt_names, output_folder)
            self.__issue_certificate(harica_client, csr_path, self.args.profile)
        else:
            # CSR has been provided, just issue the certificate
            self.__issue_certificate(harica_client, self.args.csr, self.args.profile)

    def __generate_key_csr(self, harica_client, cn, alt_names, output_folder):
        """
        Generates a private key and CSR for the specified common name and alternative names.

        This method generates an RSA private key, creates a CSR with the provided common name (CN) and alternative
        names (SANs), and saves both the private key and CSR to the specified output folder.

        Args:
            harica_client (object): The Harica client to interact with the API.
            cn (str): The Common Name for the certificate.
            alt_names (str): A comma-separated list of alternative names.
            output_folder (str): The folder where the private key and CSR will be saved.

        Returns:
            str: The file path to the generated CSR.
        """
        # Create the list of domains, including the CN and SANs
        domains = [cn]
        for alt_name in alt_names.split(","):
            if alt_name and alt_name not in domains:
                domains.append(alt_name)

        organizations = harica_client.get_matching_organizations(domains)

        if not organizations:
            self.logger.error("No available organization for this domain list")
            return

        if len(organizations) > 1:
            self.logger.error("Multiple orgs possible but no selection made (use -O org)")
            return

        organization = organizations[0]

        self.logger.info(
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
        self.logger.info(f"{Fore.BLUE}Private key created in {key_path}{Style.RESET_ALL}")
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
        self.logger.info(f"{Fore.BLUE}CSR created in {csr_path}{Style.RESET_ALL}")

        return csr_path

    def __issue_certificate(self, harica_client, csr_file, profile):
        """
        Issues a certificate request by submitting a CSR to the Harica client.

        This method reads the provided CSR file, validates it, and submits it to the Harica client for certification.
        It also handles logging and outputs relevant information, including certificate IDs and download instructions.

        Args:
            harica_client (object): The Harica client to interact with the API.
            csr_file (str): The path to the CSR file.
            profile (str): The certificate profile (OV or DV) to use for the request.
        """
        try:
            with open(csr_file, "rb") as f:
                csr = x509.load_pem_x509_csr(f.read(), default_backend())

                cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                alt_names = [x.value for x in csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]

                # Check if the number of SANs is 10 or more and print a warning
                if len(alt_names) >= 10:
                    self.logger.warning(
                        f"{Fore.RED}Warning: Certificates with more than 10 SANs might be refused.{Style.RESET_ALL}"
                    )

                domains = [cn]
                for alt_name in alt_names:
                    if alt_name and alt_name not in domains:
                        domains.append(alt_name)

                self.logger.info(f"{Fore.YELLOW}Submitting CSR to Harica... Please wait...{Style.RESET_ALL}")

                cert_id = harica_client.request_certificate(
                    domains, csr.public_bytes(serialization.Encoding.PEM).decode(), profile
                )

                self.logger.info(f"{Fore.GREEN}CSR submitted with certificate ID {cert_id}.{Style.RESET_ALL}")

                id_file = f"{csr_file}.id"
                with open(id_file, "w") as id_f:
                    id_f.write(cert_id)
                self.logger.info(f"{Fore.GREEN}Certificate ID written to {id_file}.{Style.RESET_ALL}")

                self.logger.info(
                    f"Ask another administrator to approve the certificate, using command: \n\ttcs-garr approve --id {cert_id}"
                )
                self.logger.info(
                    f"After administrator approval, you will be able to download it using command: \n\tTo get fullchain: {Fore.BLUE}tcs-garr download --id {cert_id} --output-filename {cn}_fullchain.pem{Style.RESET_ALL}\n\tTo get only certificate: {Fore.BLUE}tcs-garr download --id {cert_id} --output-filename {cn}.pem --download-type certificate{Style.RESET_ALL}"
                )

        except FileNotFoundError:
            self.logger.error(f"{Fore.RED}CSR file {csr_file} not found.{Style.RESET_ALL}")
            exit(1)
