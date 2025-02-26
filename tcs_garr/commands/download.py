import base64
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from tcs_garr.commands.base import BaseCommand
from tcs_garr.utils import load_config


class DownloadCommand(BaseCommand):
    """
    Command to download a certificate by ID and save it to a specified file or print it.

    Args:
        args (argparse.Namespace): The command-line arguments passed to the command.
    """

    def __init__(self, args):
        super().__init__(args)
        self.command_name = "download"
        self.help_text = "Download a certificate by ID"

    def configure_parser(self, parser):
        """
        Configures the argument parser for the command.

        Args:
            parser (argparse.ArgumentParser): The argument parser to configure.
        """
        # Add the argument to specify the certificate ID to download
        parser.add_argument("--id", required=True, help="ID of the certificate to download.")

        # Optional output filename for saving the certificate
        parser.add_argument(
            "--output-filename",
            default=None,
            help="Optional filename to save the certificate inside the default output folder.",
        )
        # Add force flag to allow overwriting the file
        parser.add_argument("--force", "-f", action="store_true", help="Force overwrite if the output file already exists.")

        # Specify the type of download (either 'pemBundle' or 'certificate')
        parser.add_argument(
            "--download-type",
            choices=["pemBundle", "certificate"],
            default="pemBundle",
            help="Type of download: 'pemBundle' or 'certificate'. Default is 'pemBundle'.",
        )

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
        Executes the command to download the certificate by ID, and saves or prints the certificate data.

        If the certificate data is a PKCS7 bundle, it will be processed accordingly.
        """
        harica_client = self.harica_client()
        # Fetch the certificate using the provided ID
        certificate = harica_client.get_certificate(self.args.id)

        # Get the data of the specified download type
        data_to_write = certificate.get(self.args.download_type)

        # If no data is found for 'pemBundle', handle the PKCS7 format
        if not data_to_write and self.args.download_type == "pemBundle":
            # Get the PKCS7 encoded data and decode it
            p7b_data_string = certificate.get("pKCS7")
            p7b_base64 = p7b_data_string.replace("-----BEGIN PKCS7-----", "").replace("-----END PKCS7-----", "").strip()
            p7b_data = base64.b64decode(p7b_base64)

            # Load and extract the certificates from the PKCS7 data
            if p7b_data:
                pkcs7_cert = pkcs7.load_der_pkcs7_certificates(p7b_data)
                if pkcs7_cert:
                    # Convert certificates to PEM format and join them into a single string
                    data_to_write = "".join(
                        cert.public_bytes(serialization.Encoding.PEM).decode("utf-8") for cert in pkcs7_cert
                    )

        if data_to_write:
            # Determine the output folder from the config
            output_folder = self.get_output_folder()

            # If the output folder and filename are provided, save the certificate to a file
            if output_folder and self.args.output_filename:
                output_path = os.path.join(output_folder, self.args.output_filename)

                # Check if the file already exists, and handle the force flag for overwriting
                if os.path.exists(output_path) and not self.args.force:
                    print(f"File {output_path} already exists. Use --force to overwrite.")
                else:
                    # Write the certificate data to the file (binary or text based on data type)
                    with open(output_path, "wb" if isinstance(data_to_write, bytes) else "w") as cert_file:
                        cert_file.write(data_to_write)
                    print(f"Certificate saved to {output_path}")
            else:
                # If no filename is provided, print the certificate data
                print(data_to_write)
        else:
            # Handle case where no data is found for the given certificate ID
            print(f"No data found for certificate ID {self.args.id}.")
