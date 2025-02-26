import base64
import os

from colorama import Fore, Style

from tcs_garr.commands.base import BaseCommand
from tcs_garr.utils import load_config


class K8sCommand(BaseCommand):
    """
    Command to generate a Kubernetes TLS secret YAML file from a certificate and key.

    Args:
        args (argparse.Namespace): The command-line arguments passed to the command.
    """

    def __init__(self, args):
        """
        Initializes the K8sCommand class.

        Args:
            args (argparse.Namespace): The command-line arguments passed to the command.
        """
        super().__init__(args)
        self.command_name = "k8s"
        self.help_text = "Generate Kubernetes TLS resource file"

    def configure_parser(self, parser):
        """
        Configures the argument parser for the command.

        Args:
            parser (argparse.ArgumentParser): The argument parser to configure.
        """
        # Argument for the certificate file path
        parser.add_argument("--cert", required=True, help="Path to the certificate file.")
        # Argument for the key file path
        parser.add_argument("--key", required=True, help="Path to the key file.")
        # Argument for the Kubernetes namespace where the secret will be created
        parser.add_argument("--namespace", required=True, help="Kubernetes namespace for the secret.")

    def get_output_folder(self):
        """
        Retrieve the default output folder from the configuration.

        Returns:
            str: The output folder path from the configuration.
        """
        # Load environment-specific configuration to get the output folder
        username, password, totp_seed, output_folder = load_config(self.args.environment)
        return output_folder

    def execute(self):
        """
        Executes the command to generate a Kubernetes TLS secret YAML file.

        The file is created based on the provided certificate and key files, and the generated YAML is saved to the output folder.
        """
        # Get the name for the secret from the key file name (without the extension)
        name = os.path.splitext(os.path.basename(self.args.key))[0]

        # Read and encode the certificate file in base64
        with open(self.args.cert, "r") as cert_file:
            cert_b64 = base64.b64encode(cert_file.read().encode("utf-8")).decode("utf-8")

        # Read and encode the key file in base64
        with open(self.args.key, "r") as key_file:
            key_b64 = base64.b64encode(key_file.read().encode("utf-8")).decode("utf-8")

        # Generate the Kubernetes secret YAML content
        secret_yaml = f"""---
apiVersion: v1
kind: Secret
type: kubernetes.io/tls
metadata:
name: {name}-tls
namespace: {self.args.namespace}
data:
tls.crt: >-
    {cert_b64}
tls.key: >-
    {key_b64}
"""

        # Define the output file path where the secret YAML will be saved
        output_file = os.path.join(self.get_output_folder(), f"{name}.yml")

        # Write the generated YAML content to the output file
        with open(output_file, "w") as f:
            f.write(secret_yaml)

        # Log the completion of the secret YAML generation
        self.logger.info(f"{Fore.GREEN}Kubernetes secret YAML generated at {output_file}.{Style.RESET_ALL}")
