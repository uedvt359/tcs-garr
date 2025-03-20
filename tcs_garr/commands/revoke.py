from datetime import datetime

from colorama import Fore, Style

from tcs_garr.commands.base import BaseCommand


class RevokeCommand(BaseCommand):
    """
    Command to revoke a certificate.

    Args:
        args (argparse.Namespace): The command-line arguments passed to the command.
    """

    def __init__(self, args):
        """
        Initializes the CancelCommand class.

        Args:
            args (argparse.Namespace): The command-line arguments passed to the command.
        """
        super().__init__(args)
        self.command_name = "revoke"
        self.help_text = "Revoke a certificate by ID"

    def configure_parser(self, parser):
        """
        Configures the argument parser for the command.

        Args:
            parser (argparse.ArgumentParser): The argument parser to configure.
        """
        # Argument for the certificate ID that will be canceled
        parser.add_argument(
            "--id",
            required=True,
            help="ID of the certificate to revoke.",
        )

    def execute(self):
        """
        Executes the command to revoke a certificate using the provided ID.
        """
        harica_client = self.harica_client()

        id = self.args.id
        cert = harica_client.get_certificate(id)

        if cert["isRevoked"]:
            self.logger.error("Certificate is already revoked.")
            exit(1)

        # Use sANS for confirmation
        dns_names = [dns_name.replace("DNS Name=", "") for dns_name in cert["sANS"].split(", ")]

        valid_from = datetime.fromisoformat(cert["validFrom"])
        valid_to = datetime.fromisoformat(cert["validTo"])

        self.logger.info(f"You are going to {Fore.RED}revoke{Style.RESET_ALL} a certificate with the following details:\n")
        self.logger.info(f"Friendly name: {cert['friendlyName']}")
        self.logger.info(f"Valid from: {valid_from.strftime('%d %B %Y %H:%M:%S')}")
        self.logger.info(f"Valid to: {valid_to.strftime('%d %B %Y %H:%M:%S')}")
        self.logger.info(f"DNS names: {', '.join(dns_names)}")

        dns_name = input(
            "\nPlease enter one of the following DNS names "
            "to confirm the revocation: "
            f"{Fore.YELLOW}{', '.join(dns_names)}{Style.RESET_ALL}: "
        )
        if dns_name not in dns_names:
            self.logger.error("Invalid DNS name. Revocation operation cancelled.")
            exit(1)

        confirm = input(f"{Fore.RED}Are you sure you want to revoke certificate with ID '{id}'? (Y/n): {Style.RESET_ALL}")
        if confirm != "Y":
            self.logger.error("Revoke operation cancelled.")
            exit(1)

        if harica_client.revoke_certificate(id):
            self.logger.info(f"Certificate with ID '{id}' has been revoked.")
        else:
            self.logger.error(f"Failed to revoke certificate with ID '{id}'.")
