from colorama import Fore, Style

from tcs_garr.commands.base import BaseCommand
import pytz
from datetime import datetime, timedelta
from dateutil import parser
from tabulate import tabulate


class ListCertificatesCommand(BaseCommand):
    """
    Command to generate a report of certificates from the Harica service.

    This command lists certificates and optionally filters them based on
    expiration criteria provided by the user, such as certificates that have
    expired since a certain number of days or certificates expiring in the
    next few days.
    """

    def __init__(self, args):
        """
        Initialize the ListCertificates class.

        Sets the `command_name` and `help_text` attributes for this command.
        The command name is "list", and it is used to generate reports about
        certificates. The `help_text` provides a brief description of the command.
        """
        super().__init__(args)
        self.command_name = "list"  # Set the command name to "list"
        self.help_text = "Generate a report from Harica"  # Help text for the command

    def configure_parser(self, parser):
        """
        Configure the argument parser for the list certificates command.

        This method adds optional arguments to filter certificates based on
        expiration dates. The user can specify certificates that have expired
        since a certain number of days or certificates that will expire in
        a certain number of days.

        Args:
            parser: An argparse.ArgumentParser object used for parsing command-line arguments.
        """
        # Add an optional argument to filter certificates that have expired since a given number of days
        parser.add_argument(
            "--expired-since",
            type=int,
            help="List certificates whose expiry date is X days before now.",
        )

        # Add an optional argument to filter certificates that will expire in a given number of days
        parser.add_argument("--expiring-in", type=int, help="List certificates whose expiry date is X days after now.")

    def execute(self):
        """
        Execute the list certificates command to retrieve and display certificates.

        This method fetches certificates from the Harica client and optionally filters
        them based on expiration criteria (expired since a number of days or expiring
        in a number of days). The filtered certificates are then displayed in a tabular format.

        Args:
            args: Parsed command-line arguments that include optional filters for
                  certificate expiration dates.
        """
        # Get the current UTC date and time
        current_date = pytz.utc.localize(datetime.now())

        # Calculate the date range based on expired_since or expiring_in arguments, if provided
        from_date = current_date - timedelta(days=self.args.expired_since) if self.args.expired_since is not None else None
        to_date = current_date + timedelta(days=self.args.expiring_in) if self.args.expiring_in is not None else None

        # Get the Harica client instance
        harica_client = self.harica_client()

        # Retrieve the list of certificates from the Harica client
        certificates = harica_client.list_certificates()
        data = []  # Initialize a list to store certificate data for tabular display

        # Sort certificates by the 'certificateValidTo' field
        for item in sorted(certificates, key=lambda x: x["certificateValidTo"] if "certificateValidTo" in x else ""):
            # Parse the expiration date and convert to UTC
            expire_date_naive = parser.isoparse(item["certificateValidTo"])
            expire_date = pytz.utc.localize(expire_date_naive)

            # Filter certificates based on the provided date range
            if (from_date is None or expire_date <= from_date) and (to_date is None or expire_date < to_date):
                # Create a dictionary of certificate status fields
                status_fields = {
                    "isEidasValidated": item.get("isEidasValidated"),
                    "isExpired": item.get("isExpired"),
                    "isHighRisk": item.get("isHighRisk"),
                    "isPaid": item.get("isPaid"),
                    "isPendingP12": item.get("isPendingP12"),
                    "isRevoked": item.get("isRevoked"),
                }

                # Filter out None or False values, keeping only True values for status display
                status = [field for field, value in status_fields.items() if value]

                # Append the certificate data to the list for tabular display
                data.append(
                    [
                        item["transactionId"],
                        item["dN"],  # Certificate Distinguished Name
                        item["certificateValidTo"],  # Expiration date of the certificate
                        ", ".join(status) if status else "",  # Status fields that are True
                        ";".join([subjAltName["fqdn"] for subjAltName in item["domains"]])
                        if "domains" in item
                        else "",  # Alternate names
                        item["user"],  # User who requested the certificate
                    ]
                )

        # Log the results in a formatted table with headers, using color for column titles
        self.logger.info(
            tabulate(
                data,
                headers=[
                    Fore.BLUE + "ID",  # Transaction ID
                    "dN",  # Column header for "Distinguished Name" in blue
                    "Expire at",  # Column header for expiration date
                    "Status",  # Column header for certificate status
                    "AltNames",  # Column header for alternate names
                    "Requested by" + Style.RESET_ALL,  # Column header for user who requested the certificate
                ],
            )
        )
