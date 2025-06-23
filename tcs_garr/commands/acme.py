from datetime import datetime

from colorama import Fore, Style

from tcs_garr.commands.base import BaseCommand
from tcs_garr.utils import UserRole


class AcmeAccountsCommand(BaseCommand):
    """
    Command to list available acme accounts and display their details.


    Args:
        args (argparse.Namespace): The command-line arguments passed to the command.
    """

    REQUIRED_ROLE = UserRole.ENTERPRISE_ADMIN

    def __init__(self, args):
        super().__init__(args)
        self.command_name = "acme"
        self.help_text = "List ACME accounts configured in Harica"

    def configure_parser(self, parser):
        """
        Configure the argument parser for the domains command.

        This method is overridden from the BaseCommand class but is not used
        for the 'domains' command as it does not require any additional arguments.

        Args:
            parser: An argparse.ArgumentParser object used for parsing command-line arguments.
        """
        pass  # No arguments needed for this command

    def execute(self):
        """
        Executes the command to list ACME accounts from Harica.
        """
        try:
            accounts = self.harica_client.list_acme_accounts()
        except Exception as e:
            self.logger.error(f"{Fore.RED}Failed to retrieve ACME accounts: {e}{Style.RESET_ALL}")
            return

        if not accounts:
            self.logger.info(f"{Fore.YELLOW}No ACME accounts found.{Style.RESET_ALL}")
            return

        self.logger.info(f"{Fore.CYAN}Found {len(accounts)} ACME account(s):{Style.RESET_ALL}")
        for account in accounts:
            friendly_name = account.get("friendlyName", "N/A")
            email = account.get("userEmail", "N/A")
            entity = account.get("entityName", "N/A")
            acme_url = account.get("acmeServerUrl", "N/A")
            created_at = account.get("createdAt", "N/A")
            notes = account.get("notes", None)
            is_enabled = account.get("isEnabled", False)

            try:
                created_date = datetime.fromisoformat(created_at)
                created_str = created_date.strftime("%Y-%m-%d %H:%M")
            except ValueError:
                created_str = "Unknown"

            status_color = Fore.GREEN if is_enabled else Fore.RED
            status_str = "ENABLED" if is_enabled else "DISABLED"

            # Base output string
            output = (
                f"{status_color}{friendly_name}{Style.RESET_ALL} "
                f"({entity}) - {email}\n"
                f"  Created: {created_str}\n"
                f"  ACME URL: {acme_url}\n"
                f"  Status: {status_str}"
            )

            # Add notes only if not None or empty
            if notes:
                output += f"\n  Notes: {notes}"

            self.logger.info(f"{output}\n")
