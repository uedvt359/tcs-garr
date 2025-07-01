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
        Configure the argument parser for the acme command.

        This method is overridden from the BaseCommand class but is not used
        for the 'acme' command as it does not require any additional arguments.

        Args:
            parser: An argparse.ArgumentParser object used for parsing command-line arguments.
        """
        subparsers = parser.add_subparsers(dest="action")

        # Subcommand to list ACME accounts
        list_parser = subparsers.add_parser("list", help="List all ACME accounts")
        list_parser.add_argument("--show-disabled", action="store_true", help="Show also disabled ACME accounts")

        # Subcommand to get info on a specific ACME account
        info_parser = subparsers.add_parser("info", help="Get information on a specific ACME account")
        info_parser.add_argument("account_id", type=str, help="ID of the ACME account to retrieve information for")

        # Subcommand to create a new ACME account
        create_parser = subparsers.add_parser("create", help="Create a new ACME account")
        create_parser.add_argument("friendly_name", type=str, help="Friendly name for the new ACME account")
        create_parser.add_argument(
            "--transaction_type",
            type=str,
            default="SSL OV",
            choices=["SSL OV", "SSL DV"],
            help="Transaction type for the new ACME account",
        )

    def execute(self):
        """
        Executes the command to list ACME accounts from Harica.
        """
        action = self.args.action

        if action == "list":
            self._list_accounts(self.args.show_disabled)
        elif action == "info":
            self._account_info(self.args.account_id)
        elif action == "create":
            self._create_account(self.args.friendly_name, self.args.transaction_type)

    def _format_account_output(self, account, show_secrets=False) -> str:
        """Format an ACME account entry for display.

        Parameters
        ----------
        account : dict
            ACME account entry.
        show_secrets : bool, optional
            Whether to include secrets in the output, by default False

        Returns
        -------
        str
            Formatted output string.

        """
        id = account.get("id", "N/A")
        friendly_name = account.get("friendlyName", "N/A")
        email = account.get("userEmail", "N/A")
        entity = account.get("entityName", "N/A")
        acme_url = account.get("acmeServerUrl", "N/A")
        created_at = account.get("createdAt", "N/A")
        notes = account.get("notes", None)
        is_enabled = account.get("isEnabled", False)
        type = account.get("transactionTypeName", "N/A")
        last_time_used = account.get("lastTimeUsed", "N/A")

        try:
            created_at = created_at.split(".")[0]  # Remove microseconds
            created_date = datetime.fromisoformat(created_at)
            created_str = created_date.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            created_str = "Unknown"

        status_color = Fore.GREEN if is_enabled else Fore.RED
        status_str = "ENABLED" if is_enabled else "DISABLED"

        output = (
            f"{status_color}{friendly_name}{Style.RESET_ALL} "
            f"({entity}) - {email}\n"
            f"  ID: {id}\n"
            f"  Status: {status_color}{status_str}{Style.RESET_ALL}\n"
            f"  Type: {type}\n"
            f"  Created: {created_str}\n"
            f"  Last time used: {last_time_used}"
        )

        if notes:
            output += f"\n  Notes: {notes}"

        # Add acme url here
        output += f"\n  ACME URL: {acme_url}"

        if show_secrets:
            key_id = account.get("keyId", "N/A")
            hmac_key = account.get("hmacKey", "N/A")
            output += f"\n  Key ID: {key_id}\n  HMAC Key: {hmac_key}"

        return output

    def _list_accounts(self, show_disabled=False):
        """Lists all ACME accounts configured in Harica."""
        try:
            accounts = self.harica_client.list_acme_accounts()
        except Exception as e:
            self.logger.error(f"{Fore.RED}Failed to retrieve ACME accounts: {e}{Style.RESET_ALL}")
            return

        if not accounts:
            self.logger.info(f"{Fore.YELLOW}No ACME accounts found.{Style.RESET_ALL}")
            return

        self.logger.info(f"{Fore.CYAN}ACME account(s):{Style.RESET_ALL}\n")

        count = {"enabled": 0, "disabled": 0}

        for account in accounts:
            enabled = account.get("isEnabled", False)
            count["disabled" if not enabled else "enabled"] += 1

            # Flag not provided and account is disabled
            if not show_disabled and not enabled:
                continue

            output = self._format_account_output(account)
            self.logger.info(f"{output}\n")

        self.logger.info(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
        self.logger.info(f"  Enabled: {Fore.GREEN}{count['enabled']}{Style.RESET_ALL}")
        self.logger.info(f"  Disabled: {Fore.RED}{count['disabled']}{Style.RESET_ALL}\n")

        self.logger.info(
            f"{Fore.CYAN}To see more details about an ACME account, use "
            f"the 'info' subcommand with the account ID.{Style.RESET_ALL}"
        )

        if not show_disabled:
            self.logger.info(
                f"{Fore.CYAN}To also display disabled ACME accounts, use "
                "the 'list' subcommand with the '--show-disabled' "
                f"flag.{Style.RESET_ALL}"
            )

    def _account_info(self, account_id):
        try:
            accounts = self.harica_client.list_acme_accounts()
            account = next((a for a in accounts if a.get("id") == account_id), None)
        except Exception as e:
            self.logger.error(f"{Fore.RED}Failed to retrieve ACME accounts: {e}{Style.RESET_ALL}")
            return

        if not account:
            self.logger.error(f"{Fore.RED}ACME account not found.{Style.RESET_ALL}")
            return

        output = self._format_account_output(account, show_secrets=True)
        self.logger.info(f"{output}\n")

    def _create_account(self, friendly_name, transaction_type):
        try:
            account = self.harica_client.create_acme_account(friendly_name=friendly_name, transaction_type=transaction_type)

            if not account:
                self.logger.error(f"{Fore.RED}Failed to create ACME account.{Style.RESET_ALL}")
                return

            self.logger.info(f"{Fore.GREEN}ACME account created successfully:{Style.RESET_ALL}\n")

            output = self._format_account_output(account, show_secrets=True)
            self.logger.info(f"{output}\n")
        except Exception as e:
            self.logger.error(f"{Fore.RED}Failed to create ACME account: {e}{Style.RESET_ALL}")
