from abc import ABC, abstractmethod
from colorama import Fore, Style

from tcs_garr.exceptions import NoHaricaAdminException, NoHaricaApproverException
from tcs_garr.harica_client import HaricaClient
from tcs_garr.logger import setup_logger
from tcs_garr.utils import load_config


class BaseCommand(ABC):
    """Base class that all command implementations should inherit from."""

    def __init__(self, args):
        # Default command name (can be overridden by subclasses)
        self.command_name = None

        self.args = args

        self.logger = setup_logger()

        # Default help text (should be overridden by subclasses)
        self.help_text = "No description available"

    @abstractmethod
    def configure_parser(self, parser):
        """
        Configure the argument parser for this command.

        Args:
            parser: The argparse parser for this command
        """
        pass

    def harica_client(self):
        username, password, totp_seed, output_folder = load_config(self.args.environment)

        try:
            harica_client = HaricaClient(username, password, totp_seed, environment=self.args.environment)
            return harica_client
        except NoHaricaAdminException:
            self.error(f"{Fore.RED}No Harica Admin role found in the user profile.{Style.RESET_ALL}")
            exit(1)
        except NoHaricaApproverException:
            self.error(f"{Fore.RED}No Harica Approver role found in the user profile.{Style.RESET_ALL}")
            exit(1)

    @abstractmethod
    def execute(self, args):
        """
        Execute the command with the parsed arguments.

        Args:
            args: The parsed command arguments
        """
        pass
