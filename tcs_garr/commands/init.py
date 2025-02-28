from tcs_garr.commands.base import BaseCommand
import os
import configparser
from colorama import Fore, Style
import tcs_garr.settings as settings
import getpass


class InitCommand(BaseCommand):
    """
    Command to generate or update the Harica configuration file.

    This command prompts the user for necessary credentials (email, password, and TOTP seed)
    and generates or updates the Harica configuration file in the user's home directory for the specified environment.
    It can be forced to overwrite an existing configuration file if needed.

    Args:
        args (argparse.Namespace): The command-line arguments passed to the command.
    """

    def __init__(self, args):
        """
        Initializes the InitCommand class.

        Args:
            args (argparse.Namespace): The command-line arguments passed to the command.
        """
        super().__init__(args)
        self.command_name = "init"
        self.help_text = "Generate Harica config file"

    def configure_parser(self, parser):
        """
        Configures the argument parser for the init command.

        This method defines the optional argument for forcing the overwrite of the configuration file.

        Args:
            parser (argparse.ArgumentParser): The argument parser to configure.
        """
        # Optional argument to force overwrite of the configuration file
        parser.add_argument("--force", "-f", action="store_true", help="Force overwrite configuration file.")

    def execute(self):
        """
        Executes the command to create or update the Harica configuration file.

        This method calls the `_create_config_file` method with the provided environment and force options.
        """
        # Call the method to create or update the configuration file
        self._create_config_file(self.args.environment, self.args.force)

    def _create_config_file(self, environment="production", force=False):
        """
        Creates or updates the Harica configuration file in the user's home directory for the specified environment.

        This method reads the existing configuration file, checks if a configuration already exists for the specified
        environment, and prompts the user for necessary credentials if a new configuration is needed. The configuration
        is then saved to the specified path.

        Args:
            environment (str): The environment for which to create the configuration. Defaults to "production".
            force (bool): Whether to force overwrite an existing configuration file. Defaults to False.
        """
        # Create a RawConfigParser instance to handle the configuration file
        config = configparser.RawConfigParser()

        # Check if the configuration file already exists
        if os.path.exists(settings.CONFIG_PATH):
            # Read the existing configuration file if it exists
            config.read(settings.CONFIG_PATH)

        # Ensure the directory for the config file exists
        os.makedirs(os.path.dirname(settings.CONFIG_PATH), exist_ok=True)

        # Set the section name based on the environment, defaulting to 'harica' for production
        section_name = f"harica-{environment}" if environment != "production" else "harica"

        # Check if the section already exists and whether to force overwrite
        if config.has_section(section_name) and not force:
            # Warn the user if the configuration already exists and is not forced to be overwritten
            self.logger.warning(
                f"Configuration for '{environment}' environment already exists in {settings.CONFIG_PATH}. "
                f"If you want to reinitialize the configuration, use the --force option."
            )
            return

        # Prompt the user for credentials and configuration details
        username = input(f"{Fore.GREEN}👤 Enter Harica email: {Style.RESET_ALL}")
        password = getpass.getpass(f"{Fore.GREEN}🔒 Enter Harica password: {Style.RESET_ALL}")
        totp_seed = getpass.getpass(f"{Fore.GREEN}🔒 Enter Harica TOTP Seed: {Style.RESET_ALL}")

        # Prompt for output folder, defaulting to the configured path if left empty
        output_folder = (
            input(f"{Fore.GREEN}📂 Enter output folder (default is '{settings.OUTPUT_PATH}'): {Style.RESET_ALL}")
            or settings.OUTPUT_PATH
        )
        # Expand in case input was a relative path
        output_folder = os.path.abspath(os.path.expanduser(output_folder))

        # Update the configuration with the user inputs
        config[section_name] = {
            "username": username,
            "password": password,
            "totp_seed": totp_seed,
            "output_folder": output_folder,
        }

        # Write the configuration to the file
        with open(settings.CONFIG_PATH, "w") as configfile:
            config.write(configfile)

        # Set appropriate permissions for the configuration file
        os.chmod(settings.CONFIG_PATH, settings.CONFIG_FILE_PERMISSIONS)

        # Log success message
        self.logger.info(f"✨ Configuration for '{environment}' environment updated at {settings.CONFIG_PATH}")
