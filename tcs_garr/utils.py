import configparser
import os
import re
import shutil
import subprocess
import sys
from importlib.metadata import version as get_installed_version

import pyotp
import requests

from tcs_garr.logger import setup_logger
import tcs_garr.settings as settings


logger = setup_logger()


def generate_otp(totp_seed):
    totp = pyotp.parse_uri(totp_seed)
    return totp.now()


def check_pypi_version():
    """Get the latest version of the package from PyPI."""
    url = f"https://pypi.org/pypi/{settings.PACKAGE_NAME}/json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data["info"]["version"]
    else:
        raise Exception("Failed to fetch version from PyPI")


def get_current_version():
    """Get the currently installed version of the package."""
    return get_installed_version(settings.PACKAGE_NAME)


def is_installed_via_pipx():
    """Check if the current environment is pipx."""
    return shutil.which("pipx") is not None and "pipx" in sys.prefix


def upgrade_via_pip():
    """Upgrade the package using pip."""
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", settings.PACKAGE_NAME])


def upgrade_via_pipx():
    """Upgrade the package using pipx."""
    subprocess.run(["pipx", "upgrade", settings.PACKAGE_NAME])


def upgrade_package():
    """Upgrade the package depending on whether it's installed via pip or pipx."""
    if is_installed_via_pipx():
        upgrade_via_pipx()
    else:
        upgrade_via_pip()


def validate_config(config_data):
    """
    Validates that all required configuration fields are present and correct.

    :param config_data: Dictionary containing configuration values.
    """
    missing_fields = [key for key, value in config_data.items() if not value]
    if missing_fields:
        logger.error(f"❌ Missing configuration values for: {', '.join(missing_fields)}")
        exit(1)

    # Validate email
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    valid = re.match(pattern, config_data["username"])
    if not valid:
        logger.error(f"❌ Invalid email format for username: {config_data['username']}")
        exit(1)

    # Validate TOTP seed
    try:
        generate_otp(config_data["totp_seed"])
    except ValueError:
        logger.error(f"❌ Invalid TOTP seed: {config_data['totp_seed']}")
        exit(1)


def bc_move_previous_config():
    """
    Move an existing config file from the home directory to the new CONFIG_PATH.

    This function must be removed in future releases.
    """
    import shutil

    old_config_path = os.path.join(os.path.expanduser("~"), settings.CONFIG_FILENAME)

    # Check if the old config file exists
    if os.path.exists(old_config_path):
        # Create directories that host config file
        os.makedirs(os.path.dirname(settings.CONFIG_PATH), exist_ok=True)

        # Move the config file
        try:
            shutil.move(old_config_path, settings.CONFIG_PATH)
            logger.debug("Moved existing config.")
        except Exception as e:
            logger.error(f"Failed to move config: {e}")
    else:
        logger.debug("No existing config file found to move.")


def load_config(environment="production"):
    """
    Load Harica configuration based on the environment.
    """

    bc_move_previous_config()

    # For backward compatibility set write permission
    if os.path.exists(settings.CONFIG_PATH) and not os.access(settings.CONFIG_PATH, os.W_OK):
        os.chmod(settings.CONFIG_PATH, settings.CONFIG_FILE_PERMISSIONS)

    # Determine the section name based on the environment
    section_name = f"harica-{environment}" if environment != "production" else "harica"

    config_data = None

    for path in settings.CONFIG_PATHS:
        if os.path.exists(path):
            config = configparser.RawConfigParser()
            config.read(path)

            if config.has_section(section_name):
                config_data = {
                    "username": config.get(section_name, "username"),
                    "password": config.get(section_name, "password"),
                    "totp_seed": config.get(section_name, "totp_seed"),
                    "output_folder": config.get(section_name, "output_folder"),
                }
            else:
                logger.error(f"No configuration found for environment '{environment}' in {path}")
                exit(1)
            break

    # Fallback to env variables if no config file
    if config_data is None:
        logger.info("No config file found. Falling back to environment variables.")
        config_data = {
            "username": os.getenv("HARICA_USERNAME"),
            "password": os.getenv("HARICA_PASSWORD"),
            "totp_seed": os.getenv("HARICA_TOTP_SEED"),
            "output_folder": os.getenv("HARICA_OUTPUT_FOLDER", settings.OUTPUT_PATH),
        }

        # Ensure all required environment variables are set
        if not all([config_data["username"], config_data["password"], config_data["totp_seed"]]):
            logger.error(
                "Configuration file or environment variables missing. "
                "Generate config file with 'tcs-garr init' command or set "
                "HARICA_USERNAME, HARICA_PASSWORD and HARICA_TOTP_SEED "
                "environment variables."
            )
            exit(1)

    validate_config(config_data)

    return (
        config_data["username"],
        config_data["password"],
        config_data["totp_seed"],
        config_data["output_folder"],
    )
