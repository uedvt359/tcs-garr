import subprocess
import sys
from importlib.metadata import version as get_installed_version

import pyotp
import requests
import shutil

PACKAGE_NAME = "tcs-garr"


def generate_otp(totp_seed):
    totp = pyotp.parse_uri(totp_seed)
    return totp.now()


def check_pypi_version():
    """Get the latest version of the package from PyPI."""
    url = f"https://pypi.org/pypi/{PACKAGE_NAME}/json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data["info"]["version"]
    else:
        raise Exception("Failed to fetch version from PyPI")


def get_current_version():
    """Get the currently installed version of the package."""
    return get_installed_version(PACKAGE_NAME)


def is_installed_via_pipx():
    """Check if the current environment is pipx."""
    return shutil.which("pipx") is not None and "pipx" in sys.prefix


def upgrade_via_pip():
    """Upgrade the package using pip."""
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", PACKAGE_NAME])


def upgrade_via_pipx():
    """Upgrade the package using pipx."""
    subprocess.run(["pipx", "upgrade", PACKAGE_NAME])


def upgrade_package():
    """Upgrade the package depending on whether it's installed via pip or pipx."""
    if is_installed_via_pipx():
        upgrade_via_pipx()
    else:
        upgrade_via_pip()
