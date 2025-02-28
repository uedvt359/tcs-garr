import os

PACKAGE_NAME = "tcs-garr"
CONFIG_FILENAME = "tcs-garr.conf"
CONFIG_FILE_PERMISSIONS = 0o600
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".config", PACKAGE_NAME, CONFIG_FILENAME)
CONFIG_PATHS = [
    os.path.join(os.getcwd(), CONFIG_FILENAME),
    CONFIG_PATH,
]
OUTPUT_FOLDER = "harica_certificates"
OUTPUT_PATH = os.path.join(os.path.expanduser("~"), OUTPUT_FOLDER)
