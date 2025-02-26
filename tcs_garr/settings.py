import os

PACKAGE_NAME = "tcs-garr"
CONFIG_FILENAME = "tcs-garr.conf"
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".config", PACKAGE_NAME, CONFIG_FILENAME)
OUTPUT_FOLDER = "harica_certificates"
OUTPUT_PATH = os.path.join(os.path.expanduser("~"), OUTPUT_FOLDER)
CONFIG_PATHS = [
    os.path.join(os.getcwd(), CONFIG_FILENAME),
    CONFIG_PATH,
]
