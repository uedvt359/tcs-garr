import logging
import os
import tcs_garr.settings as settings


def setup_logger():
    # Set up logging
    logger = logging.getLogger()
    if not logger.hasHandlers():
        logger.setLevel(logging.DEBUG)

        # Handler console
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(console)

        # Set log file path
        log_file = os.path.join(settings.OUTPUT_PATH, "harica.log")
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"))
        logger.addHandler(file_handler)
    return logger
