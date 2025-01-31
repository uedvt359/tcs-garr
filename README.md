# Harica Client

![Version](https://img.shields.io/badge/Version-0.2.1-brightgreen.svg)

[![python](https://img.shields.io/badge/Python-3.9%2B-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Contributions welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)

## Overview

The `Harica Client` is a command-line tool for managing and interacting with certificates on the Harica platform. It offers features like listing, downloading, issuing certificates, approving requests, and generating domain validation tokens, all via the Harica API.

## Warning ⚠️

**Consortium GARR provides this code to the community for sharing purposes but does not commit to providing support, maintenance, or further development of the code. Use it at your own discretion.**

### Prerequisites

Before using the Harica client, please ensure the following:

1. **Create a local account on the Harica platform**: You must create a local account on Harica at [https://cm.harica.gr](https://cm.harica.gr). Do not use federated IDEM credentials, as they do not support API access.

   - If you're already logged in with federated IDEM credentials, you can create a new local account using an email alias. Federated users do not have a password and therefore cannot use the API.

2. **Administrator Permissions**: To use the API, your local account must have administrator permissions. To obtain these:

   - **Enable 2FA (Two-Factor Authentication)** on your profile page.
   - Save the TOTP seed provided after enabling 2FA, as you will need it for future authentication. TOTP seed is like `otpauth://totp/HARICA:...omissis...`
   - After enabling 2FA, request an existing administrator to elevate your account to Administrator privileges.

Once these steps are completed, you are ready to use the Harica client.

## Installation

You can install the Harica package in a virtual environment or via `pipx`.

### Virtual Environment

1. Open a terminal or command prompt and navigate to the directory where you want to install the package. Then, run the following command to create a virtual environment:

    ```bash
    mkdir <path>
    python -m venv venv
    ```

    This will create a folder named `venv` in your project directory, containing a self-contained Python environment.

2. Activate the virtual environment based on your operating system:

    ```bash
    source venv/bin/activate
    ```

3. Install the package

    ```bash
    pip install harica
    ```

### Pipx

1. Open a terminal and install the package

    ```bash
    PIPX_BIN_DIR=/usr/local/bin pipx install harica
    ```

## Configuration

After installation, the first time you run the client, you will need to initialize the configuration file with your credentials by running:

```bash
harica init
```

This will create a `harica.conf` file in your home directory. This file will contain your Harica username, password, TOTP seed, and folder for issued certificates and will have secure permissions.

The script will look for this configuration file in the current directory and the home directory. If not found, it will notify you to initialize the configuration using the `harica init` command.

## Usage

Once the setup is complete, you can use the Harica client for various operations. The command syntax follows this pattern:

```bash
harica [command] [options]
```

To view all available commands and options:

```bash
harica --help

usage: harica [-h] [--debug] {list,request,init,download,approve,whoami,validate,domains} ...

Harica Certificate Manager

positional arguments:
  {list,request,init,download,approve,whoami,validate,domains}
    list                Generate a report from Sectigo
    request             Request a new certificate
    init                Generate Sectigo config file
    download            Download a certificate by ID
    approve             Approve a certificate by ID
    whoami              Get logged in user profile
    validate            Create validation token for domains
    domains             List available domains

options:
  -h, --help            show this help message and exit
  --debug               Enable DEBUG logging.
```

### Available Commands

1. **Initialize configuration**:

   ```bash
   harica init
   ```

   This command initializes the configuration file with your credentials (email, password, and TOTP seed).

2. **Get user profile**:
   ```bash
   harica whoami
   ```

   This command retrieves the profile of the logged-in user.

3. **List all certificates**:

   ```bash
   harica list --help

   usage: harica list [-h] [--since SINCE] [--to TO]

    options:
    -h, --help     show this help message and exit
    --since SINCE  List certificates which expiry date is X days before now. Default is 10.
    --to TO        List certificates which expiry date is X days after now. Default is 30.
   ```

   This command will list all available certificates. You can filter them by date range using the `--since` and `--to` options.

4. **Download a certificate**:

   ```bash
   harica download --help

   usage: harica download [-h] --id ID [--output-filename OUTPUT_FILENAME] [--force] [--download-type {pemBundle,certificate}]

    options:
    -h, --help            show this help message and exit
    --id ID               ID of the certificate to download.
    --output-filename OUTPUT_FILENAME
                            Optional filename to save the certificate inside default output_folder.
    --force, -f           Force overwrite if the output file already exists.
    --download-type {pemBundle,certificate}
                            Type of download: 'pemBundle' or 'certificate'. Default is 'pemBundle'.
   ```

   Replace `ID` with the ID of the certificate you wish to download. You can use `pemBundle` or `certificate` as arguments for specific download formats.

5. **Request a new certificate**:

   ```bash
   harica request --help

   usage: harica request [-h] [--alt_names ALT_NAMES] --cn CN

    options:
    -h, --help            show this help message and exit
    --alt_names ALT_NAMES
                            Comma separated alternative names.
    --cn CN               Common name of the certificate.
   ```

   Replace `CN` with the Common Name (e.g., `example.com`) and `ALT_NAMES` with alternative names for the certificate (comma-separated).

   After requesting a new certificate, it will need to be approved by an administrator before it can be downloaded.

6. **Approve a certificate**:

   ```bash
   harica approve --help
   usage: harica approve [-h] --id ID

    options:
    -h, --help  show this help message and exit
    --id ID     ID of the certificate to approve.
   ```

7. **Generate validation token for domains**:

   ```bash
   usage: harica validate [-h] --domains DOMAINS

   options:
   -h, --help         show this help message and exit
   --domains DOMAINS  Comma separated list of domains.
   ```

   This command generates validation tokens for the specified domains. Replace `DOMAINS` with a comma-separated list of domains you need to validate.

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE.md) file for details.

## Contributing and Further Development

Contributions, further developments, error reports (and possibly fixes) are welcome.

For more info, please read the [CONTRIBUTING](CONTRIBUTING.md) file.
