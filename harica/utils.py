import pyotp


def generate_otp(totp_seed):
    totp = pyotp.parse_uri(totp_seed)
    return totp.now()
