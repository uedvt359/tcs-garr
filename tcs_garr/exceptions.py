class NoHaricaAdminException(Exception):
    """No Harica admin role in the user profile"""

    pass


class NoHaricaApproverException(Exception):
    """No Harica approver role in the user profile"""

    pass


class CertificateNotApprovedException(Exception):
    """The requested certificated was not approved"""

    pass
