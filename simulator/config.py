import os


class Config:
    DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 8080))

    # Rapid7 Nexpose (on-prem InsightVM) uses HTTP Basic Auth:
    # username = console user, password = console password.
    # Optional 2FA via a `Token` header (accepted but not validated here).
    AUTH_USERNAME = os.environ.get('NEXPOSE_USERNAME', 'nxadmin')
    AUTH_PASSWORD = os.environ.get('NEXPOSE_PASSWORD', 'nxadmin-secret')

    # Fleet sizing
    EXTRA_SERVERS = int(os.environ.get('EXTRA_SERVERS', 12))
    # 0 = whole catalog
    VULN_COUNT = int(os.environ.get('VULN_COUNT', 0))

    DEFAULT_PAGE_SIZE = int(os.environ.get('DEFAULT_PAGE_SIZE', 10))
