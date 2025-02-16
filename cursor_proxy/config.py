import ssl

# DNS Configuration
DNS_TIMEOUT = 1.0
DNS_LIFETIME = 3.0
DNS_SERVERS = [
    ('8.8.8.8', 53),
    ('1.1.1.1', 53),
    ('208.67.222.222', 53)
]

# Firefox-specific domains to handle specially
FIREFOX_DOMAINS = {
    'tiles.services.mozilla.com': '0.0.0.0',
    'snippets.cdn.mozilla.net': '0.0.0.0',
    'detectportal.firefox.com': '0.0.0.0'
}

# SSL Configuration
SSL_OPTIONS = {
    'check_hostname': False,
    'verify_mode': ssl.CERT_NONE,
    'ciphers': 'ALL:@SECLEVEL=1',  # Allow all cipher suites
    'ssl_version': ssl.PROTOCOL_TLS,
    'options': (
        ssl.OP_NO_SSLv2 | 
        ssl.OP_NO_SSLv3 | 
        ssl.OP_NO_COMPRESSION
    )
}

# Buffer and timeout settings
BUFFER_SIZE = 65536
CONNECT_TIMEOUT = 30
READ_TIMEOUT = 30
SOCKET_TIMEOUT = 60

# SSL/TLS Configuration
VERIFY_SSL = False

# Retry configuration
MAX_RETRIES = 2
RETRY_DELAY = 0.5 