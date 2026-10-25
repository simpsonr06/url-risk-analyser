import os
from typing import List

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Environment: 'development', 'production', or 'testing'
ENV = os.getenv("ENV", "development").lower()

# Server Bindings
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

# Database Configuration
DATABASE_PATH = os.getenv("DATABASE_PATH", os.path.join(BASE_DIR, "phishing_platform.db"))
DATABASE_URL = DATABASE_PATH  # Backward compatibility alias

# RDAP Service Configuration
RDAP_BASE_URL = os.getenv("RDAP_BASE_URL", "https://rdap.org/domain/")
RDAP_TIMEOUT_SECONDS = float(os.getenv("RDAP_TIMEOUT_SECONDS", "4.0"))

_raw_rdap_allowed = os.getenv("RDAP_ALLOWED_HOSTS", "")
if _raw_rdap_allowed:
    RDAP_ALLOWED_HOSTS: List[str] = [h.strip().lower() for h in _raw_rdap_allowed.split(",") if h.strip()]
else:
    RDAP_ALLOWED_HOSTS: List[str] = [
        "rdap.org",
        "*.rdap.org",
        "*.arin.net",
        "*.ripe.net",
        "*.apnic.net",
        "*.lacnic.net",
        "*.afrinic.net",
        "*.iana.org",
        "*.icann.org",
        "*.verisign-grs.com",
        "*.centralnic.com",
        "*.afilias-srs.net",
        "*.pir.org",
        "*.nominet.uk",
        "*.denic.de",
        "*.eurid.eu",
        "*.nic.cz"
    ]


# Security & CORS
_raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
ALLOWED_ORIGINS: List[str] = [origin.strip() for origin in _raw_origins.split(",") if origin.strip()]

# Rate Limiting
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() in ("true", "1", "yes")
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))

# Payload constraints
MAX_URL_LENGTH = int(os.getenv("MAX_URL_LENGTH", "2048"))
