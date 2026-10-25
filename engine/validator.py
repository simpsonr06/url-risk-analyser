import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, Optional
from config.settings import MAX_URL_LENGTH

# Disallowed schemes that must be strictly rejected
DISALLOWED_SCHEMES = {"javascript", "data", "file", "ftp", "gopher", "mailto", "tel", "ssh"}

# Regex for basic hostname syntax according to RFC 1123 / RFC 952
DOMAIN_NAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

class ValidationError(Exception):
    """Custom exception raised when URL validation fails."""
    pass

def is_ip_address(host: str) -> bool:
    """Check if the host string is an IPv4 or IPv6 address."""
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False

def check_ip_security(host: str) -> Dict[str, bool]:
    """
    Check if an IP host is loopback, private, link-local (cloud metadata),
    reserved, or multicast. Supports IPv4-mapped IPv6 addresses.
    """
    clean_host = host.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        if ip_obj.version == 6 and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped
        return {
            "is_ip": True,
            "is_loopback": ip_obj.is_loopback,
            "is_private": ip_obj.is_private,
            "is_link_local": ip_obj.is_link_local,
            "is_reserved": ip_obj.is_reserved,
            "is_multicast": ip_obj.is_multicast,
            "is_non_public": (
                ip_obj.is_loopback or 
                ip_obj.is_private or 
                ip_obj.is_link_local or 
                ip_obj.is_reserved or 
                ip_obj.is_multicast or
                ip_obj.is_unspecified
            )
        }
    except ValueError:
        return {
            "is_ip": False,
            "is_loopback": False,
            "is_private": False,
            "is_link_local": False,
            "is_reserved": False,
            "is_multicast": False,
            "is_non_public": False
        }

def validate_and_normalize_url(raw_url: str) -> Dict[str, Any]:
    """
    Validate, sanitize, and normalize input URLs.
    
    Returns structured metadata including normalized URL, extracted hostname,
    port, IP security attributes, and RDAP eligibility.
    Raises ValidationError if URL is invalid, too long, or uses a dangerous scheme.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValidationError("URL cannot be empty")
        
    url = raw_url.strip()
    if not url:
        raise ValidationError("URL cannot be empty or whitespace")
        
    if len(url) > MAX_URL_LENGTH:
        raise ValidationError(f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters")

    # Detect dangerous schemes before normalization
    lower_url = url.lower()
    for scheme in DISALLOWED_SCHEMES:
        if lower_url.startswith(f"{scheme}:"):
            raise ValidationError(f"Disallowed URL scheme: '{scheme}:'. Only HTTP and HTTPS are permitted.")

    # Automatically prefix https:// if no scheme is provided
    if not url.startswith("http://") and not url.startswith("https://"):
        # If input has another unknown scheme like custom://
        if "://" in url:
            scheme = url.split("://", 1)[0].lower()
            if scheme not in ("http", "https"):
                raise ValidationError(f"Unsupported URL scheme: '{scheme}'. Only HTTP and HTTPS are permitted.")
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValidationError(f"Malformed URL: {str(e)}")

    if parsed.scheme not in ("http", "https"):
        raise ValidationError(f"Invalid URL scheme: '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

    netloc = parsed.netloc
    if not netloc:
        raise ValidationError("URL missing host or authority component")

    # Extract userinfo if present (e.g. user:pass@host)
    userinfo = None
    host_port = netloc
    if "@" in netloc:
        userinfo, host_port = netloc.split("@", 1)

    # Extract hostname and port safely (handles IPv6 brackets like [::1]:8080)
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as e:
        raise ValidationError(f"Invalid URL port or hostname: {str(e)}")

    if not hostname:
        raise ValidationError("URL does not contain a valid hostname")

    clean_hostname = hostname.lower().rstrip(".")

    # Handle Internationalized Domain Names (IDN) via Punycode
    ascii_hostname = clean_hostname
    try:
        ascii_hostname = clean_hostname.encode("idna").decode("ascii")
    except Exception:
        # Fallback to original hostname if IDN encoding fails
        pass

    # IP analysis
    ip_info = check_ip_security(ascii_hostname)
    is_localhost = ascii_hostname == "localhost" or ascii_hostname.endswith(".localhost")
    if is_localhost:
        ip_info["is_non_public"] = True

    # RDAP eligibility:
    # Must NOT be an IP address, NOT localhost/non-public, and must match domain name format with a TLD
    is_rdap_eligible = False
    rdap_domain = None
    if not ip_info["is_ip"] and not is_localhost and not ip_info["is_non_public"]:
        if DOMAIN_NAME_REGEX.match(ascii_hostname):
            is_rdap_eligible = True
            # Strip www. prefix for RDAP lookup
            rdap_domain = ascii_hostname[4:] if ascii_hostname.startswith("www.") else ascii_hostname

    return {
        "normalized_url": parsed.geturl(),
        "raw_url": raw_url,
        "scheme": parsed.scheme,
        "netloc": netloc,
        "hostname": ascii_hostname,
        "port": port,
        "path": parsed.path or "/",
        "query": parsed.query,
        "has_credentials": userinfo is not None,
        "userinfo": userinfo,
        "ip_info": ip_info,
        "is_localhost": is_localhost,
        "is_rdap_eligible": is_rdap_eligible,
        "rdap_domain": rdap_domain
    }
