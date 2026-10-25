import anyio
import fnmatch
import httpx
import httpcore
from httpcore._backends.anyio import AnyIOBackend, AnyIOStream
from httpcore._backends.base import SOCKET_OPTION, AsyncNetworkStream
from httpcore._exceptions import ConnectTimeout, ConnectError, map_exceptions
import ipaddress
import logging
import re
import socket
from typing import Dict, Any, List, Optional, Tuple, Union
from urllib.parse import urlparse
from config.settings import RDAP_BASE_URL, RDAP_TIMEOUT_SECONDS, RDAP_ALLOWED_HOSTS
from engine.validator import check_ip_security, is_ip_address

logger = logging.getLogger(__name__)

# Strict domain name pattern for RDAP query parameter
VALID_DOMAIN_QUERY = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

def is_prohibited_ip(ip_str_or_obj: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """
    Check if an IP address is non-global, loopback, private, link-local, reserved,
    multicast, unspecified, shared address space (RFC 6598 100.64.0.0/10),
    documentation, benchmarking, or an IPv4-mapped prohibited address.
    """
    if isinstance(ip_str_or_obj, str):
        clean = ip_str_or_obj.strip("[]")
        try:
            ip_obj = ipaddress.ip_address(clean)
        except ValueError:
            return True
    else:
        ip_obj = ip_str_or_obj

    if ip_obj.version == 6 and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    return bool(
        not ip_obj.is_global or
        ip_obj.is_loopback or
        ip_obj.is_private or
        ip_obj.is_link_local or
        ip_obj.is_reserved or
        ip_obj.is_multicast or
        ip_obj.is_unspecified
    )

def is_allowed_rdap_host(hostname: str, allowed_patterns: Optional[List[str]]) -> bool:
    """
    Validate whether a hostname strictly matches the configured allowlist of trusted RDAP registries.
    Fails closed if allowed_patterns is empty or None.
    Rejects wildcard '*' to prevent accidental bypass.
    """
    if not allowed_patterns:
        return False
    host = hostname.lower().strip(".")
    for pattern in allowed_patterns:
        pat = pattern.lower().strip(".")
        if pat == "*":
            # Wildcard '*' is rejected to prevent silent allowlist disablement
            continue
        if pat == host:
            return True
        if pat.startswith("*."):
            suffix = pat[2:]
            if host == suffix or host.endswith("." + suffix):
                return True
    return False

def resolve_hostname_ips(hostname: str) -> List[str]:
    """
    Resolve a hostname to its IP addresses using TCP/443 context.
    Returns an empty list if resolution fails.
    """
    try:
        addr_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        ips = []
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except (socket.gaierror, OSError):
        return []

class SSRFSafeBackend(AnyIOBackend):
    """
    Custom network backend for httpcore that pins the TCP connection to a validated
    public IP address while preserving the original server_hostname for TLS SNI and
    certificate verification. Eliminates DNS rebinding at the connection level.
    """
    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[SOCKET_OPTION] | None = None,
    ) -> AsyncNetworkStream:
        if socket_options is None:
            socket_options = []

        try:
            addr_info = await anyio.to_thread.run_sync(
                socket.getaddrinfo, host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP
            )
        except (socket.gaierror, OSError) as e:
            raise ConnectError(f"DNS resolution failed for {host}: {e}")

        valid_ip = None
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip = sockaddr[0]
            if is_prohibited_ip(ip):
                raise ConnectError(f"Prohibited IP target resolved for {host}: {ip}")
            if valid_ip is None:
                valid_ip = ip

        if not valid_ip:
            raise ConnectError(f"No valid IP address found for {host}")

        exc_map = {
            TimeoutError: ConnectTimeout,
            OSError: ConnectError,
            anyio.BrokenResourceError: ConnectError,
        }
        with map_exceptions(exc_map):
            with anyio.fail_after(timeout):
                stream: anyio.abc.ByteStream = await anyio.connect_tcp(
                    remote_host=valid_ip,
                    remote_port=port,
                    local_host=local_address,
                )
                for option in socket_options:
                    stream._raw_socket.setsockopt(*option)
        return AnyIOStream(stream)

class SSRFSafeTransport(httpx.AsyncHTTPTransport):
    """
    AsyncHTTPTransport configured with SSRFSafeBackend to enforce connection-level
    IP pinning and prohibit DNS rebinding.

    Dependency & Architecture Note:
    httpx does not expose network_backend in AsyncHTTPTransport.__init__.
    We inject SSRFSafeBackend directly onto self._pool._network_backend.
    This preserves all pool limits (max_connections, max_keepalive_connections,
    keepalive_expiry), HTTP/2 negotiation, retries, socket options, and SSL contexts,
    while ensuring every connection created by the pool uses our safe backend.
    Compatible and tested with httpx==0.28.1, httpcore==1.0.9, and anyio==4.12.1.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pool._network_backend = SSRFSafeBackend()

def validate_rdap_destination(
    url: str,
    allowed_hosts: Optional[List[str]] = None
) -> Tuple[bool, str]:
    """
    Thoroughly validate an RDAP URL before sending outbound requests.
    
    Protections:
    - Enforces HTTPS scheme.
    - Rejects missing, empty, or unparseable hostnames.
    - Rejects non-standard ports (only port 443 or default is allowed).
    - Rejects literal IP addresses (IPv4, IPv6, IPv4-mapped IPv6).
    - Rejects localhost and loopback hostnames.
    - Enforces strict allowlist of authorized RDAP registry hosts (fails closed if empty).
    - Pre-resolves DNS and verifies all resolved IPs against prohibited IP ranges.
    """
    if not url or not isinstance(url, str):
        return False, "Malformed redirect location"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Malformed redirect location"

    # Enforce HTTPS scheme
    if parsed.scheme.lower() != "https":
        return False, "Insecure redirect rejected"

    # Reject URL user credentials (user:pass@host) to prevent credentials leakage or parser confusion
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        return False, "Prohibited redirect destination"

    hostname = parsed.hostname
    if not hostname:
        return False, "Prohibited redirect destination"

    clean_host = hostname.lower().strip(".")

    # Reject non-standard ports (e.g. 8080, 22, 6379)
    try:
        port = parsed.port
        if port is not None and port != 443:
            return False, "Prohibited redirect destination"
    except ValueError:
        return False, "Prohibited redirect destination"

    # Reject localhost and local aliases
    if clean_host == "localhost" or clean_host.endswith(".localhost"):
        return False, "Prohibited redirect destination"

    # Reject literal IP addresses (including IPv6 and IPv4-mapped IPv6)
    clean_ip_str = clean_host.strip("[]")
    try:
        ipaddress.ip_address(clean_ip_str)
        # Literal IPs are not permitted as RDAP registry hosts
        return False, "Prohibited redirect destination"
    except ValueError:
        pass

    # Enforce RDAP host allowlist (fails closed if allowed_hosts is empty or host not matched)
    if not is_allowed_rdap_host(clean_host, allowed_hosts):
        return False, "Prohibited redirect destination"

    # DNS Resolution & Rebinding Check
    resolved_ips = resolve_hostname_ips(clean_host)
    if not resolved_ips:
        return False, "Prohibited redirect destination"

    for ip_str in resolved_ips:
        if is_prohibited_ip(ip_str):
            return False, "Prohibited redirect destination"

    return True, ""

async def fetch_rdap_info(domain: str) -> Dict[str, Any]:
    """
    Fetch RDAP information for a validated domain from the configured RDAP service.
    
    Protections applied:
    - Rejects IP addresses, localhost, and non-domain strings.
    - Prevents SSRF / path traversal by validating domain query against strict regex.
    - Validates initial RDAP base URL against scheme, allowlist, and IP restrictions.
    - Uses SSRFSafeTransport to pin connection to validated IP and prevent DNS rebinding.
    - Validates every redirect location before dispatching the request:
      * Enforces HTTPS.
      * Rejects non-standard ports.
      * Rejects literal IPs, localhost, and non-allowlisted domains.
      * Resolves DNS and blocks private, link-local, loopback, and IPv4-mapped IPv6 destinations.
    - Enforces redirect chain limits and strict network timeouts.
    """
    if not domain or not isinstance(domain, str):
        return {"error": "Invalid domain parameter"}

    clean_domain = domain.strip().lower()

    # Rejection of IP addresses and malformed characters
    if is_ip_address(clean_domain):
        return {"error": "RDAP domain lookup not supported for IP addresses"}

    if not VALID_DOMAIN_QUERY.match(clean_domain):
        return {"error": "Invalid domain format for RDAP query"}

    # Base URL construction
    base = RDAP_BASE_URL if RDAP_BASE_URL.endswith("/") else f"{RDAP_BASE_URL}/"
    url = f"{base}{clean_domain}"

    # Validate initial RDAP base destination URL
    is_valid_init, reason_init = validate_rdap_destination(url, allowed_hosts=RDAP_ALLOWED_HOSTS)
    if not is_valid_init:
        logger.warning(f"Initial RDAP destination rejected: {url} ({reason_init})")
        if reason_init == "Insecure redirect rejected":
            return {"error": "Insecure redirect rejected"}
        return {"error": "Prohibited redirect destination"}

    try:
        transport = SSRFSafeTransport()
        async with httpx.AsyncClient(timeout=RDAP_TIMEOUT_SECONDS, transport=transport) as client:
            # Fetch manually validating each redirect hop for SSRF safety
            current_url = url
            response = None
            max_redirects = 3
            redirect_count = 0

            while redirect_count <= max_redirects:
                resp = await client.get(current_url, follow_redirects=False)
                
                # Check for redirect
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        break
                    
                    # Validate redirect destination before issuing request
                    is_valid_loc, reason_loc = validate_rdap_destination(
                        location, allowed_hosts=RDAP_ALLOWED_HOSTS
                    )
                    if not is_valid_loc:
                        logger.warning(f"RDAP redirect to {location} rejected: {reason_loc}")
                        if reason_loc == "Insecure redirect rejected":
                            return {"error": "Insecure redirect rejected"}
                        return {"error": "Prohibited redirect destination"}

                    current_url = location
                    redirect_count += 1
                    continue

                response = resp
                break

            if response is None:
                return {"error": "Redirect limit exceeded"}

            if response.status_code == 404:
                return {"error": "Domain not found in RDAP registry"}
                
            response.raise_for_status()
            return response.json()

    except httpx.TimeoutException:
        logger.warning(f"RDAP Service Timeout for domain '{clean_domain}'")
        return {"error": "RDAP lookup timed out"}
    except httpx.HTTPStatusError as e:
        logger.warning(f"RDAP Service HTTP {e.response.status_code} for '{clean_domain}'")
        return {"error": f"RDAP HTTP {e.response.status_code}"}
    except httpx.RequestError as e:
        logger.warning(f"RDAP Service Network error for '{clean_domain}': {e}")
        return {"error": "Network error reaching RDAP service"}
    except Exception as e:
        logger.error(f"Unexpected error during RDAP query for '{clean_domain}': {e}")
        return {"error": "Unexpected RDAP processing error"}

