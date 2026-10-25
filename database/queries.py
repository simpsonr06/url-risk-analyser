
from typing import List, Dict, Any, Optional
from urllib.parse import urlsplit, urlunsplit

from database.db import get_db_connection


def sanitize_url_for_history(url: str) -> str:
    """Remove credentials, query parameters, and fragments from a URL."""
    try:
        parts = urlsplit(url.strip())

        if not parts.scheme or not parts.netloc:
            return "[redacted URL]"

        hostname = parts.hostname
        if not hostname:
            return "[redacted URL]"

        # Preserve valid IPv6 formatting.
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"

        try:
            port = parts.port
        except ValueError:
            return "[redacted URL]"

        netloc = hostname
        if port is not None:
            netloc = f"{netloc}:{port}"

        return urlunsplit(
            (parts.scheme, netloc, parts.path, "", "")
        )
    except (ValueError, AttributeError):
        return "[redacted URL]"


def insert_scan(
    url: str,
    score: int,
    classification: str,
    creation_date: str = "N/A",
    expiration_date: str = "N/A",
    registrar: str = "N/A",
    db_path: Optional[str] = None,
) -> int:
    """Insert a sanitized scan record and return its ID."""
    conn = get_db_connection(db_path)

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (
                url, score, classification,
                creation_date, expiration_date, registrar
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                sanitize_url_for_history(url),
                score,
                classification,
                creation_date or "N/A",
                expiration_date or "N/A",
                registrar or "N/A",
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_recent_scans(
    limit: int = 10,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch recent scans, sanitizing legacy URLs before returning them."""
    conn = get_db_connection(db_path)

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                id, url, score, classification, timestamp,
                creation_date, expiration_date, registrar
            FROM scans
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
            """,
            (max(1, min(limit, 100)),),
        )

        results = []
        for row in cursor.fetchall():
            item = dict(row)
            item["url"] = sanitize_url_for_history(
                str(item.get("url") or "")
            )
            results.append(item)

        return results
    finally:
        conn.close()


def get_dashboard_stats(
    db_path: Optional[str] = None,
) -> Dict[str, int]:
    """Get aggregated dashboard statistics."""
    conn = get_db_connection(db_path)

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_scans,
                COALESCE(SUM(
                    CASE WHEN classification = 'High Risk'
                    THEN 1 ELSE 0 END
                ), 0) AS phishing_count,
                COALESCE(SUM(
                    CASE WHEN classification = 'Suspicious'
                    THEN 1 ELSE 0 END
                ), 0) AS suspicious_count,
                COALESCE(SUM(
                    CASE WHEN classification = 'Safe'
                    THEN 1 ELSE 0 END
                ), 0) AS safe_count
            FROM scans
            """
        )

        row = cursor.fetchone()

        if not row:
            return {
                "total_scans": 0,
                "phishing_count": 0,
                "suspicious_count": 0,
                "safe_count": 0,
            }

        total = row["total_scans"]
        phishing = row["phishing_count"]
        suspicious = row["suspicious_count"]
        safe = row["safe_count"]

        if safe == 0 and total > phishing + suspicious:
            safe = total - phishing - suspicious

        return {
            "total_scans": total,
            "phishing_count": phishing,
            "suspicious_count": suspicious,
            "safe_count": safe,
        }
    finally:
        conn.close()
