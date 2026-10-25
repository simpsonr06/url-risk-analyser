import tempfile
import os
from database.db import init_db
from database.queries import insert_scan, get_recent_scans, get_dashboard_stats

def test_database_crud():
    temp_dir = tempfile.mkdtemp(prefix="crud_test_")
    db_path = os.path.join(temp_dir, "crud_scans.db")
    init_db(db_path)
    
    try:
        # Check initial empty stats
        stats_empty = get_dashboard_stats(db_path=db_path)
        assert stats_empty["total_scans"] == 0
        assert stats_empty["phishing_count"] == 0
        assert stats_empty["suspicious_count"] == 0
        assert stats_empty["safe_count"] == 0

        # Insert test records
        id1 = insert_scan(
            url="https://legit-site.com",
            score=0,
            classification="Safe",
            creation_date="2020-01-01",
            expiration_date="2030-01-01",
            registrar="SafeRegistrar",
            db_path=db_path
        )
        assert id1 > 0

        id2 = insert_scan(
            url="https://phish-update.xyz",
            score=95,
            classification="High Risk",
            db_path=db_path
        )
        assert id2 > id1

        id3 = insert_scan(
            url="https://unknown-service.net",
            score=40,
            classification="Suspicious",
            db_path=db_path
        )
        assert id3 > id2

        # Query stats
        stats = get_dashboard_stats(db_path=db_path)
        assert stats["total_scans"] == 3
        assert stats["phishing_count"] == 1
        assert stats["suspicious_count"] == 1
        assert stats["safe_count"] == 1

        # Query recent scans
        recent = get_recent_scans(limit=2, db_path=db_path)
        assert len(recent) == 2
        # Most recent scan should be id3
        assert recent[0]["url"] == "https://unknown-service.net"
        assert recent[1]["url"] == "https://phish-update.xyz"
    finally:
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)
        except Exception:
            pass
