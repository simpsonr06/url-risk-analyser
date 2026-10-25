from typing import List, Dict, Any, Optional
from database.db import get_db_connection

def insert_scan(
    url: str,
    score: int,
    classification: str,
    creation_date: str = "N/A",
    expiration_date: str = "N/A",
    registrar: str = "N/A",
    db_path: Optional[str] = None
) -> int:
    """Insert a new scan record into the database and return the record ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (url, score, classification, creation_date, expiration_date, registrar)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (url, score, classification, creation_date or "N/A", expiration_date or "N/A", registrar or "N/A"))
    conn.commit()
    record_id = cursor.lastrowid
    conn.close()
    return record_id

def get_recent_scans(limit: int = 10, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch the most recent scan records."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, url, score, classification, timestamp, creation_date, expiration_date, registrar
        FROM scans 
        ORDER BY timestamp DESC, id DESC 
        LIMIT ?
    ''', (max(1, min(limit, 100)),))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_dashboard_stats(db_path: Optional[str] = None) -> Dict[str, int]:
    """Get aggregated statistics for the dashboard in a single query."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT 
            COUNT(*) as total_scans,
            COALESCE(SUM(CASE WHEN classification = 'High Risk' THEN 1 ELSE 0 END), 0) as phishing_count,
            COALESCE(SUM(CASE WHEN classification = 'Suspicious' THEN 1 ELSE 0 END), 0) as suspicious_count,
            COALESCE(SUM(CASE WHEN classification = 'Safe' THEN 1 ELSE 0 END), 0) as safe_count
        FROM scans
    ''')
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return {
            "total_scans": 0,
            "phishing_count": 0,
            "suspicious_count": 0,
            "safe_count": 0
        }
        
    total = row['total_scans']
    phishing = row['phishing_count']
    suspicious = row['suspicious_count']
    safe = row['safe_count']
    
    # Catch any legacy rows where classification was outside the standard 3
    if safe == 0 and total > (phishing + suspicious):
        safe = total - (phishing + suspicious)

    return {
        "total_scans": total,
        "phishing_count": phishing,
        "suspicious_count": suspicious,
        "safe_count": safe
    }
