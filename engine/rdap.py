from database.models import IntelligenceInfo
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
import logging

logger = logging.getLogger(__name__)

class RDAPAnalyzer:
    def __init__(self, raw_data: Optional[Dict[str, Any]]):
        self.raw_data = raw_data or {}
        self.creation_date_str = ""
        self.expiration_date_str = ""
        self.registrar = ""
        self.domain_age_days: Optional[int] = None
        self.is_not_found = False

    def _extract_events(self):
        """Extract registration and expiration dates from RDAP events array."""
        events = self.raw_data.get("events", [])
        for event in events:
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")
            if action == "registration" and not self.creation_date_str:
                self.creation_date_str = date
            elif action == "expiration" and not self.expiration_date_str:
                self.expiration_date_str = date

    def _extract_registrar(self):
        """Extract registrar name from RDAP entities."""
        entities = self.raw_data.get("entities", [])
        for entity in entities:
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcardArray = entity.get("vcardArray", [])
                if len(vcardArray) > 1 and isinstance(vcardArray[1], list):
                    for prop in vcardArray[1]:
                        if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn":
                            self.registrar = str(prop[3])
                            return

    def _calculate_age(self):
        """Calculate domain age in days from creation date."""
        if not self.creation_date_str:
            return
            
        # Clean date string (handles '2020-01-01T00:00:00Z', fractional seconds, etc.)
        clean_date = self.creation_date_str.replace("Z", "+00:00")
        try:
            creation_dt = datetime.fromisoformat(clean_date)
            # Ensure timezone-aware comparison
            if creation_dt.tzinfo is None:
                creation_dt = creation_dt.replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)
            delta = now_dt - creation_dt
            self.domain_age_days = max(0, delta.days)
        except Exception as e:
            logger.debug(f"Could not parse RDAP creation date '{self.creation_date_str}': {e}")
            self.domain_age_days = None

    def analyze(self) -> Tuple[Optional[IntelligenceInfo], int, list]:
        """
        Process raw RDAP data and return (IntelligenceInfo, score_addition, indicators).
        """
        score_addition = 0
        indicators = []

        if not self.raw_data:
            return None, 0, ["Domain intelligence could not be retrieved"]

        if "error" in self.raw_data:
            err_msg = self.raw_data["error"]
            if "not found" in err_msg.lower():
                score_addition += 15
                indicators.append("Domain not found in RDAP registry (unregistered or newly created)")
            else:
                indicators.append(f"Domain intelligence unavailable: {err_msg}")
            return None, score_addition, indicators

        self._extract_events()
        self._extract_registrar()
        self._calculate_age()

        # Domain age scoring
        if self.domain_age_days is not None:
            if self.domain_age_days < 30:
                score_addition += 35
                indicators.append(f"Critically young domain (registered {self.domain_age_days} days ago)")
            elif self.domain_age_days < 90:
                score_addition += 25
                indicators.append(f"Newly registered domain (registered {self.domain_age_days} days ago)")
        elif not self.creation_date_str:
            indicators.append("Domain registration date missing from RDAP records")

        intel_info = IntelligenceInfo(
            available=True,
            created=self.creation_date_str if self.creation_date_str else None,
            expires=self.expiration_date_str if self.expiration_date_str else None,
            registrar=self.registrar if self.registrar else "Unknown",
            age=f"{self.domain_age_days} DAYS" if self.domain_age_days is not None else "Unknown"
        )

        return intel_info, score_addition, indicators

def analyze_domain_intel(domain: str, raw_rdap: dict) -> dict:
    """Analyze domain intelligence and return structured score & indicators."""
    analyzer = RDAPAnalyzer(raw_rdap)
    intel_info, score_addition, indicators = analyzer.analyze()
    
    return {
        "score_addition": score_addition,
        "indicators": indicators,
        "intelligence": intel_info
    }
