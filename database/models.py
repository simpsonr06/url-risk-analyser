from pydantic import BaseModel, Field
from typing import List, Optional

class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Target URL to analyze")

class IntelligenceInfo(BaseModel):
    available: bool = Field(default=False, description="Whether RDAP intelligence was retrieved")
    registrar: Optional[str] = Field(default=None, description="Domain registrar name")
    age: Optional[str] = Field(default=None, description="Calculated domain age")
    created: Optional[str] = Field(default=None, description="Registration creation date")
    expires: Optional[str] = Field(default=None, description="Registration expiration date")

class ScanResponse(BaseModel):
    score: int = Field(..., ge=0, le=100, description="Composite threat risk score (0-100)")
    level: str = Field(..., description="Risk category: Safe, Suspicious, or High Risk")
    reasons: List[str] = Field(default_factory=list, description="List of detected anomalies or risk indicators")
    intelligence: Optional[IntelligenceInfo] = Field(default=None, description="Domain intelligence details")

class DashboardStats(BaseModel):
    total_scans: int
    phishing_count: int
    suspicious_count: int
    safe_count: int

class RecentScanItem(BaseModel):
    id: Optional[int] = None
    url: str
    score: int
    classification: str
    timestamp: str
    creation_date: Optional[str] = "N/A"
    expiration_date: Optional[str] = "N/A"
    registrar: Optional[str] = "N/A"
