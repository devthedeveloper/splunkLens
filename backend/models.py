from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime, timedelta

class ASTCommand(str, Enum):
    SEARCH = "search"
    STATS = "stats"
    TIMECHART = "timechart"
    TABLE = "table"
    EVAL = "eval"
    WHERE = "where"
    LOOKUP = "lookup"
    TSTATS = "tstats"
    DATAMODEL = "datamodel"

class ASTNode(BaseModel):
    command: ASTCommand
    args: Dict[str, Any] = Field(default_factory=dict)
    children: Optional[List['ASTNode']] = None

    @validator('children')
    def validate_children(cls, v):
        if v is not None and not isinstance(v, list):
            raise ValueError('Children must be a list of ASTNode')
        return v

class NLQuery(BaseModel):
    query: str = Field(..., min_length=1, max_length=1000)
    index: Optional[str] = None
    sourcetype: Optional[str] = None
    lookback_days: int = Field(7, ge=1, le=30)

class SPLResponse(BaseModel):
    spl: str
    explanation: str
    estimated_cost: Optional[float] = None
    estimated_results: Optional[int] = None

class SplunkRunRequest(BaseModel):
    spl: str = Field(..., min_length=1)
    splunk_token: Optional[str] = None
    earliest_time: Optional[str] = None
    latest_time: Optional[str] = None
    max_results: Optional[int] = Field(default=1000, ge=1, le=10000)

class SplunkRunResponse(BaseModel):
    job_id: str
    results_link: str
    preview_rows: List[Dict[str, Any]]
    status: str

class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None

# Schema models
class SchemaContext(BaseModel):
    indexes: List[str]
    sourcetypes: List[str]
    common_fields: List[str]
    macros: List[str]
    datamodels: List[str]
    
    class Config:
        schema_extra = {
            "example": {
                "indexes": ["main", "web", "security", "audit"],
                "sourcetypes": ["access_combined", "cisco_asa", "windows_security"],
                "common_fields": ["src_ip", "dest_ip", "user", "status", "bytes"],
                "macros": ["search_web_traffic", "search_security_events"],
                "datamodels": ["web", "internal_audit", "performance"]
            }
        }

# Validation models
class ValidationResult(BaseModel):
    is_valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)