# src/models.py
from pydantic import BaseModel, Field
from typing import Optional

class Dependency(BaseModel):
    """Represents a single dependency."""
    name: str
    version: str

class Vulnerability(BaseModel):
    """Represents a found vulnerability for a dependency."""
    name: str                         
    version: str                      
    cve_id: str = Field(default="N/A")
    severity: str = Field(default="UNKNOWN")
    summary: str = Field(default="No summary provided") 

    
    def __hash__(self):
        return hash((self.name, self.version, self.cve_id))

    def __eq__(self, other):
        if not isinstance(other, Vulnerability):
            return NotImplemented
        return (self.name, self.version, self.cve_id) == (other.name, other.version, other.cve_id)
