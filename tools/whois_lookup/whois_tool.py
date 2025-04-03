"""WHOIS lookup tool for domain analysis."""
import whois
from crewai.tools import BaseTool
from pydantic import BaseModel, Field, ConfigDict
from typing import Dict, Any, ClassVar, Optional

class WhoisInput(BaseModel):
    """Input for WHOIS lookup."""
    domain: str = Field(..., description="Domain name to lookup")

class WhoisTool(BaseTool):
    """Tool for performing WHOIS lookups."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    name: ClassVar[str] = "whois_lookup"
    description: str = "Lookup WHOIS information for a domain"
    input_schema: ClassVar[type] = WhoisInput

    def _run(self, domain: str) -> Dict[str, Any]:
        """Run WHOIS lookup for a domain."""
        try:
            w = whois.whois(domain)
            return {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "dnssec": w.dnssec,
                "updated_date": str(w.updated_date)
            }
        except Exception as e:
            return {"error": str(e)}

    async def _arun(self, domain: str) -> Dict[str, Any]:
        """Run WHOIS lookup asynchronously."""
        return self._run(domain) 