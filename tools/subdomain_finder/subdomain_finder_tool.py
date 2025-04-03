"""Tool for finding subdomains using crt.sh."""

import requests
from crewai.tools import BaseTool
from pydantic import BaseModel, Field, ConfigDict
from typing import Dict, Any, List, ClassVar
import logging
import re # Keep re if still needed locally, or remove if not
import json # Import json

# Import the shared validation function
from .validation_utils import is_potentially_valid_domain_for_tool

logger = logging.getLogger(__name__)

class SubdomainInput(BaseModel):
    """Input for subdomain finder."""
    domain: str = Field(..., description="Parent domain name to find subdomains for")

class SubdomainFinderTool(BaseTool):
    """Tool for querying crt.sh for subdomains."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    name: ClassVar[str] = "subdomain_finder_crtsh"
    description: str = "Finds subdomains for a given domain using Certificate Transparency logs (crt.sh)."
    input_schema: ClassVar[type] = SubdomainInput

    def _run(self, domain: str) -> Dict[str, Any]:
        """Run subdomain lookup via crt.sh."""
        # --- Input Validation --- 
        if not is_potentially_valid_domain_for_tool(domain):
            logger.error(f"SubdomainFinderTool received invalid domain input: '{domain}'")
            return {"error": f"Invalid domain format provided: '{domain}'. Please provide a valid domain name."}
        # --- End Input Validation --- 
        
        logger.info(f"Searching crt.sh for subdomains of {domain}")
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            
            if response.text == 'null\n': # Handle case where crt.sh returns literal null
                 logger.info(f"crt.sh returned null for {domain}. No subdomains found via certificates.")
                 return {"domain": domain, "subdomains": [], "source": "crt.sh"}
            
            # Process JSON response
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value')
                if name_value:
                    # Split potential multiple domains/subdomains on newline and filter
                    found_domains = name_value.split('\n')
                    for fd in found_domains:
                        clean_fd = fd.strip().lower()
                        # Basic filtering: belongs to the target domain, not wildcard
                        if clean_fd.endswith(f".{domain.lower()}") and '*' not in clean_fd:
                            subdomains.add(clean_fd)
                            
            found_list = sorted(list(subdomains))
            logger.info(f"Found {len(found_list)} potential subdomains for {domain} via crt.sh")
            return {"domain": domain, "subdomains": found_list, "source": "crt.sh"}

        except requests.exceptions.Timeout:
            logger.error(f"Timeout connecting to crt.sh for domain {domain}")
            return {"error": "Timeout connecting to crt.sh"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying crt.sh for domain {domain}: {e}")
            return {"error": f"Failed to query crt.sh: {e}"}
        except json.JSONDecodeError as e:
             logger.error(f"Error decoding JSON response from crt.sh for {domain}: {e}. Response text: {response.text[:200]}")
             return {"error": f"Failed to decode crt.sh response: {e}"}
        except Exception as e:
            logger.error(f"Unexpected error in SubdomainFinderTool for {domain}: {e}", exc_info=True)
            return {"error": f"An unexpected error occurred: {e}"}

    async def _arun(self, domain: str) -> Dict[str, Any]:
        """Run subdomain lookup asynchronously (delegates to sync)."""
        # Note: requests is synchronous. For true async, use httpx or aiohttp.
        return self._run(domain) 