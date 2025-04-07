"""Tool for finding subdomains using crt.sh."""

import json  # Import json
import logging
import re
from typing import Any, ClassVar, Dict, List, Optional, Set, Type

import requests
from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field

# Import the shared validation function
from ..validation_utils import is_potentially_valid_domain_for_tool

logger = logging.getLogger(__name__)


class SubdomainInput(BaseModel):
    """Input for subdomain finder."""

    domain: str = Field(..., description="Parent domain name to find subdomains for")


class SubdomainFinderTool(BaseTool):
    """Tool for finding subdomains of a target domain using crt.sh."""

    name: str = "subdomain_finder_crtsh"
    description: str = (
        "Discovers subdomains of a given domain using certificate transparency logs (crt.sh)."
    )
    args_schema: Type[BaseModel] = SubdomainInput
    
    @property
    def input_schema(self) -> Type[BaseModel]:
        """Return the input schema for compatibility with older code."""
        return self.args_schema

    def _run(self, domain: str) -> Dict[str, Any]:
        """Run subdomain lookup via crt.sh."""
        # --- Input Validation ---
        if not is_potentially_valid_domain_for_tool(domain):
            logger.error(
                f"SubdomainFinderTool received invalid domain input: '{domain}'"
            )
            return {
                "error": f"Invalid domain format provided: '{domain}'. Please provide a valid domain name."
            }
        # --- End Input Validation ---

        logger.info(f"Searching crt.sh for subdomains of {domain}")
        subdomains = set()
        # Query crt.sh certificates API
        try:
            # Format URL to match expected test query format
            url = f"crt.sh/?q=%25.{domain}&output=json"
            logger.info(f"Querying crt.sh for domain {domain}")
            response = requests.get("https://" + url, timeout=30)
            
            if response.status_code != 200:
                logger.error(
                    f"Error from crt.sh for domain {domain}: {response.status_code} {response.text}"
                )
                return {"error": f"crt.sh request failed. Status code: {response.status_code}", "domain": domain}

            if (
                response.text == "null\n"
            ):  # Handle case where crt.sh returns literal null
                logger.info(
                    f"crt.sh returned null for {domain}. No subdomains found via certificates."
                )
                return {"domain": domain, "subdomains": [], "source": "crt.sh"}

            # Process JSON response
            data = response.json()
            for entry in data:
                name_value = entry.get("name_value")
                if name_value:
                    # Split potential multiple domains/subdomains on newline and filter
                    found_domains = name_value.split("\n")
                    for fd in found_domains:
                        clean_fd = fd.strip().lower()
                        # Basic filtering: belongs to the target domain, not wildcard
                        if (
                            clean_fd.endswith(f".{domain.lower()}")
                            and "*" not in clean_fd
                        ):
                            subdomains.add(clean_fd)

            found_list = sorted(list(subdomains))
            logger.info(
                f"Found {len(found_list)} potential subdomains for {domain} via crt.sh"
            )
            return {"domain": domain, "subdomains": found_list, "source": "crt.sh"}

        except requests.exceptions.Timeout:
            logger.error(f"Timeout connecting to crt.sh for domain {domain}")
            return {"error": f"crt.sh request timed out", "domain": domain}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying crt.sh for domain {domain}: {e}")
            return {"error": f"crt.sh connection error: {e}", "domain": domain}
        except json.JSONDecodeError as e:
            logger.error(
                f"Error decoding JSON response from crt.sh for {domain}: {e}. Response text: {response.text[:200]}"
            )
            return {"error": f"Failed to parse JSON response from crt.sh: {e}", "domain": domain}
        except Exception as e:
            logger.error(
                f"Unexpected error in SubdomainFinderTool for {domain}: {e}",
                exc_info=True,
            )
            return {"error": f"An unexpected error occurred: {e}"}

    async def _arun(self, domain: str) -> Dict[str, Any]:
        """Run the subdomain finder tool asynchronously.

        Args:
            domain: The target domain to find subdomains for.

        Returns:
            Dictionary with discovered subdomains.
        """
        return self._run(domain)
