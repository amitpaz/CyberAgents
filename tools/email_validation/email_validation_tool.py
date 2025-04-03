"""Tool for validating SPF and DMARC email security records."""

import dns.resolver
from crewai.tools import BaseTool
from pydantic import BaseModel, Field, ConfigDict
from typing import Dict, Any, List, Optional, ClassVar

class EmailValidationInput(BaseModel):
    """Input for email security validation."""
    domain: str = Field(..., description="Domain name to validate SPF and DMARC for")

class EmailValidationTool(BaseTool):
    """Tool for performing SPF and DMARC validation."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    name: ClassVar[str] = "email_security_validator"
    description: str = "Validates SPF and DMARC DNS records for a given domain and suggests improvements."
    input_schema: ClassVar[type] = EmailValidationInput

    def _run(self, domain: str) -> Dict[str, Any]:
        """Run SPF and DMARC validation for a domain."""
        results = {
            "spf": {"record": None, "valid": False, "suggestion": "No SPF record found."},
            "dmarc": {"record": None, "valid": False, "suggestion": "No DMARC record found."}
        }
        resolver = dns.resolver.Resolver()

        # --- SPF Check --- 
        try:
            txt_records = resolver.resolve(domain, "TXT")
            spf_record = None
            for record in txt_records:
                record_text = record.to_text().strip('"')
                if record_text.startswith("v=spf1"):
                    spf_record = record_text
                    results["spf"]["record"] = spf_record
                    # Basic validation: exists and seems like SPF
                    results["spf"]["valid"] = True 
                    results["spf"]["suggestion"] = "SPF record found. Further validation may be needed for correctness (e.g., include mechanisms, qualifiers like -all)."
                    # More complex validation could be added here
                    if "-all" not in spf_record.lower() and "~all" not in spf_record.lower():
                         results["spf"]["suggestion"] += " Consider adding a strong failure mechanism like '-all' or '~all'."
                    break # Found the first SPF record
            if not spf_record:
                results["spf"]["suggestion"] = "No SPF record found. Suggest creating one, e.g., 'v=spf1 mx -all' or use an SPF generator."

        except dns.resolver.NoAnswer:
            results["spf"]["suggestion"] = "No TXT records found for the domain, therefore no SPF record."
        except dns.resolver.NXDOMAIN:
             results["spf"]["suggestion"] = f"Domain {domain} does not exist."
             # No point checking DMARC if domain doesn't exist
             results["dmarc"]["suggestion"] = f"Domain {domain} does not exist."
             return results 
        except Exception as e:
            results["spf"]["error"] = f"Error querying SPF: {str(e)}"
            results["spf"]["suggestion"] = "An error occurred during SPF check."

        # --- DMARC Check --- 
        dmarc_domain = f"_dmarc.{domain}"
        try:
            txt_records = resolver.resolve(dmarc_domain, "TXT")
            dmarc_record = None
            for record in txt_records:
                record_text = record.to_text().strip('"')
                if record_text.startswith("v=DMARC1"):
                    dmarc_record = record_text
                    results["dmarc"]["record"] = dmarc_record
                    # Basic validation: exists and has a policy tag
                    if "p=" in record_text:
                        results["dmarc"]["valid"] = True
                        policy = [tag for tag in record_text.split(';') if tag.strip().startswith("p=")]
                        if policy:
                            policy_value = policy[0].split('=')[1].strip().lower()
                            if policy_value == 'none':
                                results["dmarc"]["suggestion"] = "DMARC record found with policy 'none'. Consider changing to 'quarantine' or 'reject' for better protection after monitoring reports."
                            else:
                                results["dmarc"]["suggestion"] = f"DMARC record found with policy '{policy_value}'. This enforces email authentication."
                        else:
                            results["dmarc"]["suggestion"] = "DMARC record found, but policy tag 'p=' seems malformed."
                            results["dmarc"]["valid"] = False # Invalid if policy is missing/malformed
                    else:
                        results["dmarc"]["suggestion"] = "DMARC record found, but required policy tag 'p=' is missing."
                        results["dmarc"]["valid"] = False
                    break # Found DMARC
            if not dmarc_record:
                 results["dmarc"]["suggestion"] = "No DMARC record found at _dmarc.{domain}. Suggest creating one to enforce SPF/DKIM alignment and receive reports."

        except dns.resolver.NoAnswer:
            results["dmarc"]["suggestion"] = f"No TXT records found for _dmarc.{domain}. No DMARC policy defined."
        except dns.resolver.NXDOMAIN:
            # This is expected if the domain exists but has no DMARC record
             results["dmarc"]["suggestion"] = f"Subdomain _dmarc.{domain} does not exist. No DMARC policy defined."
        except Exception as e:
            results["dmarc"]["error"] = f"Error querying DMARC: {str(e)}"
            results["dmarc"]["suggestion"] = "An error occurred during DMARC check."
            
        return results

    async def _arun(self, domain: str) -> Dict[str, Any]:
        """Run SPF and DMARC validation asynchronously (delegates to sync)."""
        # For simplicity, reusing the synchronous run method.
        # A true async implementation would use an async DNS library.
        return self._run(domain) 