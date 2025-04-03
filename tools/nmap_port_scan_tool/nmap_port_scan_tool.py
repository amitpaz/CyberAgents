"""Tool for performing Nmap port scans."""

import ipaddress  # For validation
import logging
import re  # For validation
import subprocess
from typing import Any, ClassVar, Dict, List, Optional

import nmap
from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field


# --- Add validation helpers ---
def is_valid_ip_address_or_network(ip_str: str) -> bool:
    """Checks if the string is a valid IPv4/IPv6 address or network CIDR."""
    if not isinstance(ip_str, str) or not ip_str:
        return False
    try:
        # Allows single addresses or networks like 192.168.1.0/24
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        return False


def is_potentially_valid_hostname(hostname: str) -> bool:
    """Basic check for hostname validity (less strict than domain)."""
    if not isinstance(hostname, str) or not hostname:
        return False
    # Reject inputs with common attack characters or path-like structures
    if re.search(r"[\s<>\'\"`;|&!*()]|(/|\\|\.\\.)", hostname):
        return False
    # Very basic: allows letters, numbers, hyphen, dot
    if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
        return False
    return True


def is_valid_nmap_target(target: str) -> bool:
    """Checks if the target is a valid IP address, network, or hostname."""
    return is_valid_ip_address_or_network(target) or is_potentially_valid_hostname(
        target
    )


def is_valid_nmap_ports(ports_str: Optional[str]) -> bool:
    """Checks if the ports string is valid (comma-separated numbers/ranges within 1-65535)."""
    if ports_str is None:
        return True  # Default is allowed
    if not isinstance(ports_str, str) or not ports_str:
        return False
    # Allows digits, commas, hyphens. Reject others.
    if not re.match(r"^[\d,-]+$", ports_str):
        return False

    try:
        parts = ports_str.split(",")
        for part in parts:
            if "-" in part:
                # Validate range
                start, end = map(int, part.split("-", 1))
                if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                    return False
            elif part.isdigit():
                # Validate single port
                port_num = int(part)
                if not (1 <= port_num <= 65535):
                    return False
            else:
                return False  # Should have been caught by regex, but double check
    except ValueError:
        return False  # Catch errors from int() conversion or multiple hyphens

    return True


def sanitize_nmap_arguments(arguments: Optional[str]) -> str:
    """Basic sanitization for Nmap arguments. Disallows shell metacharacters.
    NOTE: This is a basic blocklist and might not be exhaustive. Proper
    sandboxing or more sophisticated validation might be needed if complex
    user-supplied arguments are expected.
    """
    default_args = "-sV -T4"
    if arguments is None:
        return default_args
    if not isinstance(arguments, str):
        return default_args
    # Block common shell injection characters/sequences
    if re.search(r"[;&|`$\(\)\{\}<>!\\]|\.\./", arguments):
        logger.warning(
            f"Potentially unsafe characters detected in Nmap arguments: '{arguments}'. Using default arguments."
        )
        return default_args
    # Allow common safe args (letters, numbers, hyphen, space, comma, dot)
    if not re.match(r"^[a-zA-Z0-9\s\-,.\\/]+$", arguments):
        logger.warning(
            f"Disallowed characters detected in Nmap arguments: '{arguments}'. Using default arguments."
        )
        return default_args

    # Specific dangerous flags (non-exhaustive)
    dangerous_flags = ["--interactive", "--script", "-oN", "-oX", "-oG", "-oS", "-oA"]
    for flag in dangerous_flags:
        if flag in arguments.split():  # Check as whole words
            logger.warning(
                f"Potentially dangerous Nmap flag '{flag}' detected in arguments: '{arguments}'. Using default arguments."
            )
            return default_args

    return arguments


# --- End validation helpers ---

logger = logging.getLogger(__name__)


class NmapInput(BaseModel):
    """Input for Nmap port scan."""

    targets: str = Field(
        ...,
        description="Target IP address, hostname, or network range (e.g., 192.168.1.0/24)",
    )
    ports: Optional[str] = Field(
        default="21,22,23,25,80,110,135,139,443,445,3389,8080",
        description="Comma-separated list of ports or port ranges to scan (e.g., '80,443', '1-1024'). Defaults to common ports.",
    )
    arguments: Optional[str] = Field(
        default="-sV -T4",
        description="Additional Nmap arguments (e.g., '-sV -T4' for service version detection, '-O' for OS detection - requires root/admin).",
    )


class NmapPortScanTool(BaseTool):
    """Tool for running Nmap scans. Requires Nmap to be installed on the system."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: ClassVar[str] = "nmap_port_scanner"
    description: str = (
        "Performs a port scan using Nmap on specified targets and ports. "
        "Returns structured data about open ports, protocols, and services found. "
        "Requires Nmap executable to be installed on the system where this tool runs. "
        "Use responsibly and ensure you have permission to scan the targets."
    )
    input_schema: ClassVar[type] = NmapInput
    nm: Optional[nmap.PortScanner] = None

    def __init__(self, **kwargs):
        """Initialize the tool, checking for Nmap installation."""
        super().__init__(**kwargs)
        try:
            # Check if nmap executable exists
            subprocess.run(["nmap", "-V"], capture_output=True, check=True, timeout=5)
            self.nm = nmap.PortScanner()
            logger.info("Nmap executable found. NmapPortScanTool initialized.")
        except FileNotFoundError:
            logger.error("Nmap command not found. Please install Nmap on the system.")
            self.nm = None
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.error(f"Error verifying Nmap installation: {e}")
            self.nm = None
        except Exception as e:
            logger.error(f"Unexpected error initializing NmapPortScanTool: {e}")
            self.nm = None

    def _check_nmap(self) -> bool:
        """Check if Nmap is available."""
        if self.nm is None:
            logger.error("Nmap is not available or failed to initialize.")
            return False
        return True

    def _run(
        self, targets: str, ports: Optional[str] = None, arguments: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run Nmap scan."""
        if not self._check_nmap():
            return {"error": "Nmap is not installed or available on the system."}

        # --- Input Validation & Sanitization ---
        if not is_valid_nmap_target(targets):
            logger.error(f"NmapPortScanTool received invalid target input: '{targets}'")
            return {
                "error": f"Invalid target format provided: '{targets}'. Please provide a valid IP, hostname, or CIDR network."
            }

        if not is_valid_nmap_ports(ports):
            logger.error(f"NmapPortScanTool received invalid ports input: '{ports}'")
            return {
                "error": f"Invalid ports format provided: '{ports}'. Use comma-separated numbers or ranges (e.g., '80,443', '1-1024')."
            }

        # Sanitize arguments (basic blocklist approach)
        safe_arguments = sanitize_nmap_arguments(arguments)
        # --- End Input Validation ---

        ports_to_scan = (
            ports if ports else "21,22,23,25,80,110,135,139,443,445,3389,8080"
        )
        # Use sanitized arguments
        nmap_args = safe_arguments

        logger.info(
            f"Starting Nmap scan on targets: '{targets}', ports: '{ports_to_scan}', arguments: '{nmap_args}'"
        )

        try:
            # Ensure arguments are passed correctly
            self.nm.scan(hosts=targets, ports=ports_to_scan, arguments=nmap_args)

            scan_results = {
                "scan_arguments": f"nmap {nmap_args} -p {ports_to_scan} {targets}",
                "hosts": [],
            }

            for host in self.nm.all_hosts():
                host_data = {
                    "host": host,
                    "status": self.nm[host].state(),
                    "protocols": {},
                }
                protocols = self.nm[host].all_protocols()
                for proto in protocols:
                    host_data["protocols"][proto] = []
                    ports_info = self.nm[host][proto]
                    for port, port_data in ports_info.items():
                        if port_data["state"] == "open":  # Only report open ports
                            port_detail = {
                                "port": port,
                                "state": port_data["state"],
                                "name": port_data.get("name", ""),
                                "product": port_data.get("product", ""),
                                "version": port_data.get("version", ""),
                                "extrainfo": port_data.get("extrainfo", ""),
                                "cpe": port_data.get("cpe", ""),
                            }
                            host_data["protocols"][proto].append(port_detail)

                # Only add host if open ports were found in scanned protocols
                if any(host_data["protocols"][p] for p in protocols):
                    scan_results["hosts"].append(host_data)

            logger.info(
                f"Nmap scan completed for targets: '{targets}'. Found {len(scan_results['hosts'])} hosts with open ports."
            )
            return scan_results

        except nmap.PortScannerError as e:
            logger.error(f"Nmap scanning error for targets '{targets}': {e}")
            return {"error": f"Nmap scanning error: {e}"}
        except Exception as e:
            logger.error(
                f"Unexpected error during Nmap scan for '{targets}': {e}", exc_info=True
            )
            return {"error": f"An unexpected error occurred during Nmap scan: {e}"}

    async def _arun(
        self, targets: str, ports: Optional[str] = None, arguments: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run Nmap scan asynchronously (delegates to sync)."""
        # python-nmap is synchronous
        return self._run(targets=targets, ports=ports, arguments=arguments)
