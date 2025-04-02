"""Tool for performing Nmap port scans."""

import nmap
from crewai.tools import BaseTool
from pydantic import BaseModel, Field, ConfigDict
from typing import Dict, Any, List, Optional, ClassVar
import logging
import subprocess

logger = logging.getLogger(__name__)

class NmapInput(BaseModel):
    """Input for Nmap port scan."""
    targets: str = Field(..., description="Target IP address, hostname, or network range (e.g., 192.168.1.0/24)")
    ports: Optional[str] = Field(default="21,22,23,25,80,110,135,139,443,445,3389,8080", description="Comma-separated list of ports or port ranges to scan (e.g., '80,443', '1-1024'). Defaults to common ports.")
    arguments: Optional[str] = Field(default="-sV -T4", description="Additional Nmap arguments (e.g., '-sV -T4' for service version detection, '-O' for OS detection - requires root/admin).")

class NmapPortScanTool(BaseTool):
    """Tool for running Nmap scans. Requires Nmap to be installed on the system."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    name: ClassVar[str] = "nmap_port_scanner"
    description: str = ("Performs a port scan using Nmap on specified targets and ports. "
                        "Returns structured data about open ports, protocols, and services found. "
                        "Requires Nmap executable to be installed on the system where this tool runs. "
                        "Use responsibly and ensure you have permission to scan the targets.")
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

    def _run(self, targets: str, ports: Optional[str] = None, arguments: Optional[str] = None) -> Dict[str, Any]:
        """Run Nmap scan."""
        if not self._check_nmap():
            return {"error": "Nmap is not installed or available on the system."}

        ports_to_scan = ports if ports else "21,22,23,25,80,110,135,139,443,445,3389,8080"
        nmap_args = arguments if arguments else "-sV -T4"
        
        logger.info(f"Starting Nmap scan on targets: '{targets}', ports: '{ports_to_scan}', arguments: '{nmap_args}'")
        
        try:
            # Ensure arguments are passed correctly
            self.nm.scan(hosts=targets, ports=ports_to_scan, arguments=nmap_args)
            
            scan_results = {"scan_arguments": f"nmap {nmap_args} -p {ports_to_scan} {targets}", "hosts": []}
            
            for host in self.nm.all_hosts():
                host_data = {
                    "host": host,
                    "status": self.nm[host].state(),
                    "protocols": {}
                }
                protocols = self.nm[host].all_protocols()
                for proto in protocols:
                    host_data["protocols"][proto] = []
                    ports_info = self.nm[host][proto]
                    for port, port_data in ports_info.items():
                        if port_data['state'] == 'open': # Only report open ports
                            port_detail = {
                                "port": port,
                                "state": port_data['state'],
                                "name": port_data.get('name', ''),
                                "product": port_data.get('product', ''),
                                "version": port_data.get('version', ''),
                                "extrainfo": port_data.get('extrainfo', ''),
                                "cpe": port_data.get('cpe', '')
                            }
                            host_data["protocols"][proto].append(port_detail)
                
                # Only add host if open ports were found in scanned protocols
                if any(host_data["protocols"][p] for p in protocols):
                    scan_results["hosts"].append(host_data)

            logger.info(f"Nmap scan completed for targets: '{targets}'. Found {len(scan_results['hosts'])} hosts with open ports.")
            return scan_results
            
        except nmap.PortScannerError as e:
             logger.error(f"Nmap scanning error for targets '{targets}': {e}")
             return {"error": f"Nmap scanning error: {e}"}
        except Exception as e:
            logger.error(f"Unexpected error during Nmap scan for '{targets}': {e}", exc_info=True)
            return {"error": f"An unexpected error occurred during Nmap scan: {e}"}

    async def _arun(self, targets: str, ports: Optional[str] = None, arguments: Optional[str] = None) -> Dict[str, Any]:
        """Run Nmap scan asynchronously (delegates to sync)."""
        # python-nmap is synchronous
        return self._run(targets=targets, ports=ports, arguments=arguments) 