"""Utility functions for validating tool inputs."""

import logging
import re

logger = logging.getLogger(__name__)


def is_potentially_valid_domain_for_tool(domain_str: str) -> bool:
    """Basic validation suitable for tool input.
    Checks length and for obviously disallowed characters.
    """
    if not isinstance(domain_str, str) or not domain_str:
        return False
    # Check length (overall and label length) - relaxed upper bound for flexibility
    if len(domain_str) > 500 or len(domain_str) == 0:
        return False
    # Reject inputs with common attack characters or path-like structures
    if re.search(r"[\s<>\'\"`;|&!*()]|(/|\\|\.\\.)", domain_str):
        return False
    # Basic checks:
    # - contains at least one dot
    # - doesn't start/end with dot/hyphen
    # - doesn't have hyphen directly before the TLD dot (e.g., name-.com)
    if (
        "." not in domain_str
        or domain_str.startswith((".", "-"))
        or domain_str.endswith((".", "-"))
        or "-." in domain_str
    ):
        return False
    return True


# Could also move the IP/Nmap validation helpers here if desired
