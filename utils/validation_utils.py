"""Utility functions for validation of various inputs."""

import json
import logging
import re
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import yaml
from jsonschema import Draft7Validator, RefResolver, exceptions

logger = logging.getLogger(__name__)


def is_valid_url(url: str) -> bool:
    """
    Validate if a string is a valid URL.
    
    Args:
        url: The URL string to validate
        
    Returns:
        True if the URL is valid, False otherwise
    """
    try:
        result = urlparse(url)
        # Check if scheme and netloc are present
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def validate_yaml_against_schema(
    yaml_data: Dict[str, Any], schema_path: str
) -> Dict[str, Any]:
    """
    Validate a YAML document against a JSON Schema.
    
    Args:
        yaml_data: The YAML data to validate
        schema_path: Path to the JSON Schema file
        
    Returns:
        Dictionary with validation results
    """
    try:
        # Load the schema
        with open(schema_path, "r") as f:
            schema = yaml.safe_load(f)
        
        # Create validator
        resolver = RefResolver(
            f"file://{schema_path}", schema
        )
        validator = Draft7Validator(schema, resolver=resolver)
        
        # Validate
        errors = list(validator.iter_errors(yaml_data))
        
        if errors:
            error_messages = []
            for error in errors:
                error_path = "/".join(str(p) for p in error.path) if error.path else ""
                error_message = f"{error_path}: {error.message}"
                error_messages.append(error_message)
            
            return {
                "is_valid": False,
                "errors": error_messages
            }
        
        return {"is_valid": True}
    
    except exceptions.SchemaError as e:
        logger.error(f"Schema error: {e}")
        return {
            "is_valid": False,
            "errors": [f"Schema error: {e}"]
        }
    except Exception as e:
        logger.error(f"Validation error: {e}")
        return {
            "is_valid": False,
            "errors": [f"Validation error: {e}"]
        }


def is_potentially_valid_domain(domain_str: str) -> bool:
    """
    Basic validation for domain names.
    
    Args:
        domain_str: The domain string to validate
        
    Returns:
        True if the domain is potentially valid, False otherwise
    """
    if not isinstance(domain_str, str) or not domain_str:
        return False
        
    # Check length
    if len(domain_str) > 255 or len(domain_str) < 4:
        return False
        
    # Check for disallowed characters
    if re.search(r"[^a-zA-Z0-9.-]", domain_str):
        return False
        
    # Domain should have at least one dot and TLD
    if "." not in domain_str:
        return False
        
    # Shouldn't start/end with dot or hyphen
    if domain_str.startswith((".", "-")) or domain_str.endswith((".", "-")):
        return False
        
    # Split into labels and check each
    labels = domain_str.split(".")
    for label in labels:
        # Labels should be 1-63 chars
        if not label or len(label) > 63:
            return False
            
        # Labels shouldn't start/end with hyphen
        if label.startswith("-") or label.endswith("-"):
            return False
    
    return True


def validate_api_key(api_key: str) -> Optional[str]:
    """
    Validate and sanitize an API key.
    
    Args:
        api_key: The API key to validate
        
    Returns:
        Sanitized API key if valid, None otherwise
    """
    if not api_key or not isinstance(api_key, str):
        return None
    
    # Remove whitespace
    api_key = api_key.strip()
    
    # Check length
    if len(api_key) < 10:
        return None
    
    # Basic check for common patterns
    if re.match(r"^[a-zA-Z0-9_\-+./]+$", api_key):
        return api_key
    
    return None 