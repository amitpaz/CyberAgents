#!/usr/bin/env python3
"""
Command-line script for syncing Semgrep policies.

This script provides a convenient interface for synchronizing
Semgrep policies from the official repository to local storage.
"""

import sys
import argparse
import logging
from typing import List, Optional
from pathlib import Path

# Add parent directory to path to allow imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.semgrep_scanner.utils import (
    sync_all_policies,
    sync_language_policies,
    get_sync_status
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_args() -> argparse.ArgumentParser:
    """Set up command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Sync Semgrep policies from the official repository."
    )
    
    # Command subparsers
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Sync command
    sync_parser = subparsers.add_parser("sync", help="Synchronize policies")
    sync_parser.add_argument(
        "languages", nargs="*", 
        help="Languages to sync (default: all supported languages)"
    )
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Show sync status")
    
    return parser


def handle_sync(languages: Optional[List[str]] = None) -> None:
    """
    Handle the sync command.
    
    Args:
        languages: List of languages to sync policies for
    """
    if not languages:
        logger.info("Syncing policies for all supported languages...")
        result = sync_all_policies()
    else:
        logger.info(f"Syncing policies for: {', '.join(languages)}")
        result = sync_language_policies(languages)
    
    if result.get("success", False):
        logger.info(f"Successfully synchronized {result['total_policies']} policies")
        
        # Print details for each language
        for lang, count in result.get("languages", {}).items():
            logger.info(f"  {lang}: {count} policies")
    else:
        logger.error(f"Synchronization failed: {result.get('message', 'Unknown error')}")


def handle_status() -> None:
    """Handle the status command."""
    status = get_sync_status()
    
    logger.info(f"Current Semgrep Policy Sync Status:")
    logger.info(f"Last sync: {status['last_sync'] or 'Never'}")
    logger.info(f"Commit hash: {status['commit_hash'] or 'N/A'}")
    logger.info(f"Total policies: {status['total_policies']}")
    
    logger.info("Language policy counts:")
    for lang, info in status.get("languages", {}).items():
        last_updated = info.get("last_updated", "Unknown")
        count = info.get("count", 0)
        logger.info(f"  {lang}: {count} policies (Last updated: {last_updated})")


def main() -> None:
    """Main entry point."""
    parser = setup_args()
    args = parser.parse_args()
    
    if not args.command:
        # Default to sync if no command specified
        handle_sync()
    elif args.command == "sync":
        handle_sync(args.languages)
    elif args.command == "status":
        handle_status()
    else:
        parser.print_help()


if __name__ == "__main__":
    main() 