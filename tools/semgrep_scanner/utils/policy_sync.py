"""
Semgrep Policy Sync Utility.

This module provides utilities to synchronize Semgrep policies from the
official Semgrep repository to local storage for offline use and customization.
"""

import datetime
import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import yaml

# Set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Configuration
SEMGREP_REPO_URL = "https://github.com/returntocorp/semgrep-rules.git"
DEFAULT_LANGUAGES = [
    "python",
    "javascript",
    "typescript",
    "java",
    "go",
    "ruby",
    "php",
    "c",
    "cpp",
    "csharp",
]

# Local paths
BASE_DIR = Path(__file__).resolve().parent.parent
POLICIES_DIR = BASE_DIR / "policies"
KNOWLEDGE_DIR = POLICIES_DIR / "knowledge"
METADATA_FILE = POLICIES_DIR / "sync_metadata.json"


class PolicySyncManager:
    """
    Manager for synchronizing Semgrep policies from the official repository
    to local storage.
    """

    def __init__(
        self,
        repo_url: str = SEMGREP_REPO_URL,
        base_dir: Path = BASE_DIR,
        policies_dir: Path = POLICIES_DIR,
        knowledge_dir: Path = KNOWLEDGE_DIR,
    ):
        """
        Initialize the policy sync manager.

        Args:
            repo_url: URL of the Semgrep rules repository
            base_dir: Base directory of the tool
            policies_dir: Directory to store policy metadata
            knowledge_dir: Directory to store policy rules
        """
        self.repo_url = repo_url
        self.base_dir = base_dir
        self.policies_dir = policies_dir
        self.knowledge_dir = knowledge_dir

        # Create directories if they don't exist
        self.policies_dir.mkdir(parents=True, exist_ok=True)
        self.knowledge_dir.mkdir(parents=True, exist_ok=True)

        # Load metadata if exists
        self.metadata = self._load_metadata()

    def _load_metadata(self) -> Dict:
        """
        Load synchronization metadata from the metadata file.

        Returns:
            Dictionary containing synchronization metadata
        """
        if not METADATA_FILE.exists():
            return {
                "last_sync": None,
                "commit_hash": None,
                "languages": {},
                "version": "1.0.0",
            }

        try:
            with open(METADATA_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading metadata: {str(e)}")
            return {
                "last_sync": None,
                "commit_hash": None,
                "languages": {},
                "version": "1.0.0",
            }

    def _save_metadata(self) -> None:
        """Save synchronization metadata to the metadata file."""
        try:
            with open(METADATA_FILE, "w") as f:
                json.dump(self.metadata, f, indent=2)
        except IOError as e:
            logger.error(f"Error saving metadata: {str(e)}")

    def _clone_or_update_repo(self, temp_dir: str) -> Tuple[bool, Optional[str]]:
        """
        Clone or update the Semgrep rules repository.

        Args:
            temp_dir: Temporary directory for the repository

        Returns:
            Tuple with success status and commit hash
        """
        try:
            # Clone the repository
            logger.info(f"Cloning Semgrep rules repository to {temp_dir}...")
            subprocess.run(
                ["git", "clone", "--depth=1", self.repo_url, temp_dir],
                check=True,
                capture_output=True,
                text=True,
            )

            # Get the commit hash
            result = subprocess.run(
                ["git", "-C", temp_dir, "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            )
            commit_hash = result.stdout.strip()

            return True, commit_hash
        except subprocess.CalledProcessError as e:
            logger.error(f"Git operation failed: {e.stderr}")
            return False, None
        except Exception as e:
            logger.error(f"Error during repository operations: {str(e)}")
            return False, None

    def _find_policy_files(
        self, temp_dir: str, languages: List[str]
    ) -> Dict[str, List[Path]]:
        """
        Find policy files for specified languages in the repository.

        Args:
            temp_dir: Path to the temporary directory containing the repository
            languages: List of languages to find policies for

        Returns:
            Dictionary mapping languages to lists of policy files
        """
        policy_files = {}
        repo_path = Path(temp_dir)

        # Define common security-related directories to search
        security_dirs = [
            "c",
            "csharp",
            "go",
            "java",
            "javascript",
            "php",
            "python",
            "ruby",
            "scala",
            "typescript",
            "terraform",
            "docker",
            "kubernetes",
            "secrets",
            "security",
            "auth",
            "injection",
            "xss",
            "sqli",
            "csrf",
            "crypto",
            "command-injection",
            "path-traversal",
            "insecure-transport",
            "open-redirect",
            "xxe",
            "deserialization",
        ]

        # Priority patterns for security issues
        security_patterns = [
            r"injection",
            r"xss",
            r"sqli",
            r"command",
            r"traversal",
            r"csrf",
            r"ssrf",
            r"access-control",
            r"auth",
            r"security",
            r"vulnerab",
            r"exploit",
            r"attack",
            r"auth",
            r"token",
            r"secret",
            r"password",
            r"cred",
            r"key",
            r"cert",
            r"permission",
            r"sandbox",
            r"overflow",
            r"bound",
            r"race",
            r"deadlock",
            r"dos",
            r"backdoor",
            r"bypass",
            r"brute-force",
            r"privil",
            r"escalat",
            r"sign",
            r"crypto",
            r"encrypt",
            r"decrypt",
            r"hash",
            r"random",
            r"trust",
            r"validate",
        ]

        # Prepare regex for faster matching
        security_regex = re.compile("|".join(security_patterns), re.IGNORECASE)

        # Find all .yaml and .yml files
        yaml_files = list(repo_path.glob("**/*.yml"))
        yaml_files.extend(repo_path.glob("**/*.yaml"))

        for language in languages:
            language_files = []

            # First, look in language-specific directories
            language_dir = repo_path / language
            if language_dir.exists() and language_dir.is_dir():
                language_files.extend(language_dir.glob("**/*.yml"))
                language_files.extend(language_dir.glob("**/*.yaml"))

            # Also look for language-specific files in security-related dirs
            for sec_dir in security_dirs:
                sec_path = repo_path / sec_dir
                if sec_path.exists() and sec_path.is_dir():
                    # Find language-specific rules in security directories
                    for yaml_file in sec_path.glob("**/*.yml"):
                        try:
                            # Check if file contains language identifier
                            content = yaml_file.read_text()
                            if (
                                f"language: {language}" in content.lower()
                                or f"languages: ['{language}'" in content.lower()
                                or f'languages: ["{language}"' in content.lower()
                            ):
                                language_files.append(yaml_file)
                        except UnicodeDecodeError:
                            # Skip files that can't be read as text
                            continue

                    for yaml_file in sec_path.glob("**/*.yaml"):
                        try:
                            content = yaml_file.read_text()
                            if (
                                f"language: {language}" in content.lower()
                                or f"languages: ['{language}'" in content.lower()
                                or f'languages: ["{language}"' in content.lower()
                            ):
                                language_files.append(yaml_file)
                        except UnicodeDecodeError:
                            continue

            # Filter to prioritize security-related rules
            security_files = []
            other_files = []

            for file in language_files:
                if security_regex.search(str(file)):
                    security_files.append(file)
                else:
                    other_files.append(file)

            # Combine with security files first
            policy_files[language] = security_files + other_files
            logger.info(
                f"Found {len(policy_files[language])} policy files for {language}"
            )

        return policy_files

    def _copy_policies(
        self, policy_files: Dict[str, List[Path]], temp_dir: str
    ) -> Dict[str, int]:
        """
        Copy policy files to the knowledge directory.

        Args:
            policy_files: Dictionary mapping languages to lists of policy files
            temp_dir: Path to the temporary directory containing the repository

        Returns:
            Dictionary mapping languages to counts of copied policies
        """
        copied_counts = {}

        for language, files in policy_files.items():
            # Create language directory
            lang_dir = self.knowledge_dir / language
            lang_dir.mkdir(parents=True, exist_ok=True)

            # Clean existing files if needed
            if lang_dir.exists():
                for existing_file in lang_dir.glob("*.yml"):
                    existing_file.unlink()
                for existing_file in lang_dir.glob("*.yaml"):
                    existing_file.unlink()

            # Copy files
            copied_count = 0
            for i, file_path in enumerate(files):
                # Create a new filename based on the policy content
                rel_path = file_path.relative_to(Path(temp_dir))
                new_name = f"{language}_{rel_path.stem}_{i}.yml"
                new_name = new_name.replace("/", "_").replace("\\", "_")

                try:
                    shutil.copy2(file_path, lang_dir / new_name)
                    copied_count += 1
                except IOError as e:
                    logger.error(
                        f"Error copying {file_path} to {lang_dir / new_name}: {str(e)}"
                    )

            copied_counts[language] = copied_count
            logger.info(f"Copied {copied_count} policies for {language}")

            # Update metadata for this language
            self.metadata["languages"][language] = {
                "count": copied_count,
                "last_updated": datetime.datetime.now().isoformat(),
            }

        return copied_counts

    def sync_policies(self, languages: Optional[List[str]] = None) -> Dict:
        """
        Synchronize policies from the Semgrep rules repository.

        Args:
            languages: List of languages to synchronize policies for.
                If None, all supported languages will be synchronized.

        Returns:
            Dictionary with synchronization results
        """
        if languages is None:
            languages = DEFAULT_LANGUAGES

        logger.info(f"Starting synchronization for languages: {', '.join(languages)}")

        temp_dir = tempfile.mkdtemp(prefix="semgrep_rules_")
        try:
            # Clone or update repository
            success, commit_hash = self._clone_or_update_repo(temp_dir)
            if not success:
                return {"success": False, "message": "Failed to clone repository"}

            # Find policy files
            policy_files = self._find_policy_files(temp_dir, languages)

            # Copy policies
            copied_counts = self._copy_policies(policy_files, temp_dir)

            # Update metadata
            self.metadata["last_sync"] = datetime.datetime.now().isoformat()
            self.metadata["commit_hash"] = commit_hash
            self._save_metadata()

            return {
                "success": True,
                "commit_hash": commit_hash,
                "languages": copied_counts,
                "total_policies": sum(copied_counts.values()),
            }

        finally:
            # Clean up
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.error(f"Error cleaning up temporary directory: {str(e)}")

    def get_sync_status(self) -> Dict:
        """
        Get the current synchronization status.

        Returns:
            Dictionary with synchronization status
        """
        return {
            "last_sync": self.metadata.get("last_sync"),
            "commit_hash": self.metadata.get("commit_hash"),
            "languages": self.metadata.get("languages", {}),
            "total_policies": sum(
                lang_info.get("count", 0)
                for lang_info in self.metadata.get("languages", {}).values()
            ),
        }


def sync_all_policies() -> Dict:
    """
    Synchronize policies for all supported languages.

    Returns:
        Dictionary with synchronization results
    """
    manager = PolicySyncManager()
    return manager.sync_policies()


def sync_language_policies(languages: List[str]) -> Dict:
    """
    Synchronize policies for specified languages.

    Args:
        languages: List of languages to synchronize policies for

    Returns:
        Dictionary with synchronization results
    """
    manager = PolicySyncManager()
    return manager.sync_policies(languages)


def get_sync_status() -> Dict:
    """
    Get the current synchronization status.

    Returns:
        Dictionary with synchronization status
    """
    manager = PolicySyncManager()
    return manager.get_sync_status()


def get_policy_name_from_path(policy_path: Path) -> str:
    """Extract the policy name from its file path.

    Args:
        policy_path: The Path object representing the policy file.

    Returns:
        The policy name (filename without extension).
    """
    return policy_path.stem


def fetch_policy_languages(policy_path: Path) -> List[str]:
    """Extract languages from a policy file."""
    language_files: List[str] = []
    try:
        with open(policy_path, "r") as f:
            policy_data = yaml.safe_load(f)
            if isinstance(policy_data, dict) and "rules" in policy_data:
                for rule in policy_data["rules"]:
                    if isinstance(rule, dict) and "languages" in rule:
                        langs = rule["languages"]
                        if isinstance(langs, list):
                            language_files.extend(
                                lang for lang in langs if isinstance(lang, str)
                            )
    except Exception as e:
        logger.error(f"Error reading languages from {policy_path}: {e}")
    return list(set(language_files))


def write_policy_to_file(policy_path: Path, content: Union[Dict, List]):
    """Write policy content (dict or list) to a file."""
    _write_policy_to_file_internal(policy_path, content)


def _write_policy_to_file_internal(policy_path: Path, content: Union[Dict, List]):
    """Helper function to write policy content (dict or list) to a file."""
    try:
        with open(policy_path, "w") as f:
            yaml.safe_dump(content, f, indent=2, sort_keys=False)
        logger.info(f"Successfully wrote policy to {policy_path}")
    except Exception as e:
        logger.error(f"Error writing policy to {policy_path}: {e}")
