"""Defect Review Agent module for analyzing and providing fixes for security vulnerabilities."""

from .defect_review_agent import (  # noqa: F401 -- Explicitly expose for dynamic loading
    DefectReviewAgent,
)

__all__ = ["DefectReviewAgent"]
