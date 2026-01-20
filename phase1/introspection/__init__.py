"""
phase1/introspection/__init__.py

System introspection via osquery.
"""

from phase1.introspection.extractor import (
    OSQueryInterface,
    SystemStateExtractor,
)

__all__ = [
    "OSQueryInterface",
    "SystemStateExtractor",
]
