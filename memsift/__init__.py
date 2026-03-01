"""
MemSift - Memory Forensics and RAM Analysis Tool

A professional memory forensics toolkit for incident response,
malware investigation, and digital forensics.
"""

__version__ = "1.0.0"
__author__ = "MemSift Security"
__all__ = ["core", "plugins", "utils"]

from .core.analyzer import MemoryAnalyzer
from .core.parser import MemoryParser

__version_info__ = tuple(int(x) for x in __version__.split("."))
