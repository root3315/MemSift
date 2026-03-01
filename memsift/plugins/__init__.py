"""Analysis plugins for memory forensics."""

from .base import AnalysisPlugin, AnalysisFinding
from .processes import ProcessScanner
from .network import NetworkAnalyzer
from .strings import StringExtractor
from .injection import InjectionDetector
from .crypto import CryptoScanner
from .registry import RegistryScanner
from .filesystem import FileSystemScanner

__all__ = [
    "AnalysisPlugin",
    "AnalysisFinding",
    "ProcessScanner",
    "NetworkAnalyzer",
    "StringExtractor",
    "InjectionDetector",
    "CryptoScanner",
    "RegistryScanner",
    "FileSystemScanner",
]
