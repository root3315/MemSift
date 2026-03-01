"""
Memory Analyzer Module

Core analysis engine that orchestrates plugins and performs
comprehensive memory analysis for security investigations.
"""

from __future__ import annotations
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Optional
from collections.abc import Callable
from enum import Enum, auto

from .parser import MemoryParser, MemoryDumpInfo


class AnalysisStatus(Enum):
    """Status of an analysis operation."""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    PARTIAL = auto()


@dataclass
class AnalysisFinding:
    """Represents a single finding from analysis."""
    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    offset: Optional[int] = None
    address: Optional[int] = None
    evidence: bytes = field(default_factory=bytes)
    context: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            'category': self.category,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'offset': self.offset,
            'address': hex(self.address) if self.address else None,
            'evidence': self.evidence.hex() if self.evidence else None,
            'context': self.context
        }


@dataclass
class AnalysisResult:
    """Complete result of a memory analysis."""
    dump_info: MemoryDumpInfo
    findings: list[AnalysisFinding] = field(default_factory=list)
    statistics: dict = field(default_factory=dict)
    duration: float = 0.0
    status: AnalysisStatus = AnalysisStatus.PENDING
    errors: list[str] = field(default_factory=list)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'critical')
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'high')
    
    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'medium')
    
    @property
    def total_findings(self) -> int:
        return len(self.findings)
    
    def summary(self) -> str:
        """Generate a summary of the analysis."""
        lines = [
            f"Analysis Status: {self.status.name}",
            f"Duration: {self.duration:.2f}s",
            f"Total Findings: {self.total_findings}",
            f"  - Critical: {self.critical_count}",
            f"  - High: {self.high_count}",
            f"  - Medium: {self.medium_count}",
        ]
        if self.errors:
            lines.append(f"Errors: {len(self.errors)}")
        return '\n'.join(lines)


class AnalysisPlugin:
    """
    Base class for analysis plugins.
    
    Plugins implement specific analysis capabilities and can be
    registered with the MemoryAnalyzer to extend functionality.
    """
    
    name: str = "base_plugin"
    description: str = "Base analysis plugin"
    version: str = "1.0.0"
    
    def __init__(self):
        self.enabled = True
        self._parser: Optional[MemoryParser] = None
    
    def initialize(self, parser: MemoryParser) -> None:
        """Called when plugin is initialized with a parser."""
        self._parser = parser
    
    def analyze(self) -> list[AnalysisFinding]:
        """
        Perform analysis and return findings.
        
        Override this method in subclasses to implement analysis logic.
        """
        raise NotImplementedError("Subclasses must implement analyze()")
    
    def get_statistics(self) -> dict:
        """Return plugin-specific statistics."""
        return {}


class MemoryAnalyzer:
    """
    Main analysis engine for memory forensics.
    
    Orchestrates plugins, manages analysis state, and aggregates results.
    """
    
    def __init__(self, filepath: str | Path):
        self.filepath = Path(filepath)
        self.parser = MemoryParser(filepath)
        self._plugins: list[AnalysisPlugin] = []
        self._plugin_registry: dict[str, AnalysisPlugin] = {}
        self._current_result: Optional[AnalysisResult] = None
        
    @property
    def plugins(self) -> list[AnalysisPlugin]:
        """Get list of registered plugins."""
        return self._plugins.copy()
    
    @property
    def plugin_names(self) -> list[str]:
        """Get names of registered plugins."""
        return [p.name for p in self._plugins]
    
    def register_plugin(self, plugin: AnalysisPlugin) -> None:
        """Register an analysis plugin."""
        plugin.initialize(self.parser)
        self._plugins.append(plugin)
        self._plugin_registry[plugin.name] = plugin
    
    def unregister_plugin(self, name: str) -> bool:
        """Unregister a plugin by name."""
        if name in self._plugin_registry:
            plugin = self._plugin_registry.pop(name)
            self._plugins.remove(plugin)
            return True
        return False
    
    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin by name."""
        if name in self._plugin_registry:
            self._plugin_registry[name].enabled = True
            return True
        return False
    
    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin by name."""
        if name in self._plugin_registry:
            self._plugin_registry[name].enabled = False
            return True
        return False
    
    def analyze(self, plugin_names: Optional[list[str]] = None) -> AnalysisResult:
        """
        Run analysis with specified or all enabled plugins.
        
        Args:
            plugin_names: List of plugin names to run. If None, runs all enabled plugins.
        
        Returns:
            AnalysisResult containing all findings and statistics.
        """
        start_time = time.time()
        
        with self.parser.open():
            dump_info = self.parser.info
            
            # Detect architecture if needed (for raw dumps)
            if dump_info.architecture == "unknown" and dump_info.additional_info.get('_detect_arch_on_open'):
                dump_info.architecture = self.parser.detect_architecture()

            result = AnalysisResult(
                dump_info=dump_info,
                status=AnalysisStatus.RUNNING
            )
            
            # Determine which plugins to run
            plugins_to_run = self._plugins
            if plugin_names:
                plugins_to_run = [p for p in self._plugins if p.name in plugin_names]
            plugins_to_run = [p for p in plugins_to_run if p.enabled]
            
            # Run each plugin
            for plugin in plugins_to_run:
                try:
                    findings = plugin.analyze()
                    result.findings.extend(findings)
                    stats = plugin.get_statistics()
                    if stats:
                        result.statistics[plugin.name] = stats
                except Exception as e:
                    result.errors.append(f"Plugin {plugin.name} failed: {str(e)}")
            
            # Calculate duration
            result.duration = time.time() - start_time
            
            # Determine final status
            if result.errors and result.findings:
                result.status = AnalysisStatus.PARTIAL
            elif result.errors:
                result.status = AnalysisStatus.FAILED
            else:
                result.status = AnalysisStatus.COMPLETED
            
            # Add general statistics
            result.statistics['general'] = {
                'file_size': dump_info.size,
                'format': dump_info.format.name,
                'architecture': dump_info.architecture,
                'os_type': dump_info.os_type,
                'regions_count': len(dump_info.regions),
                'plugins_run': len(plugins_to_run),
            }
            
            self._current_result = result
            return result
    
    def get_result(self) -> Optional[AnalysisResult]:
        """Get the most recent analysis result."""
        return self._current_result
    
    def search(self, pattern: bytes) -> list[int]:
        """Search for a byte pattern in memory."""
        with self.parser.open():
            return list(self.parser.find_pattern(pattern))
    
    def extract_at(self, offset: int, size: int) -> bytes:
        """Extract bytes at a specific offset."""
        with self.parser.open():
            return self.parser.read_at(offset, size)
    
    def get_strings(self, min_length: int = 4) -> list[tuple[int, str]]:
        """Extract strings from memory."""
        with self.parser.open():
            return list(self.parser.get_strings(min_length))
