"""
Memory Analyzer Module

Core analysis engine that orchestrates plugins and performs
comprehensive memory analysis for security investigations.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

from .parser import MemoryParser, MemoryDumpInfo


class AnalysisStatus(Enum):
    """Status of an analysis operation."""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    PARTIAL = auto()


@dataclass(slots=True)
class AnalysisFinding:
    """Represents a single finding from analysis."""
    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    offset: int | None = None
    address: int | None = None
    evidence: bytes = field(default_factory=bytes)
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            'category': self.category,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'offset': self.offset,
            'address': hex(self.address) if self.address is not None else None,
            'evidence': self.evidence.hex() if self.evidence else None,
            'context': self.context
        }


@dataclass(slots=True)
class AnalysisResult:
    """Complete result of a memory analysis."""
    dump_info: MemoryDumpInfo
    findings: list[AnalysisFinding] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)
    duration: float = 0.0
    status: AnalysisStatus = AnalysisStatus.PENDING
    errors: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        """Count of critical severity findings."""
        return sum(1 for finding in self.findings if finding.severity == 'critical')

    @property
    def high_count(self) -> int:
        """Count of high severity findings."""
        return sum(1 for finding in self.findings if finding.severity == 'high')

    @property
    def medium_count(self) -> int:
        """Count of medium severity findings."""
        return sum(1 for finding in self.findings if finding.severity == 'medium')

    @property
    def total_findings(self) -> int:
        """Total count of all findings."""
        return len(self.findings)

    def summary(self) -> str:
        """Generate a summary of the analysis."""
        lines: list[str] = [
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

    Example:
        >>> class MyPlugin(AnalysisPlugin):
        ...     name = "my_plugin"
        ...     def analyze(self) -> list[AnalysisFinding]:
        ...         return []
    """

    name: str = "base_plugin"
    description: str = "Base analysis plugin"
    version: str = "1.0.0"

    def __init__(self) -> None:
        """Initialize the plugin."""
        self.enabled = True
        self._parser: MemoryParser | None = None

    def initialize(self, parser: MemoryParser) -> None:
        """Called when plugin is initialized with a parser.

        Args:
            parser: MemoryParser instance for accessing memory.
        """
        self._parser = parser

    def analyze(self) -> list[AnalysisFinding]:
        """
        Perform analysis and return findings.

        Override this method in subclasses to implement analysis logic.

        Returns:
            List of AnalysisFinding objects.
        """
        raise NotImplementedError("Subclasses must implement analyze()")

    def get_statistics(self) -> dict[str, Any]:
        """Return plugin-specific statistics."""
        return {}


class MemoryAnalyzer:
    """
    Main analysis engine for memory forensics.

    Orchestrates plugins, manages analysis state, and aggregates results.

    Example:
        >>> analyzer = MemoryAnalyzer("memory.dump")
        >>> analyzer.register_plugin(ProcessScanner())
        >>> result = analyzer.analyze()
        >>> print(f"Found {result.total_findings} findings")
    """

    def __init__(self, filepath: str | Path) -> None:
        """Initialize the analyzer with a memory dump file.

        Args:
            filepath: Path to the memory dump file.
        """
        self.filepath = Path(filepath)
        self.parser = MemoryParser(filepath)
        self._plugins: list[AnalysisPlugin] = []
        self._plugin_registry: dict[str, AnalysisPlugin] = {}
        self._current_result: AnalysisResult | None = None

    @property
    def plugins(self) -> list[AnalysisPlugin]:
        """Get list of registered plugins."""
        return self._plugins.copy()

    @property
    def plugin_names(self) -> list[str]:
        """Get names of registered plugins."""
        return [plugin.name for plugin in self._plugins]

    def register_plugin(self, plugin: AnalysisPlugin) -> None:
        """Register an analysis plugin.

        Args:
            plugin: AnalysisPlugin instance to register.
        """
        plugin.initialize(self.parser)
        self._plugins.append(plugin)
        self._plugin_registry[plugin.name] = plugin

    def unregister_plugin(self, name: str) -> bool:
        """Unregister a plugin by name.

        Args:
            name: Name of the plugin to unregister.

        Returns:
            True if plugin was unregistered, False if not found.
        """
        if name in self._plugin_registry:
            plugin = self._plugin_registry.pop(name)
            self._plugins.remove(plugin)
            return True
        return False

    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin by name.

        Args:
            name: Name of the plugin to enable.

        Returns:
            True if plugin was enabled, False if not found.
        """
        if name in self._plugin_registry:
            self._plugin_registry[name].enabled = True
            return True
        return False

    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin by name.

        Args:
            name: Name of the plugin to disable.

        Returns:
            True if plugin was disabled, False if not found.
        """
        if name in self._plugin_registry:
            self._plugin_registry[name].enabled = False
            return True
        return False

    def analyze(self, plugin_names: list[str] | None = None) -> AnalysisResult:
        """Run analysis with specified or all enabled plugins.

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
            plugins_to_run = self._get_plugins_to_run(plugin_names)

            # Run each plugin
            for plugin in plugins_to_run:
                self._run_plugin(plugin, result)

            # Calculate duration
            result.duration = time.time() - start_time

            # Determine final status
            result.status = self._determine_analysis_status(result)

            # Add general statistics
            result.statistics['general'] = self._build_general_statistics(dump_info, plugins_to_run)

            self._current_result = result
            return result

    def _get_plugins_to_run(self, plugin_names: list[str] | None) -> list[AnalysisPlugin]:
        """Get list of plugins to run based on input and enabled status.

        Args:
            plugin_names: List of plugin names to run, or None for all.

        Returns:
            List of plugins to execute.
        """
        plugins_to_run = self._plugins
        if plugin_names:
            plugins_to_run = [p for p in self._plugins if p.name in plugin_names]
        return [p for p in plugins_to_run if p.enabled]

    def _run_plugin(self, plugin: AnalysisPlugin, result: AnalysisResult) -> None:
        """Run a single plugin and collect its results.

        Args:
            plugin: Plugin to execute.
            result: AnalysisResult to populate with findings.
        """
        try:
            findings = plugin.analyze()
            result.findings.extend(findings)
            stats = plugin.get_statistics()
            if stats:
                result.statistics[plugin.name] = stats
        except Exception as exc:
            result.errors.append(f"Plugin {plugin.name} failed: {exc}")

    def _determine_analysis_status(self, result: AnalysisResult) -> AnalysisStatus:
        """Determine the final analysis status based on results.

        Args:
            result: AnalysisResult with completed analysis data.

        Returns:
            Appropriate AnalysisStatus value.
        """
        if result.errors and result.findings:
            return AnalysisStatus.PARTIAL
        elif result.errors:
            return AnalysisStatus.FAILED
        return AnalysisStatus.COMPLETED

    def _build_general_statistics(
        self,
        dump_info: MemoryDumpInfo,
        plugins_to_run: list[AnalysisPlugin]
    ) -> dict[str, Any]:
        """Build general statistics dictionary.

        Args:
            dump_info: Memory dump information.
            plugins_to_run: List of plugins that were executed.

        Returns:
            Dictionary of general statistics.
        """
        return {
            'file_size': dump_info.size,
            'format': dump_info.format.name,
            'architecture': dump_info.architecture,
            'os_type': dump_info.os_type,
            'regions_count': len(dump_info.regions),
            'plugins_run': len(plugins_to_run),
        }

    def get_result(self) -> AnalysisResult | None:
        """Get the most recent analysis result."""
        return self._current_result

    def search(self, pattern: bytes) -> list[int]:
        """Search for a byte pattern in memory.

        Args:
            pattern: Byte sequence to search for.

        Returns:
            List of offsets where pattern was found.
        """
        with self.parser.open():
            return list(self.parser.find_pattern(pattern))

    def extract_at(self, offset: int, size: int) -> bytes:
        """Extract bytes at a specific offset.

        Args:
            offset: Byte offset to extract from.
            size: Number of bytes to extract.

        Returns:
            Extracted bytes.
        """
        with self.parser.open():
            return self.parser.read_at(offset, size)

    def get_strings(self, min_length: int = 4) -> list[tuple[int, str]]:
        """Extract strings from memory.

        Args:
            min_length: Minimum string length to extract.

        Returns:
            List of (offset, string) tuples.
        """
        with self.parser.open():
            return list(self.parser.get_strings(min_length))
