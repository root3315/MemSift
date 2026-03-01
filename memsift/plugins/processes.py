"""
Process Scanner Plugin

Scans memory dumps for process artifacts including:
- Process structures (EPROCESS on Windows, task_struct on Linux)
- Process names and PIDs
- Suspicious process characteristics
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.analyzer import AnalysisPlugin, AnalysisFinding

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass(slots=True)
class ProcessInfo:
    """Information about a detected process."""
    pid: int | None
    name: str
    offset: int
    parent_pid: int | None = None
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)


class ProcessScanner(AnalysisPlugin):
    """
    Scans memory for process artifacts.

    Detects process structures, enumerates running processes,
    and identifies suspicious process characteristics.
    """

    name = "process_scanner"
    description = "Scan for process artifacts and detect suspicious processes"
    version = "1.0.0"

    # Common suspicious process name patterns
    SUSPICIOUS_PATTERNS: tuple[str, ...] = (
        r'(?i)inject',
        r'(?i)hook',
        r'(?i)patch',
        r'(?i)dump',
        r'(?i)steal',
        r'(?i)keylog',
        r'(?i)rat\b',
        r'(?i)backdoor',
        r'(?i)crypter',
        r'(?i)obfusc',
    )

    # Known malicious process name fragments
    KNOWN_MALICIOUS: tuple[str, ...] = (
        'mimikatz', 'metasploit', 'meterpreter', 'cobalt',
        'beacon', 'empire', 'psexec', 'wmic',
    )

    # Common executable extensions
    EXECUTABLE_EXTENSIONS: tuple[str, ...] = ('.exe', '.dll', '.so', '.bin', '.sys', '.com')

    # Legitimate process names for masquerading detection
    LEGITIMATE_PROCESS_NAMES: tuple[str, ...] = (
        'svchost', 'explorer', 'lsass', 'csrss', 'wininit', 'system'
    )

    def __init__(self) -> None:
        """Initialize the process scanner."""
        super().__init__()
        self._processes: list[ProcessInfo] = []
        self._suspicious_count = 0
        self._compiled_patterns: list[re.Pattern] = [
            re.compile(pattern) for pattern in self.SUSPICIOUS_PATTERNS
        ]

    def analyze(self) -> list[AnalysisFinding]:
        """Scan memory for process artifacts.

        Returns:
            List of analysis findings for suspicious processes.
        """
        findings: list[AnalysisFinding] = []
        self._processes = []
        self._suspicious_count = 0

        if self._parser is None:
            return findings

        # Extract strings that look like process names
        for offset, string in self._parser.get_strings(min_length=4):
            if self._is_likely_process_name(string):
                process = self._analyze_process_string(string, offset)
                if process is not None:
                    self._processes.append(process)

                    if process.is_suspicious:
                        self._suspicious_count += 1
                        findings.append(self._create_finding(process))

        return findings

    def _is_likely_process_name(self, name: str) -> bool:
        """Check if a string looks like a process name.

        Args:
            name: String to check.

        Returns:
            True if the string appears to be a process name.
        """
        if len(name) < 3 or len(name) > 64:
            return False

        # Must contain mostly alphanumeric characters
        alnum_count = sum(1 for c in name if c.isalnum() or c in '._-')
        if alnum_count < len(name) * 0.8:
            return False

        # Common executable extensions
        has_extension = any(name.lower().endswith(ext) for ext in self.EXECUTABLE_EXTENSIONS)

        # Or looks like a Unix process name
        is_unix_name = name[0].isalpha() and all(c.isalnum() or c in '_-' for c in name)

        return has_extension or is_unix_name

    def _analyze_process_string(self, name: str, offset: int) -> ProcessInfo | None:
        """Analyze a potential process name string.

        Args:
            name: Process name string.
            offset: Offset in memory where string was found.

        Returns:
            ProcessInfo object or None if invalid.
        """
        suspicion_reasons: list[str] = []

        # Check against known malicious names
        name_lower = name.lower()
        for malicious in self.KNOWN_MALICIOUS:
            if malicious in name_lower:
                suspicion_reasons.append(f"Known malicious tool: {malicious}")

        # Check against suspicious patterns
        for pattern in self._compiled_patterns:
            if pattern.search(name):
                suspicion_reasons.append(f"Suspicious pattern match: {pattern.pattern}")

        # Check for masquerading
        if self._is_masquerading(name):
            suspicion_reasons.append("Possible masquerading attempt")

        # Extract potential PID from nearby memory
        pid = self._extract_nearby_pid(offset)
        ppid = self._extract_nearby_ppid(offset)

        return ProcessInfo(
            pid=pid,
            name=name,
            offset=offset,
            parent_pid=ppid,
            is_suspicious=len(suspicion_reasons) > 0,
            suspicion_reasons=suspicion_reasons
        )

    def _is_masquerading(self, name: str) -> bool:
        """Detect possible process name masquerading.

        Args:
            name: Process name to check.

        Returns:
            True if the name appears to be masquerading as a legitimate process.
        """
        name_lower = name.lower()
        # Remove extension for comparison
        name_base = name_lower.rsplit('.', 1)[0] if '.' in name_lower else name_lower

        for legit in self.LEGITIMATE_PROCESS_NAMES:
            if len(name_base) == len(legit):
                # Check for character substitution (0 for o, 1 for l, etc.)
                diff_count = sum(1 for a, b in zip(name_base, legit) if a != b)
                if diff_count == 1:
                    return True

        return False

    def _extract_nearby_pid(self, offset: int) -> int | None:
        """Try to extract a PID from nearby memory.

        Args:
            offset: Offset of the process name string.

        Returns:
            PID value or None if not found.
        """
        if self._parser is None:
            return None

        search_offsets = [offset - 64, offset - 32]
        try:
            name_len = len(self._parser.read_at(offset, 4))
            search_offsets.append(offset + name_len)
        except Exception:
            pass

        for search_offset in search_offsets:
            if search_offset < 0:
                continue
            pid = self._try_parse_pid_at_offset(search_offset)
            if pid is not None:
                return pid

        return None

    def _try_parse_pid_at_offset(self, offset: int) -> int | None:
        """Try to parse a PID value at a specific offset.

        Args:
            offset: Offset to check.

        Returns:
            PID value or None if not a valid PID.
        """
        try:
            data = self._parser.read_at(offset, 8)
            if len(data) >= 4:
                pid = struct.unpack('<I', data[:4])[0]
                if 0 < pid < 100000:  # Reasonable PID range
                    return pid
        except Exception:
            pass
        return None

    def _extract_nearby_ppid(self, offset: int) -> int | None:
        """Try to extract a parent PID from nearby memory.

        Args:
            offset: Offset of the process name string.

        Returns:
            Parent PID value or None.
        """
        # Simplified - in real implementation would parse process structure
        return None

    def _create_finding(self, process: ProcessInfo) -> AnalysisFinding:
        """Create an analysis finding for a suspicious process.

        Args:
            process: ProcessInfo for the suspicious process.

        Returns:
            AnalysisFinding object.
        """
        severity = "high" if any(
            "malicious" in reason.lower() for reason in process.suspicion_reasons
        ) else "medium"

        return AnalysisFinding(
            category="process",
            severity=severity,
            title=f"Suspicious Process: {process.name}",
            description=(
                f"Detected suspicious process '{process.name}' (PID: {process.pid}). "
                f"Reasons: {'; '.join(process.suspicion_reasons)}"
            ),
            offset=process.offset,
            context={
                'process_name': process.name,
                'pid': process.pid,
                'ppid': process.parent_pid,
                'reasons': process.suspicion_reasons,
            }
        )

    def get_statistics(self) -> dict[str, int]:
        """Return process scanning statistics.

        Returns:
            Dictionary of statistics.
        """
        return {
            'total_processes_found': len(self._processes),
            'suspicious_count': self._suspicious_count,
            'unique_names': len(set(p.name for p in self._processes)),
        }

    def get_processes(self) -> list[ProcessInfo]:
        """Get list of detected processes.

        Returns:
            Copy of the process list.
        """
        return self._processes.copy()
