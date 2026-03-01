"""
Process Scanner Plugin

Scans memory dumps for process artifacts including:
- Process structures (EPROCESS on Windows, task_struct on Linux)
- Process names and PIDs
- Suspicious process characteristics
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional

from ..core.analyzer import AnalysisPlugin, AnalysisFinding


@dataclass
class ProcessInfo:
    """Information about a detected process."""
    __slots__ = ('pid', 'name', 'offset', 'parent_pid', 'is_suspicious', 'suspicion_reasons')
    
    pid: int | None
    name: str
    offset: int
    parent_pid: int | None = None
    is_suspicious: bool = False
    suspicion_reasons: list[str] = None
    
    def __post_init__(self):
        if self.suspicion_reasons is None:
            self.suspicion_reasons = []


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
    SUSPICIOUS_PATTERNS = [
        r'(?i)inject',
        r'(?i)hook',
        r'(?i)patch',
        r'(?i)dump',
        r'(?i)steal',
        r'(?i)keylog',
        r'(?i)rat',
        r'(?i)backdoor',
        r'(?i)crypter',
        r'(?i)obfusc',
    ]
    
    # Known malicious process name fragments
    KNOWN_MALICIOUS = [
        'mimikatz', 'metasploit', 'meterpreter', 'cobalt',
        'beacon', 'empire', 'psexec', 'wmic',
    ]
    
    def __init__(self):
        super().__init__()
        self._processes: list[ProcessInfo] = []
        self._suspicious_count = 0
        self._compiled_patterns = [re.compile(p) for p in self.SUSPICIOUS_PATTERNS]
    
    def analyze(self) -> list[AnalysisFinding]:
        """Scan memory for process artifacts."""
        findings = []
        self._processes = []
        self._suspicious_count = 0
        
        if self._parser is None:
            return findings
        
        # Extract strings that look like process names
        for offset, string in self._parser.get_strings(min_length=4):
            # Filter for likely process names (alphanumeric, common extensions)
            if self._is_likely_process_name(string):
                process = self._analyze_process_string(string, offset)
                if process:
                    self._processes.append(process)
                    
                    if process.is_suspicious:
                        self._suspicious_count += 1
                        findings.append(self._create_finding(process))
        
        return findings
    
    def _is_likely_process_name(self, name: str) -> bool:
        """Check if a string looks like a process name."""
        if len(name) < 3 or len(name) > 64:
            return False
        
        # Must contain mostly alphanumeric characters
        alnum_count = sum(1 for c in name if c.isalnum() or c in '._-')
        if alnum_count < len(name) * 0.8:
            return False
        
        # Common executable extensions
        exe_extensions = ['.exe', '.dll', '.so', '.bin', '.sys', '.com']
        has_extension = any(name.lower().endswith(ext) for ext in exe_extensions)
        
        # Or looks like a Unix process name
        is_unix_name = name[0].isalpha() and all(c.isalnum() or c in '_-' for c in name)
        
        return has_extension or is_unix_name
    
    def _analyze_process_string(self, name: str, offset: int) -> Optional[ProcessInfo]:
        """Analyze a potential process name string."""
        suspicion_reasons = []
        
        # Check against known malicious names
        name_lower = name.lower()
        for malicious in self.KNOWN_MALICIOUS:
            if malicious in name_lower:
                suspicion_reasons.append(f"Known malicious tool: {malicious}")
        
        # Check against suspicious patterns
        for pattern in self._compiled_patterns:
            if pattern.search(name):
                suspicion_reasons.append(f"Suspicious pattern match: {pattern.pattern}")
        
        # Check for masquerading (e.g., svch0st.exe with zero instead of 'o')
        if self._is_masquerading(name):
            suspicion_reasons.append("Possible masquerading attempt")
        
        # Extract potential PID from nearby memory (heuristic)
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
        """Detect possible process name masquerading."""
        name_lower = name.lower()
        
        # Common masquerading targets
        legitimate_names = ['svchost', 'explorer', 'lsass', 'csrss', 'wininit', 'system']
        
        for legit in legitimate_names:
            if len(name_lower) == len(legit):
                # Check for character substitution (0 for o, 1 for l, etc.)
                diff_count = sum(1 for a, b in zip(name_lower, legit) if a != b)
                if diff_count == 1:
                    return True
        
        return False
    
    def _extract_nearby_pid(self, offset: int) -> Optional[int]:
        """Try to extract a PID from nearby memory."""
        if self._parser is None:
            return None
        
        try:
            # Look for common PID ranges near the process name
            for search_offset in [offset - 64, offset - 32, offset + len(self._parser.read_at(offset, 4))]:
                if search_offset < 0:
                    continue
                data = self._parser.read_at(search_offset, 8)
                if len(data) >= 4:
                    # Try little-endian 32-bit
                    import struct
                    pid = struct.unpack('<I', data[:4])[0]
                    if 0 < pid < 100000:  # Reasonable PID range
                        return pid
        except Exception:
            pass
        
        return None
    
    def _extract_nearby_ppid(self, offset: int) -> Optional[int]:
        """Try to extract a parent PID from nearby memory."""
        # Simplified - in real implementation would parse process structure
        return None
    
    def _create_finding(self, process: ProcessInfo) -> AnalysisFinding:
        """Create an analysis finding for a suspicious process."""
        return AnalysisFinding(
            category="process",
            severity="high" if any("malicious" in r.lower() for r in process.suspicion_reasons) else "medium",
            title=f"Suspicious Process: {process.name}",
            description=f"Detected suspicious process '{process.name}' (PID: {process.pid}). "
                       f"Reasons: {'; '.join(process.suspicion_reasons)}",
            offset=process.offset,
            context={
                'process_name': process.name,
                'pid': process.pid,
                'ppid': process.parent_pid,
                'reasons': process.suspicion_reasons,
            }
        )
    
    def get_statistics(self) -> dict:
        """Return process scanning statistics."""
        return {
            'total_processes_found': len(self._processes),
            'suspicious_count': self._suspicious_count,
            'unique_names': len(set(p.name for p in self._processes)),
        }
    
    def get_processes(self) -> list[ProcessInfo]:
        """Get list of detected processes."""
        return self._processes.copy()
