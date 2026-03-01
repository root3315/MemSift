"""
Injection Detector Plugin

Detects code injection techniques in memory:
- DLL injection artifacts
- Process hollowing indicators
- Shellcode patterns
- RWX memory regions
- API hooking signatures
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.analyzer import AnalysisPlugin, AnalysisFinding

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass(slots=True)
class InjectionIndicator:
    """Represents a potential code injection indicator."""
    indicator_type: str  # rwx_memory, shellcode, hook, hollowing
    description: str
    offset: int
    address: int | None = None
    confidence: str = "medium"  # low, medium, high
    evidence: bytes = field(default_factory=bytes)


class InjectionDetector(AnalysisPlugin):
    """
    Detects code injection techniques in memory dumps.

    Identifies RWX memory regions, shellcode patterns,
    API hooks, and process hollowing indicators.
    """

    name = "injection_detector"
    description = "Detect code injection techniques and shellcode"
    version = "1.0.0"

    # Maximum findings per category to prevent overwhelming output
    MAX_SHELLCODE_FINDINGS = 10
    MAX_API_FINDINGS_PER_TYPE = 5
    MAX_HOOK_FINDINGS = 20
    SEARCH_LIMIT = 0x10000000  # 256 MB search limit

    # Common shellcode patterns
    SHELLCODE_PATTERNS: dict[str, bytes] = {
        'egg_hunter': b'\x66\x81\xca\xff\x0f',
        'metasploit_stager': b'\xfc\xe8\x89',
        'shellcode_nop_sled': b'\x90\x90\x90\x90\x90\x90\x90\x90',
        'push_ret': b'\x50\xc3',
        'jmp_esp': b'\xff\xe4',
    }

    # x64 syscall patterns
    X64_SYSCALL_PATTERNS: tuple[bytes, ...] = (
        b'\x0f\x05',  # syscall
        b'\xcd\x80',  # int 0x80 (x86)
        b'\x65\x48\x8b',  # mov rax, gs: (thread local storage access)
    )

    # API hook signatures
    HOOK_SIGNATURES: dict[str, bytes] = {
        'jmp_abs': b'\xe9',  # JMP rel32
        'push_ret': b'\x68',  # push imm32
        'mov_rax_jmp': b'\x48\xb8',  # mov rax, imm64
    }

    # Suspicious API function names
    SUSPICIOUS_APIS: tuple[bytes, ...] = (
        b'VirtualAlloc',
        b'VirtualProtect',
        b'WriteProcessMemory',
        b'CreateRemoteThread',
        b'NtMapViewOfSection',
        b'SetWindowsHookEx',
        b'GetAsyncKeyState',
        b'GetKeyState',
        b'GetForegroundWindow',
    )

    def __init__(self) -> None:
        """Initialize the injection detector."""
        super().__init__()
        self._indicators: list[InjectionIndicator] = []
        self._rwx_regions = 0
        self._shellcode_detections = 0
        self._hook_detections = 0

    def analyze(self) -> list[AnalysisFinding]:
        """Analyze memory for injection indicators.

        Returns:
            List of analysis findings for injection techniques.
        """
        findings: list[AnalysisFinding] = []
        self._indicators = []
        self._rwx_regions = 0
        self._shellcode_detections = 0
        self._hook_detections = 0

        if self._parser is None:
            return findings

        # Check for RWX memory regions
        findings.extend(self._analyze_memory_permissions())

        # Search for shellcode patterns
        findings.extend(self._search_shellcode())

        # Search for suspicious API references
        findings.extend(self._search_suspicious_apis())

        # Look for hook signatures
        findings.extend(self._search_hooks())

        return findings

    def _analyze_memory_permissions(self) -> list[AnalysisFinding]:
        """Analyze memory region permissions for RWX regions.

        Returns:
            List of findings for RWX regions.
        """
        findings: list[AnalysisFinding] = []

        if self._parser is None:
            return findings

        for region in self._parser.info.regions:
            if region.is_readable and region.is_writable and region.is_executable:
                self._rwx_regions += 1

                indicator = InjectionIndicator(
                    indicator_type='rwx_memory',
                    description=f"RWX memory region at {hex(region.start)}-{hex(region.end)}",
                    offset=region.data_offset,
                    address=region.start,
                    confidence='high',
                )
                self._indicators.append(indicator)

                findings.append(AnalysisFinding(
                    category="injection",
                    severity="high",
                    title="RWX Memory Region Detected",
                    description=(
                        f"Memory region with Read-Write-Execute permissions found. "
                        f"This is a common indicator of code injection. "
                        f"Region: {hex(region.start)}-{hex(region.end)} ({region.size} bytes)"
                    ),
                    offset=region.data_offset,
                    address=region.start,
                    context={
                        'region_start': hex(region.start),
                        'region_end': hex(region.end),
                        'region_size': region.size,
                        'permissions': region.permissions,
                    }
                ))

        return findings

    def _search_shellcode(self) -> list[AnalysisFinding]:
        """Search for known shellcode patterns.

        Returns:
            List of findings for shellcode detections.
        """
        findings: list[AnalysisFinding] = []

        if self._parser is None:
            return findings

        search_limit = min(self.SEARCH_LIMIT, self._parser.size)

        for name, pattern in self.SHELLCODE_PATTERNS.items():
            if self._shellcode_detections >= self.MAX_SHELLCODE_FINDINGS:
                break

            for offset in self._parser.find_pattern(pattern, 0, search_limit):
                self._shellcode_detections += 1

                context = self._safe_read_context(offset, pattern)

                findings.append(AnalysisFinding(
                    category="injection",
                    severity="high",
                    title=f"Shellcode Pattern: {name}",
                    description=f"Detected {name} pattern at offset {hex(offset)}",
                    offset=offset,
                    evidence=context,
                    context={
                        'pattern_name': name,
                        'pattern_hex': pattern.hex(),
                    }
                ))

                if self._shellcode_detections >= self.MAX_SHELLCODE_FINDINGS:
                    break

        return findings

    def _safe_read_context(self, offset: int, pattern: bytes) -> bytes:
        """Safely read context around a pattern match.

        Args:
            offset: Offset of the pattern.
            pattern: Matched pattern bytes.

        Returns:
            Context bytes or the pattern itself if read fails.
        """
        if self._parser is None:
            return pattern

        try:
            return self._parser.read_at(max(0, offset - 16), 48)
        except Exception:
            return pattern

    def _search_suspicious_apis(self) -> list[AnalysisFinding]:
        """Search for suspicious API function references.

        Returns:
            List of findings for suspicious API references.
        """
        findings: list[AnalysisFinding] = []

        if self._parser is None:
            return findings

        search_limit = min(self.SEARCH_LIMIT, self._parser.size)

        for api_name in self.SUSPICIOUS_APIS:
            api_findings_count = 0
            for offset in self._parser.find_pattern(api_name, 0, search_limit):
                if api_findings_count >= self.MAX_API_FINDINGS_PER_TYPE:
                    break

                is_in_executable = self._is_offset_in_executable_region(offset)
                severity = "high" if is_in_executable else "medium"

                findings.append(AnalysisFinding(
                    category="injection",
                    severity=severity,
                    title=f"Suspicious API Reference: {api_name.decode()}",
                    description=(
                        f"Reference to {api_name.decode()} found at offset {hex(offset)}. "
                        f"{'Located in executable memory region.' if is_in_executable else ''}"
                    ),
                    offset=offset,
                    context={
                        'api_name': api_name.decode(),
                        'in_executable_region': is_in_executable,
                    }
                ))
                api_findings_count += 1

        return findings

    def _is_offset_in_executable_region(self, offset: int) -> bool:
        """Check if an offset is in an executable memory region.

        Args:
            offset: Offset to check.

        Returns:
            True if in executable region.
        """
        if self._parser is None:
            return False

        for region in self._parser.info.regions:
            if region.contains(offset) and region.is_executable:
                return True
        return False

    def _search_hooks(self) -> list[AnalysisFinding]:
        """Search for API hooking signatures.

        Returns:
            List of findings for potential hooks.
        """
        findings: list[AnalysisFinding] = []

        if self._parser is None:
            return findings

        # Search for JMP rel32 (common inline hook)
        jmp_pattern = self.HOOK_SIGNATURES['jmp_abs']
        search_limit = min(self.SEARCH_LIMIT, self._parser.size)

        for offset in self._parser.find_pattern(jmp_pattern, 0, search_limit):
            if self._hook_detections >= self.MAX_HOOK_FINDINGS:
                break

            finding = self._analyze_potential_hook(offset)
            if finding is not None:
                findings.append(finding)
                self._hook_detections += 1

        return findings

    def _analyze_potential_hook(self, offset: int) -> AnalysisFinding | None:
        """Analyze a potential hook at an offset.

        Args:
            offset: Offset to analyze.

        Returns:
            AnalysisFinding if hook detected, None otherwise.
        """
        if self._parser is None:
            return None

        try:
            jump_data = self._parser.read_at(offset, 5)
            if len(jump_data) != 5 or jump_data[0] != 0xe9:
                return None

            rel_offset = struct.unpack('<i', jump_data[1:5])[0]
            target = offset + 5 + rel_offset

            # Check if jumping outside normal code flow (large jump)
            if abs(rel_offset) <= 0x1000:
                return None

            return AnalysisFinding(
                category="injection",
                severity="medium",
                title="Potential API Hook Detected",
                description=(
                    f"Long JMP instruction at offset {hex(offset)} "
                    f"jumping to {hex(target)} (rel: {rel_offset})"
                ),
                offset=offset,
                evidence=jump_data,
                context={
                    'hook_type': 'jmp_rel32',
                    'target_address': hex(target),
                    'relative_offset': rel_offset,
                }
            )
        except Exception:
            return None

    def get_statistics(self) -> dict[str, int | dict[str, int]]:
        """Return injection detection statistics.

        Returns:
            Dictionary of statistics.
        """
        type_counts: dict[str, int] = dict(
            (key, sum(1 for i in self._indicators if i.indicator_type == key))
            for key in set(i.indicator_type for i in self._indicators)
        )
        return {
            'total_indicators': len(self._indicators),
            'rwx_regions': self._rwx_regions,
            'shellcode_detections': self._shellcode_detections,
            'hook_detections': self._hook_detections,
            'by_type': type_counts,
        }

    def get_indicators(self) -> list[InjectionIndicator]:
        """Get list of injection indicators.

        Returns:
            Copy of the indicator list.
        """
        return self._indicators.copy()
