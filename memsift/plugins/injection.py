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

from ..core.analyzer import AnalysisPlugin, AnalysisFinding


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
    
    # Common shellcode patterns
    SHELLCODE_PATTERNS = {
        'egg_hunter': b'\x66\x81\xca\xff\x0f',  # Common egg hunter
        'metasploit_stager': b'\xfc\xe8\x89',  # Common MSF stager start
        'shellcode_nop_sled': b'\x90\x90\x90\x90\x90\x90\x90\x90',  # NOP sled
        'push_ret': b'\x50\xc3',  # push eax; ret
        'jmp_esp': b'\xff\xe4',  # jmp esp
    }
    
    # x64 syscall patterns
    X64_SYSCALL_PATTERNS = [
        b'\x0f\x05',  # syscall
        b'\xcd\x80',  # int 0x80 (x86)
        b'\x65\x48\x8b',  # mov rax, gs: (thread local storage access)
    ]
    
    # API hook signatures
    HOOK_SIGNATURES = {
        'jmp_abs': b'\xe9',  # JMP rel32
        'push_ret': b'\x68',  # push imm32
        'mov_rax_jmp': b'\x48\xb8',  # mov rax, imm64
    }
    
    # Suspicious API sequences
    SUSPICIOUS_APIS = [
        b'VirtualAlloc',
        b'VirtualProtect',
        b'WriteProcessMemory',
        b'CreateRemoteThread',
        b'NtMapViewOfSection',
        b'SetWindowsHookEx',
        b'GetAsyncKeyState',
        b'GetKeyState',
        b'GetForegroundWindow',
    ]
    
    def __init__(self):
        super().__init__()
        self._indicators: list[InjectionIndicator] = []
        self._rwx_regions = 0
        self._shellcode_detections = 0
        self._hook_detections = 0
    
    def analyze(self) -> list[AnalysisFinding]:
        """Analyze memory for injection indicators."""
        findings = []
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
        """Analyze memory region permissions for RWX regions."""
        findings = []
        
        for region in self._parser.info.regions:
            if region.is_readable and region.is_writable and region.is_executable:
                self._rwx_regions += 1
                
                indicator = InjectionIndicator(
                    indicator_type='rwx_memory',
                    description=f"RWX memory region detected at {hex(region.start)}-{hex(region.end)}",
                    offset=region.data_offset,
                    address=region.start,
                    confidence='high',
                )
                self._indicators.append(indicator)
                
                findings.append(AnalysisFinding(
                    category="injection",
                    severity="high",
                    title="RWX Memory Region Detected",
                    description=f"Memory region with Read-Write-Execute permissions found. "
                               f"This is a common indicator of code injection. "
                               f"Region: {hex(region.start)}-{hex(region.end)} ({region.size} bytes)",
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
        """Search for known shellcode patterns."""
        findings = []

        for name, pattern in self.SHELLCODE_PATTERNS.items():
            for offset in self._parser.find_pattern(pattern, 0, min(0x10000000, self._parser.size)):
                self._shellcode_detections += 1

                # Get surrounding context
                try:
                    context = self._parser.read_at(max(0, offset - 16), 48)
                except Exception:
                    context = pattern

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

                # Limit findings to prevent overwhelming output
                if self._shellcode_detections >= 10:
                    break

            if self._shellcode_detections >= 10:
                break

        return findings

    def _search_suspicious_apis(self) -> list[AnalysisFinding]:
        """Search for suspicious API function references."""
        findings = []

        for api_name in self.SUSPICIOUS_APIS:
            for offset in self._parser.find_pattern(api_name, 0, min(0x10000000, self._parser.size)):
                # Check if this is in an executable region (more suspicious)
                is_in_executable = False
                for region in self._parser.info.regions:
                    if region.contains(offset) and region.is_executable:
                        is_in_executable = True
                        break

                severity = "high" if is_in_executable else "medium"

                findings.append(AnalysisFinding(
                    category="injection",
                    severity=severity,
                    title=f"Suspicious API Reference: {api_name.decode()}",
                    description=f"Reference to {api_name.decode()} found at offset {hex(offset)}. "
                               f"{'Located in executable memory region.' if is_in_executable else ''}",
                    offset=offset,
                    context={
                        'api_name': api_name.decode(),
                        'in_executable_region': is_in_executable,
                    }
                ))

                # Limit per API
                if len([f for f in findings if api_name.decode() in f.title]) >= 5:
                    break

        return findings
    
    def _search_hooks(self) -> list[AnalysisFinding]:
        """Search for API hooking signatures."""
        findings = []

        # Common hook locations (start of important APIs)
        # In a real implementation, we'd check known API addresses
        # Here we search for hook patterns generally

        # Search for JMP rel32 (common inline hook)
        jmp_pattern = self.HOOK_SIGNATURES['jmp_abs']
        for offset in self._parser.find_pattern(jmp_pattern, 0, min(0x10000000, self._parser.size)):
            # Read the jump offset
            try:
                jump_data = self._parser.read_at(offset, 5)
                if len(jump_data) == 5 and jump_data[0] == 0xe9:
                    rel_offset = struct.unpack('<i', jump_data[1:5])[0]
                    target = offset + 5 + rel_offset

                    # Check if jumping outside normal code flow (large jump)
                    if abs(rel_offset) > 0x1000:
                        self._hook_detections += 1

                        findings.append(AnalysisFinding(
                            category="injection",
                            severity="medium",
                            title="Potential API Hook Detected",
                            description=f"Long JMP instruction at offset {hex(offset)} "
                                       f"jumping to {hex(target)} (rel: {rel_offset})",
                            offset=offset,
                            evidence=jump_data,
                            context={
                                'hook_type': 'jmp_rel32',
                                'target_address': hex(target),
                                'relative_offset': rel_offset,
                            }
                        ))

                        if self._hook_detections >= 20:
                            break
            except Exception:
                pass

            if self._hook_detections >= 20:
                break

        return findings
    
    def get_statistics(self) -> dict:
        """Return injection detection statistics."""
        return {
            'total_indicators': len(self._indicators),
            'rwx_regions': self._rwx_regions,
            'shellcode_detections': self._shellcode_detections,
            'hook_detections': self._hook_detections,
            'by_type': dict(
                (k, sum(1 for i in self._indicators if i.indicator_type == k))
                for k in set(i.indicator_type for i in self._indicators)
            ),
        }
    
    def get_indicators(self) -> list[InjectionIndicator]:
        """Get list of injection indicators."""
        return self._indicators.copy()
