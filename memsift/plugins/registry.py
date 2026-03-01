"""
Registry Scanner Plugin

Scans memory dumps for Windows registry artifacts including:
- Registry key paths and values
- Registry hive signatures
- Auto-run and persistence locations
- SAM and SECURITY hive indicators
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from collections import Counter

from ..core.analyzer import AnalysisPlugin, AnalysisFinding


@dataclass(slots=True)
class RegistryArtifact:
    """Represents a registry-related artifact found in memory."""
    artifact_type: str  # key, value, hive, persistence
    key_path: str
    value: str = ""
    offset: int = 0
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)


class RegistryScanner(AnalysisPlugin):
    """
    Scans memory for Windows registry artifacts.

    Detects registry key paths, hive signatures, persistence mechanisms,
    and suspicious registry modifications that may indicate malicious activity.
    """

    name = "registry_scanner"
    description = "Scan for Windows registry artifacts and persistence indicators"
    version = "1.0.0"

    # Registry hive signatures
    HIVE_SIGNATURES = {
        b'reg\x00': "Registry Hive",
        b'CMAP': "Registry CMAP",
        b'NLTM': "Registry NLTM",
    }

    # Registry key patterns
    KEY_PATTERNS = [
        re.compile(r'(HKEY_[A-Z_]+\\[^\s<>"|?*]+)', re.IGNORECASE),
        re.compile(r'(HKLM\\[^\s<>"|?*]+)', re.IGNORECASE),
        re.compile(r'(HKCU\\[^\s<>"|?*]+)', re.IGNORECASE),
        re.compile(r'(HKU\\[^\s<>"|?*]+)', re.IGNORECASE),
        re.compile(r'(HKCR\\[^\s<>"|?*]+)', re.IGNORECASE),
    ]

    # Persistence-related registry paths
    PERSISTENCE_PATHS = [
        r'(?i)CurrentVersion\\Run',
        r'(?i)CurrentVersion\\RunOnce',
        r'(?i)CurrentVersion\\Explorer\\Shell Folders',
        r'(?i)Windows\\CurrentVersion\\Explorer\\User Shell Folders',
        r'(?i)Microsoft\\Windows\\CurrentVersion\\Run',
        r'(?i)Policies\\Explorer\\Run',
        r'(?i)Winlogon\\Shell',
        r'(?i)Winlogon\\Userinit',
        r'(?i)Winlogon\\Notify',
        r'(?i)Services\\[a-zA-Z0-9_]+\\ImagePath',
        r'(?i)CurrentControlSet\\Services',
        r'(?i)Control\\Session Manager\\BootExecute',
        r'(?i)Control\\Session Manager\\AppCertDlls',
    ]

    # Suspicious registry values
    SUSPICIOUS_VALUES = [
        re.compile(r'(?i)cmd\.exe'),
        re.compile(r'(?i)powershell'),
        re.compile(r'(?i)wscript'),
        re.compile(r'(?i)cscript'),
        re.compile(r'(?i)mshta'),
        re.compile(r'(?i)regsvr32'),
        re.compile(r'(?i)rundll32'),
        re.compile(r'(?i)certutil'),
        re.compile(r'(?i)bitsadmin'),
        re.compile(r'(?i)-enc'),
        re.compile(r'(?i)-encodedcommand'),
        re.compile(r'(?i)-e\s+[A-Za-z0-9+/=]{20,}'),
    ]

    # Sensitive registry locations
    SENSITIVE_PATHS = [
        r'(?i)SAM\\SAM\\Domains\\Account',
        r'(?i)Security\\Policy\\Secrets',
        r'(?i)Control\\Lsa',
        r'(?i)Microsoft\\Windows\\CurrentVersion\\Authentication',
        r'(?i)Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
        r'(?i)Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MappedNetworkDriveMRU',
        r'(?i)Software\\Microsoft\\Terminal Server Client',
        r'(?i)Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
    ]

    def __init__(self):
        super().__init__()
        self._artifacts: list[RegistryArtifact] = []
        self._hive_count = 0
        self._persistence_count = 0
        self._suspicious_count = 0

    def analyze(self) -> list[AnalysisFinding]:
        """Scan memory for registry artifacts."""
        findings = []
        self._artifacts = []
        self._hive_count = 0
        self._persistence_count = 0
        self._suspicious_count = 0

        if self._parser is None:
            return findings

        # Search for registry hive signatures
        findings.extend(self._search_hive_signatures())

        # Extract registry key paths from strings
        findings.extend(self._extract_registry_keys())

        # Search for persistence mechanisms
        findings.extend(self._search_persistence())

        # Search for sensitive registry access
        findings.extend(self._search_sensitive_paths())

        return findings

    def _search_hive_signatures(self) -> list[AnalysisFinding]:
        """Search for registry hive signatures in memory."""
        findings = []

        for signature, name in self.HIVE_SIGNATURES.items():
            for offset in self._parser.find_pattern(signature, 0, min(0x10000000, self._parser.size)):
                self._hive_count += 1

                artifact = RegistryArtifact(
                    artifact_type='hive',
                    key_path=f"[{name} signature]",
                    offset=offset,
                )
                self._artifacts.append(artifact)

                findings.append(AnalysisFinding(
                    category="registry",
                    severity="info",
                    title=f"Registry Hive Signature: {name}",
                    description=f"Found {name} signature at offset {hex(offset)}. "
                               f"This indicates registry hive data in memory.",
                    offset=offset,
                    context={
                        'signature_type': name,
                        'signature_hex': signature.hex(),
                    }
                ))

                # Limit findings per signature type
                if len([f for f in findings if name in f.title]) >= 5:
                    break

        return findings

    def _extract_registry_keys(self) -> list[AnalysisFinding]:
        """Extract registry key paths from memory strings."""
        findings = []

        for offset, string in self._parser.get_strings(min_length=10):
            for pattern in self.KEY_PATTERNS:
                match = pattern.search(string)
                if match:
                    key_path = match.group(1)
                    is_suspicious, reasons = self._check_key_suspicion(key_path, string)

                    artifact = RegistryArtifact(
                        artifact_type='key',
                        key_path=key_path,
                        value=string[:200] if string != key_path else "",
                        offset=offset,
                        is_suspicious=is_suspicious,
                        suspicion_reasons=reasons,
                    )
                    self._artifacts.append(artifact)

                    if is_suspicious:
                        self._suspicious_count += 1
                        findings.append(self._create_finding(artifact))

                    break  # Only match first pattern

        return findings

    def _search_persistence(self) -> list[AnalysisFinding]:
        """Search for registry-based persistence mechanisms."""
        findings = []

        for offset, string in self._parser.get_strings(min_length=15):
            for persistence_pattern in self.PERSISTENCE_PATHS:
                if re.search(persistence_pattern, string):
                    self._persistence_count += 1

                    # Check if associated with suspicious commands
                    is_suspicious = False
                    reasons = ["Persistence mechanism location"]

                    for suspicious_pattern in self.SUSPICIOUS_VALUES:
                        if suspicious_pattern.search(string):
                            is_suspicious = True
                            reasons.append(f"Suspicious command pattern: {suspicious_pattern.pattern}")
                            break

                    artifact = RegistryArtifact(
                        artifact_type='persistence',
                        key_path=string[:300],
                        offset=offset,
                        is_suspicious=is_suspicious,
                        suspicion_reasons=reasons,
                    )
                    self._artifacts.append(artifact)

                    severity = "high" if is_suspicious else "medium"
                    findings.append(AnalysisFinding(
                        category="registry",
                        severity=severity,
                        title="Registry Persistence Mechanism Detected",
                        description=f"Found registry persistence indicator: {string[:100]}...",
                        offset=offset,
                        context={
                            'persistence_type': persistence_pattern,
                            'full_string': string[:300],
                            'reasons': reasons,
                        }
                    ))
                    break

        return findings

    def _search_sensitive_paths(self) -> list[AnalysisFinding]:
        """Search for access to sensitive registry paths."""
        findings = []

        for offset, string in self._parser.get_strings(min_length=15):
            for sensitive_pattern in self.SENSITIVE_PATHS:
                if re.search(sensitive_pattern, string):
                    artifact = RegistryArtifact(
                        artifact_type='sensitive',
                        key_path=string[:300],
                        offset=offset,
                        is_suspicious=True,
                        suspicion_reasons=["Sensitive registry path access"],
                    )
                    self._artifacts.append(artifact)

                    findings.append(AnalysisFinding(
                        category="registry",
                        severity="high",
                        title="Sensitive Registry Path Detected",
                        description=f"Found reference to sensitive registry location: {string[:100]}...",
                        offset=offset,
                        context={
                            'sensitive_pattern': sensitive_pattern,
                            'full_string': string[:300],
                        }
                    ))
                    break

        return findings

    def _check_key_suspicion(self, key_path: str, context: str) -> tuple[bool, list[str]]:
        """Check if a registry key path is suspicious."""
        reasons = []
        is_suspicious = False

        # Check for persistence paths
        for persistence_pattern in self.PERSISTENCE_PATHS:
            if re.search(persistence_pattern, key_path):
                is_suspicious = True
                reasons.append("Persistence-related path")
                break

        # Check for suspicious values in context
        for suspicious_pattern in self.SUSPICIOUS_VALUES:
            if suspicious_pattern.search(context):
                is_suspicious = True
                reasons.append(f"Suspicious command: {suspicious_pattern.pattern}")
                break

        # Check for sensitive paths
        for sensitive_pattern in self.SENSITIVE_PATHS:
            if re.search(sensitive_pattern, key_path):
                is_suspicious = True
                reasons.append("Sensitive registry location")
                break

        return is_suspicious, reasons

    def _create_finding(self, artifact: RegistryArtifact) -> AnalysisFinding:
        """Create an analysis finding for a suspicious registry artifact."""
        severity = "medium"
        if "persistence" in artifact.artifact_type:
            severity = "high"
        if artifact.artifact_type == "sensitive":
            severity = "high"
        if any("malicious" in r.lower() for r in artifact.suspicion_reasons):
            severity = "critical"

        return AnalysisFinding(
            category="registry",
            severity=severity,
            title=f"Suspicious Registry Artifact: {artifact.key_path[:50]}...",
            description=f"Detected suspicious registry activity. "
                       f"Reasons: {'; '.join(artifact.suspicion_reasons)}",
            offset=artifact.offset,
            context={
                'artifact_type': artifact.artifact_type,
                'key_path': artifact.key_path,
                'value': artifact.value,
                'reasons': artifact.suspicion_reasons,
            }
        )

    def get_statistics(self) -> dict:
        """Return registry scanning statistics."""
        artifact_types = Counter(a.artifact_type for a in self._artifacts)
        return {
            'total_artifacts': len(self._artifacts),
            'hive_signatures': self._hive_count,
            'persistence_indicators': self._persistence_count,
            'suspicious_count': self._suspicious_count,
            'by_type': dict(artifact_types),
        }

    def get_artifacts(self) -> list[RegistryArtifact]:
        """Get list of detected registry artifacts."""
        return self._artifacts.copy()
