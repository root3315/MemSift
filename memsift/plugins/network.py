"""
Network Analyzer Plugin

Scans memory dumps for network artifacts including:
- Socket structures and connections
- IP addresses and ports
- Network-related strings
- Potential C2 indicators
"""

from __future__ import annotations

import re
import socket
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.analyzer import AnalysisPlugin, AnalysisFinding

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass(slots=True)
class NetworkArtifact:
    """Represents a network-related artifact found in memory."""
    artifact_type: str  # ip, port, socket, url, domain
    value: str
    offset: int
    context: str = ""
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)


class NetworkAnalyzer(AnalysisPlugin):
    """
    Analyzes memory for network artifacts and potential C2 communication.

    Detects IP addresses, ports, URLs, domains, and socket structures.
    Identifies suspicious network indicators like known-bad IPs,
    unusual ports, and potential command-and-control patterns.
    """

    name = "network_analyzer"
    description = "Analyze network artifacts and detect C2 indicators"
    version = "1.0.0"

    # Suspicious port ranges with descriptions
    SUSPICIOUS_PORTS: dict[int, str] = {
        4444: "Metasploit default",
        5555: "Common backdoor",
        6666: "Common backdoor",
        8080: "Alternative HTTP (potential proxy)",
        8443: "Alternative HTTPS",
        1337: "Leet port (often used in exploits)",
        31337: "Back Orifice",
        65535: "Unusual high port",
    }

    # Suspicious TLDs often used by malware
    SUSPICIOUS_TLDS: tuple[str, ...] = (
        '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc'
    )

    # Suspicious URL paths
    SUSPICIOUS_PATHS: tuple[str, ...] = (
        '/gate.php', '/panel/', '/bot/', '/cmd/', '/beacon/'
    )

    # C2 pattern indicators
    C2_PATTERNS: tuple[str, ...] = (
        r'(?i)beacon',
        r'(?i)callback',
        r'(?i)stage[0-9]*',
        r'(?i)payload',
        r'(?i)shell',
        r'(?i)c2[_-]?server',
        r'(?i)command[_-]?control',
    )

    def __init__(self) -> None:
        """Initialize the network analyzer."""
        super().__init__()
        self._artifacts: list[NetworkArtifact] = []
        self._ip_counter: Counter = Counter()
        self._port_counter: Counter = Counter()
        self._suspicious_count = 0
        self._compiled_c2_patterns: list[re.Pattern] = [
            re.compile(pattern) for pattern in self.C2_PATTERNS
        ]
        self._private_ip_patterns: list[re.Pattern] = [
            re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'),
            re.compile(r'\b(172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})\b'),
            re.compile(r'\b(192\.168\.\d{1,3}\.\d{1,3})\b'),
        ]

    def analyze(self) -> list[AnalysisFinding]:
        """Analyze memory for network artifacts.

        Returns:
            List of analysis findings for suspicious network activity.
        """
        findings: list[AnalysisFinding] = []
        self._artifacts = []
        self._ip_counter = Counter()
        self._port_counter = Counter()
        self._suspicious_count = 0

        if self._parser is None:
            return findings

        # Extract strings and analyze for network artifacts
        for offset, string in self._parser.get_strings(min_length=4):
            artifacts = self._analyze_string(string, offset)
            for artifact in artifacts:
                self._artifacts.append(artifact)

                if artifact.artifact_type in ('ip', 'port'):
                    self._ip_counter[artifact.value] += 1
                    self._port_counter[artifact.value] += 1

                if artifact.is_suspicious:
                    self._suspicious_count += 1
                    findings.append(self._create_finding(artifact))

        # Check for high-frequency IPs (potential C2)
        for ip, count in self._ip_counter.most_common(10):
            if count > 5:
                findings.append(self._create_frequent_ip_finding(ip, count))

        return findings

    def _analyze_string(self, string: str, offset: int) -> list[NetworkArtifact]:
        """Analyze a string for network artifacts.

        Args:
            string: String to analyze.
            offset: Offset in memory.

        Returns:
            List of NetworkArtifact objects found.
        """
        artifacts: list[NetworkArtifact] = []

        # Check for IP addresses
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', string)
        if ip_match:
            ip = ip_match.group(1)
            if self._is_valid_ip(ip):
                artifact = NetworkArtifact(
                    artifact_type='ip',
                    value=ip,
                    offset=offset,
                    context=string
                )
                self._check_ip_suspicion(artifact)
                artifacts.append(artifact)

        # Check for URLs
        url_match = re.search(r'(https?://[^\s<>"{}|\\^`\[\]]+)', string, re.IGNORECASE)
        if url_match:
            url = url_match.group(1)
            artifact = NetworkArtifact(
                artifact_type='url',
                value=url,
                offset=offset,
                context=string
            )
            self._check_url_suspicion(artifact)
            artifacts.append(artifact)

        # Check for domains (avoid double-counting IPs)
        if not ip_match:
            domain_match = re.search(
                r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})\b', string
            )
            if domain_match:
                domain = domain_match.group(1)
                artifact = NetworkArtifact(
                    artifact_type='domain',
                    value=domain,
                    offset=offset,
                    context=string
                )
                self._check_domain_suspicion(artifact)
                artifacts.append(artifact)

        # Check for port patterns
        port_match = re.search(r':(\d{2,5})\b', string)
        if port_match:
            port = int(port_match.group(1))
            if 0 < port < 65536:
                artifact = NetworkArtifact(
                    artifact_type='port',
                    value=str(port),
                    offset=offset,
                    context=string
                )
                self._check_port_suspicion(artifact)
                artifacts.append(artifact)

        # Check for C2-related strings
        for pattern in self._compiled_c2_patterns:
            if pattern.search(string):
                artifact = NetworkArtifact(
                    artifact_type='c2_indicator',
                    value=string[:100],
                    offset=offset,
                    context=string,
                    is_suspicious=True,
                    suspicion_reasons=[f"C2 pattern match: {pattern.pattern}"]
                )
                artifacts.append(artifact)
                break

        return artifacts

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate an IP address.

        Args:
            ip: IP address string to validate.

        Returns:
            True if valid IPv4 address.
        """
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _check_ip_suspicion(self, artifact: NetworkArtifact) -> None:
        """Check if an IP is suspicious.

        Args:
            artifact: NetworkArtifact to check.
        """
        ip = artifact.value

        # Check for localhost/loopback
        if ip.startswith('127.'):
            return

        # Check for private IPs
        for pattern in self._private_ip_patterns:
            if pattern.match(ip):
                artifact.suspicion_reasons.append("Private IP range")
                break

        # Check for special IPs
        if ip in ('0.0.0.0', '255.255.255.255'):
            artifact.suspicion_reasons.append("Special IP address")

        if artifact.suspicion_reasons:
            artifact.is_suspicious = True

    def _check_port_suspicion(self, artifact: NetworkArtifact) -> None:
        """Check if a port is suspicious.

        Args:
            artifact: NetworkArtifact to check.
        """
        port = int(artifact.value)

        if port in self.SUSPICIOUS_PORTS:
            artifact.suspicion_reasons.append(self.SUSPICIOUS_PORTS[port])
            artifact.is_suspicious = True
        elif port > 49152:  # Dynamic/private range
            artifact.suspicion_reasons.append("Dynamic/private port range")
            artifact.is_suspicious = True

    def _check_url_suspicion(self, artifact: NetworkArtifact) -> None:
        """Check if a URL is suspicious.

        Args:
            artifact: NetworkArtifact to check.
        """
        url = artifact.value.lower()

        # Check for suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if url.endswith(tld):
                artifact.suspicion_reasons.append(f"Suspicious TLD: {tld}")
                artifact.is_suspicious = True
                break

        # Check for IP-based URLs
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            artifact.suspicion_reasons.append("IP-based URL (potential C2)")
            artifact.is_suspicious = True

        # Check for suspicious paths
        for path in self.SUSPICIOUS_PATHS:
            if path in url:
                artifact.suspicion_reasons.append(f"Suspicious path: {path}")
                artifact.is_suspicious = True
                break

    def _check_domain_suspicion(self, artifact: NetworkArtifact) -> None:
        """Check if a domain is suspicious.

        Args:
            artifact: NetworkArtifact to check.
        """
        domain = artifact.value.lower()

        # Check for suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                artifact.suspicion_reasons.append(f"Suspicious TLD: {tld}")
                artifact.is_suspicious = True
                break

        # Check for DGA-like patterns (high consonant ratio)
        name_part = domain.split('.')[0]
        if len(name_part) > 10:
            consonants = sum(1 for c in name_part if c.isalpha() and c.lower() not in 'aeiou')
            if consonants / max(len(name_part), 1) > 0.7:
                artifact.suspicion_reasons.append("Possible DGA domain (high consonant ratio)")
                artifact.is_suspicious = True

    def _create_finding(self, artifact: NetworkArtifact) -> AnalysisFinding:
        """Create an analysis finding for a suspicious artifact.

        Args:
            artifact: Suspicious NetworkArtifact.

        Returns:
            AnalysisFinding object.
        """
        severity = "medium"
        if "malicious" in " ".join(artifact.suspicion_reasons).lower():
            severity = "high"
        elif artifact.artifact_type == 'c2_indicator':
            severity = "high"

        return AnalysisFinding(
            category="network",
            severity=severity,
            title=f"Suspicious Network Artifact: {artifact.value}",
            description=(
                f"Detected suspicious {artifact.artifact_type}: {artifact.value}. "
                f"Reasons: {'; '.join(artifact.suspicion_reasons)}"
            ),
            offset=artifact.offset,
            context={
                'artifact_type': artifact.artifact_type,
                'value': artifact.value,
                'context': artifact.context[:200] if artifact.context else "",
                'reasons': artifact.suspicion_reasons,
            }
        )

    def _create_frequent_ip_finding(self, ip: str, count: int) -> AnalysisFinding:
        """Create a finding for a frequently occurring IP.

        Args:
            ip: IP address.
            count: Number of occurrences.

        Returns:
            AnalysisFinding object.
        """
        return AnalysisFinding(
            category="network",
            severity="low",
            title=f"Frequent IP Address: {ip}",
            description=(
                f"IP address {ip} appeared {count} times in memory. "
                f"May indicate active connection or embedded configuration."
            ),
            context={
                'ip': ip,
                'occurrence_count': count,
            }
        )

    def get_statistics(self) -> dict[str, int | dict[str, int]]:
        """Return network analysis statistics.

        Returns:
            Dictionary of statistics.
        """
        artifact_type_counts: dict[str, int] = dict(
            Counter(a.artifact_type for a in self._artifacts)
        )
        return {
            'total_artifacts': len(self._artifacts),
            'unique_ips': len(self._ip_counter),
            'unique_ports': len(self._port_counter),
            'suspicious_count': self._suspicious_count,
            'artifact_types': artifact_type_counts,
        }

    def get_artifacts(self) -> list[NetworkArtifact]:
        """Get list of detected network artifacts.

        Returns:
            Copy of the artifact list.
        """
        return self._artifacts.copy()
