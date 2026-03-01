"""
Crypto Scanner Plugin

Detects cryptographic artifacts in memory:
- Encryption keys and key material
- Cryptographic constants (S-boxes, round constants)
- Encrypted data patterns
- Crypto API usage
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.analyzer import AnalysisPlugin, AnalysisFinding

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass(slots=True)
class CryptoArtifact:
    """Represents a cryptographic artifact found in memory."""
    artifact_type: str  # key, constant, encrypted_data, api
    algorithm: str | None
    offset: int
    description: str
    confidence: str = "medium"
    evidence: bytes = field(default_factory=bytes)


class CryptoScanner(AnalysisPlugin):
    """
    Scans memory for cryptographic artifacts.

    Detects encryption keys, crypto constants, encrypted data patterns,
    and cryptographic API usage that may indicate ransomware or
    covert communication.
    """

    name = "crypto_scanner"
    description = "Detect cryptographic artifacts and encryption activity"
    version = "1.0.0"

    # Search limits
    SEARCH_LIMIT = 0x10000000  # 256 MB
    SAMPLE_SIZE = 256
    ENTROPY_THRESHOLD = 7.5  # Bits per byte (max is 8.0)
    HIGH_ENTROPY_BLOCK_THRESHOLD = 32

    # AES S-box (first 16 bytes as signature)
    AES_SBOX: bytes = bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ])

    # SHA-256 constants (first 8 bytes of K array)
    SHA256_K: bytes = bytes([
        0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
    ])

    # MD5 constants (first 8 bytes)
    MD5_K: bytes = bytes([
        0xd7, 0x6a, 0xa4, 0x78, 0xe8, 0xc7, 0xb7, 0x56,
    ])

    # Cryptographic API functions
    CRYPTO_APIS: tuple[bytes, ...] = (
        b'CryptEncrypt', b'CryptDecrypt', b'CryptGenKey',
        b'CryptImportKey', b'CryptExportKey', b'CryptDeriveKey',
        b'BCryptEncrypt', b'BCryptDecrypt',
        b'NCryptEncrypt', b'NCryptDecrypt',
        b'EVP_Encrypt', b'EVP_Decrypt',
        b'AES_set_encrypt_key', b'AES_set_decrypt_key',
        b'AES_encrypt', b'AES_decrypt',
    )

    # Ransomware indicator patterns
    RANSOMWARE_PATTERNS: tuple[str, ...] = (
        r'(?i)your\s*files\s*(have\s*)?been\s*encrypted',
        r'(?i)pay\s*(bitcoin|btc|monero|xmr)',
        r'(?i)decrypt(ion)?\s*key',
        r'(?i)ransom',
        r'(?i)\.encrypted\b',
        r'(?i)\.locked\b',
        r'(?i)\.crypto\b',
        r'(?i)readme.*decrypt',
    )

    def __init__(self) -> None:
        """Initialize the crypto scanner."""
        super().__init__()
        self._artifacts: list[CryptoArtifact] = []
        self._api_count = 0
        self._constant_detections = 0
        self._ransomware_indicators = 0
        self._compiled_ransomware_patterns = [
            re.compile(pattern) for pattern in self.RANSOMWARE_PATTERNS
        ]

    def analyze(self) -> list[AnalysisFinding]:
        """Scan memory for cryptographic artifacts.

        Returns:
            List of analysis findings for crypto activity.
        """
        findings: list[AnalysisFinding] = []
        self._artifacts = []
        self._api_count = 0
        self._constant_detections = 0
        self._ransomware_indicators = 0

        if self._parser is None:
            return findings

        # Search for crypto constants
        findings.extend(self._search_crypto_constants())

        # Search for crypto API references
        findings.extend(self._search_crypto_apis())

        # Search for ransomware indicators
        findings.extend(self._search_ransomware_indicators())

        # Look for high-entropy regions (potential encrypted data)
        findings.extend(self._find_high_entropy_regions())

        return findings

    def _search_crypto_constants(self) -> list[AnalysisFinding]:
        """Search for known cryptographic constants.

        Returns:
            List of findings for crypto constant detections.
        """
        findings: list[AnalysisFinding] = []

        if self._parser is None:
            return findings

        constants = [
            (self.AES_SBOX, "AES S-box", "AES"),
            (self.SHA256_K, "SHA-256 constants", "SHA-256"),
            (self.MD5_K, "MD5 constants", "MD5"),
        ]

        search_limit = min(self.SEARCH_LIMIT, self._parser.size)

        for pattern, name, algo in constants:
            type_findings_count = 0
            for offset in self._parser.find_pattern(pattern, 0, search_limit):
                if type_findings_count >= 3:
                    break

                self._constant_detections += 1
                type_findings_count += 1

                artifact = CryptoArtifact(
                    artifact_type='constant',
                    algorithm=algo,
                    offset=offset,
                    description=f"Found {name} at offset {hex(offset)}",
                    confidence='high',
                )
                self._artifacts.append(artifact)

                findings.append(AnalysisFinding(
                    category="crypto",
                    severity="low",
                    title=f"Cryptographic Constant: {name}",
                    description=f"Detected {name} which indicates {algo} implementation in memory.",
                    offset=offset,
                    context={
                        'constant_name': name,
                        'algorithm': algo,
                    }
                ))

        return findings

    def _search_crypto_apis(self) -> list[AnalysisFinding]:
        """Search for cryptographic API function references.

        Returns:
            List of findings for crypto API detections.
        """
        findings: list[AnalysisFinding] = []

        if self._parser is None:
            return findings

        search_limit = min(self.SEARCH_LIMIT, self._parser.size)

        for api in self.CRYPTO_APIS:
            api_findings_count = 0
            for offset in self._parser.find_pattern(api, 0, search_limit):
                if api_findings_count >= 5:
                    break

                self._api_count += 1
                api_findings_count += 1

                # Determine severity based on API type
                severity = "high" if any(
                    x in api for x in [b'Encrypt', b'Decrypt', b'Key']
                ) else "medium"

                findings.append(AnalysisFinding(
                    category="crypto",
                    severity=severity,
                    title=f"Cryptographic API: {api.decode()}",
                    description=(
                        f"Reference to {api.decode()} found at offset {hex(offset)}. "
                        f"This may indicate encryption/decryption activity."
                    ),
                    offset=offset,
                    context={
                        'api_name': api.decode(),
                    }
                ))

        return findings

    def _search_ransomware_indicators(self) -> list[AnalysisFinding]:
        """Search for ransomware-related strings and patterns.

        Returns:
            List of findings for ransomware indicators.
        """
        findings: list[AnalysisFinding] = []

        if self._parser is None:
            return findings

        for offset, string in self._parser.get_strings(min_length=10):
            for pattern in self._compiled_ransomware_patterns:
                if pattern.search(string):
                    self._ransomware_indicators += 1

                    artifact = CryptoArtifact(
                        artifact_type='ransomware_indicator',
                        algorithm=None,
                        offset=offset,
                        description=f"Ransomware indicator: {string[:100]}",
                        confidence='high',
                    )
                    self._artifacts.append(artifact)

                    findings.append(AnalysisFinding(
                        category="crypto",
                        severity="critical",
                        title="Potential Ransomware Indicator",
                        description=f"Detected ransomware-related string in memory: {string[:80]}",
                        offset=offset,
                        context={
                            'matched_string': string,
                            'pattern': pattern.pattern,
                        }
                    ))
                    break

        return findings

    def _find_high_entropy_regions(self) -> list[AnalysisFinding]:
        """Find regions with high entropy (potential encrypted data).

        Returns:
            List of findings for high-entropy regions.
        """
        findings: list[AnalysisFinding] = []

        if self._parser is None or not self._parser.info.regions:
            return findings

        for region in self._parser.info.regions:
            if not region.is_readable or region.size < self.SAMPLE_SIZE:
                continue

            finding = self._analyze_region_entropy(region)
            if finding is not None:
                findings.append(finding)

        return findings

    def _analyze_region_entropy(
        self,
        region: 'MemoryRegion'  # type: ignore[name-defined]
    ) -> AnalysisFinding | None:
        """Analyze a memory region for high entropy.

        Args:
            region: Memory region to analyze.

        Returns:
            AnalysisFinding if high entropy detected, None otherwise.
        """
        if self._parser is None:
            return None

        high_entropy_blocks = 0
        first_block_offset = None

        # Sample the region
        for i in range(0, min(region.size, 0x100000), self.SAMPLE_SIZE):
            try:
                data = self._parser.read_at(region.data_offset + i, self.SAMPLE_SIZE)
                entropy = self._calculate_entropy(data)

                if entropy > self.ENTROPY_THRESHOLD:
                    if high_entropy_blocks == 0:
                        first_block_offset = region.data_offset + i
                    high_entropy_blocks += 1
            except Exception:
                continue

        # Report if significant high-entropy region found
        if high_entropy_blocks >= self.HIGH_ENTROPY_BLOCK_THRESHOLD:
            return AnalysisFinding(
                category="crypto",
                severity="medium",
                title="High Entropy Memory Region",
                description=(
                    f"Found {high_entropy_blocks} consecutive high-entropy blocks "
                    f"starting at offset {hex(first_block_offset or 0)}. "
                    f"This may indicate encrypted or compressed data."
                ),
                offset=first_block_offset or region.data_offset,
                context={
                    'entropy_blocks': high_entropy_blocks,
                    'region_start': hex(region.start),
                    'estimated_size': high_entropy_blocks * self.SAMPLE_SIZE,
                }
            )

        return None

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data.

        Args:
            data: Bytes to calculate entropy for.

        Returns:
            Entropy value in bits per byte (0.0 to 8.0).
        """
        if not data:
            return 0.0

        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        # Calculate entropy
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return entropy

    def get_statistics(self) -> dict[str, int | dict[str, int]]:
        """Return crypto scanning statistics.

        Returns:
            Dictionary of statistics.
        """
        type_counts: dict[str, int] = dict(
            (key, sum(1 for a in self._artifacts if a.artifact_type == key))
            for key in set(a.artifact_type for a in self._artifacts)
        )
        return {
            'total_artifacts': len(self._artifacts),
            'api_references': self._api_count,
            'constant_detections': self._constant_detections,
            'ransomware_indicators': self._ransomware_indicators,
            'by_type': type_counts,
        }

    def get_artifacts(self) -> list[CryptoArtifact]:
        """Get list of crypto artifacts.

        Returns:
            Copy of the artifact list.
        """
        return self._artifacts.copy()
