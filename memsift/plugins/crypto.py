"""
Crypto Scanner Plugin

Detects cryptographic artifacts in memory:
- Encryption keys and key material
- Cryptographic constants (S-boxes, round constants)
- Encrypted data patterns
- Crypto API usage
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional

from ..core.analyzer import AnalysisPlugin, AnalysisFinding


@dataclass
class CryptoArtifact:
    """Represents a cryptographic artifact found in memory."""
    artifact_type: str  # key, constant, encrypted_data, api
    algorithm: Optional[str]
    offset: int
    description: str
    confidence: str = "medium"
    evidence: bytes = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = b''


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
    
    # AES S-box (first bytes as signature)
    AES_SBOX = bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ])
    
    # DES initial permutation table signature
    DES_IP = bytes([
        0x3a, 0x32, 0x36, 0x2a, 0x3c, 0x2c, 0x34, 0x24,
    ])
    
    # RC4 key scheduling signature pattern
    RC4_KSA_PATTERN = b'\x89\xf9\x33\xc0\x99'
    
    # SHA-256 constants (first 8 bytes of K array)
    SHA256_K = bytes([
        0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
    ])
    
    # MD5 constants
    MD5_K = bytes([
        0xd7, 0x6a, 0xa4, 0x78, 0xe8, 0xc7, 0xb7, 0x56,
    ])
    
    # RSA common exponents
    RSA_EXPONENTS = [
        bytes([0x01, 0x00, 0x01]),  # 65537 (most common)
        bytes([0x03]),  # 3 (less common)
        bytes([0x11]),  # 17
    ]
    
    # Cryptographic API functions
    CRYPTO_APIS = [
        b'CryptEncrypt',
        b'CryptDecrypt',
        b'CryptGenKey',
        b'CryptImportKey',
        b'CryptExportKey',
        b'CryptDeriveKey',
        b'BCryptEncrypt',
        b'BCryptDecrypt',
        b'NCryptEncrypt',
        b'NCryptDecrypt',
        b'EVP_Encrypt',
        b'EVP_Decrypt',
        b'AES_set_encrypt_key',
        b'AES_set_decrypt_key',
        b'AES_encrypt',
        b'AES_decrypt',
    ]
    
    # Ransomware indicators
    RANSOMWARE_PATTERNS = [
        re.compile(r'(?i)your\s*files\s*(have\s*)?been\s*encrypted'),
        re.compile(r'(?i)pay\s*(bitcoin|btc|monero|xmr)'),
        re.compile(r'(?i)decrypt(ion)?\s*key'),
        re.compile(r'(?i)ransom'),
        re.compile(r'(?i)\.encrypted\b'),
        re.compile(r'(?i)\.locked\b'),
        re.compile(r'(?i)\.crypto\b'),
        re.compile(r'(?i)readme.*decrypt'),
    ]
    
    # High entropy threshold for encrypted data detection
    ENTROPY_THRESHOLD = 7.5  # Bits per byte (max is 8.0)
    
    def __init__(self):
        super().__init__()
        self._artifacts: list[CryptoArtifact] = []
        self._api_count = 0
        self._constant_detections = 0
        self._ransomware_indicators = 0
    
    def analyze(self) -> list[AnalysisFinding]:
        """Scan memory for cryptographic artifacts."""
        findings = []
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
        """Search for known cryptographic constants."""
        findings = []
        
        constants = [
            (self.AES_SBOX, "AES S-box", "AES"),
            (self.SHA256_K, "SHA-256 constants", "SHA-256"),
            (self.MD5_K, "MD5 constants", "MD5"),
        ]

        for pattern, name, algo in constants:
            for offset in self._parser.find_pattern(pattern, 0, min(0x10000000, self._parser.size)):
                self._constant_detections += 1

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

                # Limit per constant type
                if len([f for f in findings if name in f.title]) >= 3:
                    break
        
        return findings
    
    def _search_crypto_apis(self) -> list[AnalysisFinding]:
        """Search for cryptographic API function references."""
        findings = []

        for api in self.CRYPTO_APIS:
            for offset in self._parser.find_pattern(api, 0, min(0x10000000, self._parser.size)):
                self._api_count += 1

                # Determine severity based on API type
                severity = "medium"
                if any(x in api for x in [b'Encrypt', b'Decrypt', b'Key']):
                    severity = "high"

                findings.append(AnalysisFinding(
                    category="crypto",
                    severity=severity,
                    title=f"Cryptographic API: {api.decode()}",
                    description=f"Reference to {api.decode()} found at offset {hex(offset)}. "
                               f"This may indicate encryption/decryption activity.",
                    offset=offset,
                    context={
                        'api_name': api.decode(),
                    }
                ))

                # Limit per API
                if len([f for f in findings if api.decode() in f.title]) >= 5:
                    break

        return findings

    def _search_ransomware_indicators(self) -> list[AnalysisFinding]:
        """Search for ransomware-related strings and patterns."""
        findings = []

        for offset, string in self._parser.get_strings(min_length=10):
            for pattern in self.RANSOMWARE_PATTERNS:
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
        """Find regions with high entropy (potential encrypted data)."""
        findings = []

        if self._parser is None or not self._parser.info.regions:
            return findings

        # Sample regions for high entropy data
        sample_size = 256
        threshold_bytes = 32  # Minimum consecutive high-entropy blocks

        for region in self._parser.info.regions:
            if not region.is_readable or region.size < sample_size:
                continue

            high_entropy_blocks = 0
            first_block_offset = None

            # Sample the region
            for i in range(0, min(region.size, 0x100000), sample_size):
                try:
                    data = self._parser.read_at(region.data_offset + i, sample_size)
                    entropy = self._calculate_entropy(data)

                    if entropy > self.ENTROPY_THRESHOLD:
                        if high_entropy_blocks == 0:
                            first_block_offset = region.data_offset + i
                        high_entropy_blocks += 1
                except Exception:
                    continue

            # Report if significant high-entropy region found
            if high_entropy_blocks >= threshold_bytes:
                findings.append(AnalysisFinding(
                    category="crypto",
                    severity="medium",
                    title="High Entropy Memory Region",
                    description=f"Found {high_entropy_blocks} consecutive high-entropy blocks "
                               f"starting at offset {hex(first_block_offset or 0)}. "
                               f"This may indicate encrypted or compressed data.",
                    offset=first_block_offset or region.data_offset,
                    context={
                        'entropy_blocks': high_entropy_blocks,
                        'region_start': hex(region.start),
                        'estimated_size': high_entropy_blocks * sample_size,
                    }
                ))
        
        return findings
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        import math
        
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
    
    def get_statistics(self) -> dict:
        """Return crypto scanning statistics."""
        return {
            'total_artifacts': len(self._artifacts),
            'api_references': self._api_count,
            'constant_detections': self._constant_detections,
            'ransomware_indicators': self._ransomware_indicators,
            'by_type': dict(
                (k, sum(1 for a in self._artifacts if a.artifact_type == k))
                for k in set(a.artifact_type for a in self._artifacts)
            ),
        }
    
    def get_artifacts(self) -> list[CryptoArtifact]:
        """Get list of crypto artifacts."""
        return self._artifacts.copy()
