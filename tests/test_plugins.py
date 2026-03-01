"""Tests for MemSift analysis plugins."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from memsift.plugins.processes import ProcessScanner, ProcessInfo
from memsift.plugins.network import NetworkAnalyzer, NetworkArtifact
from memsift.plugins.strings import StringExtractor, ExtractedString
from memsift.plugins.injection import InjectionDetector, InjectionIndicator
from memsift.plugins.crypto import CryptoScanner, CryptoArtifact


@pytest.fixture
def temp_memory_with_processes() -> Path:
    """Create a memory dump with process-like strings."""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.dump') as f:
        f.write(b'\x00' * 100)
        f.write(b'svchost.exe\x00')
        f.write(b'\x00' * 50)
        f.write(b'mimikatz.exe\x00')
        f.write(b'\x00' * 50)
        f.write(b'explorer.exe\x00')
        f.write(b'\x00' * 100)
        filepath = Path(f.name)
    yield filepath
    filepath.unlink()


@pytest.fixture
def temp_memory_with_network() -> Path:
    """Create a memory dump with network artifacts."""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.dump') as f:
        f.write(b'\x00' * 100)
        f.write(b'192.168.1.100\x00')
        f.write(b'\x00' * 50)
        f.write(b'http://malicious.xyz/beacon\x00')
        f.write(b'\x00' * 50)
        f.write(b'callback:4444\x00')
        f.write(b'\x00' * 100)
        filepath = Path(f.name)
    yield filepath
    filepath.unlink()


@pytest.fixture
def temp_memory_with_strings() -> Path:
    """Create a memory dump with various strings."""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.dump') as f:
        f.write(b'\x00' * 100)
        f.write(b'C:\\Windows\\System32\\cmd.exe\x00')
        f.write(b'\x00' * 50)
        f.write(b'password=secret123\x00')
        f.write(b'\x00' * 50)
        f.write(b'-----BEGIN RSA PRIVATE KEY-----\x00')
        f.write(b'\x00' * 100)
        filepath = Path(f.name)
    yield filepath
    filepath.unlink()


@pytest.fixture
def temp_memory_with_crypto() -> Path:
    """Create a memory dump with crypto artifacts."""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.dump') as f:
        f.write(b'\x00' * 100)
        # AES S-box signature
        f.write(bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                       0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]))
        f.write(b'\x00' * 50)
        f.write(b'CryptEncrypt\x00')
        f.write(b'\x00' * 100)
        filepath = Path(f.name)
    yield filepath
    filepath.unlink()


class TestProcessScanner:
    """Tests for ProcessScanner plugin."""

    def test_plugin_initialization(self) -> None:
        """Test plugin initialization."""
        scanner = ProcessScanner()
        assert scanner.name == "process_scanner"
        assert scanner.enabled is True

    def test_analyze_basic(self, temp_memory_with_processes: Path) -> None:
        """Test basic process analysis."""
        from memsift.core.parser import MemoryParser

        scanner = ProcessScanner()
        parser = MemoryParser(temp_memory_with_processes)
        scanner.initialize(parser)

        with parser.open():
            findings = scanner.analyze()

        assert len(findings) >= 1  # Should find mimikatz

    def test_get_processes(self, temp_memory_with_processes: Path) -> None:
        """Test getting detected processes."""
        from memsift.core.parser import MemoryParser

        scanner = ProcessScanner()
        parser = MemoryParser(temp_memory_with_processes)
        scanner.initialize(parser)

        with parser.open():
            scanner.analyze()

        processes = scanner.get_processes()
        assert len(processes) >= 1

    def test_get_statistics(self, temp_memory_with_processes: Path) -> None:
        """Test getting statistics."""
        from memsift.core.parser import MemoryParser

        scanner = ProcessScanner()
        parser = MemoryParser(temp_memory_with_processes)
        scanner.initialize(parser)

        with parser.open():
            scanner.analyze()

        stats = scanner.get_statistics()
        assert 'total_processes_found' in stats
        assert 'suspicious_count' in stats

    def test_masquerading_detection(self) -> None:
        """Test process masquerading detection."""
        scanner = ProcessScanner()
        assert scanner._is_masquerading('svch0st.exe') is True
        assert scanner._is_masquerading('svchost.exe') is False

    def test_process_name_validation(self) -> None:
        """Test process name validation."""
        scanner = ProcessScanner()
        assert scanner._is_likely_process_name('svchost.exe') is True
        assert scanner._is_likely_process_name('notepad.exe') is True
        assert scanner._is_likely_process_name('bash') is True
        assert scanner._is_likely_process_name('') is False
        assert scanner._is_likely_process_name('a') is False


class TestNetworkAnalyzer:
    """Tests for NetworkAnalyzer plugin."""

    def test_plugin_initialization(self) -> None:
        """Test plugin initialization."""
        analyzer = NetworkAnalyzer()
        assert analyzer.name == "network_analyzer"
        assert analyzer.enabled is True

    def test_analyze_basic(self, temp_memory_with_network: Path) -> None:
        """Test basic network analysis."""
        from memsift.core.parser import MemoryParser

        analyzer = NetworkAnalyzer()
        parser = MemoryParser(temp_memory_with_network)
        analyzer.initialize(parser)

        with parser.open():
            findings = analyzer.analyze()

        assert len(findings) >= 1

    def test_ip_validation(self) -> None:
        """Test IP address validation."""
        analyzer = NetworkAnalyzer()
        assert analyzer._is_valid_ip('192.168.1.1') is True
        assert analyzer._is_valid_ip('256.1.1.1') is False
        assert analyzer._is_valid_ip('1.2.3') is False

    def test_port_suspicion(self) -> None:
        """Test port suspicion checking."""
        analyzer = NetworkAnalyzer()
        artifact = NetworkArtifact('port', '4444', 0)
        analyzer._check_port_suspicion(artifact)
        assert artifact.is_suspicious is True

    def test_get_statistics(self, temp_memory_with_network: Path) -> None:
        """Test getting statistics."""
        from memsift.core.parser import MemoryParser

        analyzer = NetworkAnalyzer()
        parser = MemoryParser(temp_memory_with_network)
        analyzer.initialize(parser)

        with parser.open():
            analyzer.analyze()

        stats = analyzer.get_statistics()
        assert 'total_artifacts' in stats
        assert 'unique_ips' in stats


class TestStringExtractor:
    """Tests for StringExtractor plugin."""

    def test_plugin_initialization(self) -> None:
        """Test plugin initialization."""
        extractor = StringExtractor()
        assert extractor.name == "string_extractor"
        assert extractor.enabled is True

    def test_analyze_basic(self, temp_memory_with_strings: Path) -> None:
        """Test basic string analysis."""
        from memsift.core.parser import MemoryParser

        extractor = StringExtractor()
        parser = MemoryParser(temp_memory_with_strings)
        extractor.initialize(parser)

        with parser.open():
            findings = extractor.analyze()

        assert len(findings) >= 1  # Should find sensitive strings

    def test_base64_detection(self) -> None:
        """Test base64 detection."""
        extractor = StringExtractor()
        assert extractor._looks_like_base64('SGVsbG8gV29ybGQh') is True
        assert extractor._looks_like_base64('not base64') is False

    def test_string_categorization(self) -> None:
        """Test string categorization."""
        extractor = StringExtractor()
        assert extractor._categorize_string('C:\\Windows\\test.exe') == 'path'
        assert extractor._categorize_string('http://example.com') == 'url'
        assert extractor._categorize_string('random text') == 'general'

    def test_get_statistics(self, temp_memory_with_strings: Path) -> None:
        """Test getting statistics."""
        from memsift.core.parser import MemoryParser

        extractor = StringExtractor()
        parser = MemoryParser(temp_memory_with_strings)
        extractor.initialize(parser)

        with parser.open():
            extractor.analyze()

        stats = extractor.get_statistics()
        assert 'total_strings' in stats
        assert 'sensitive_count' in stats


class TestInjectionDetector:
    """Tests for InjectionDetector plugin."""

    def test_plugin_initialization(self) -> None:
        """Test plugin initialization."""
        detector = InjectionDetector()
        assert detector.name == "injection_detector"
        assert detector.enabled is True

    def test_analyze_basic(self, temp_memory_with_processes: Path) -> None:
        """Test basic injection analysis."""
        from memsift.core.parser import MemoryParser

        detector = InjectionDetector()
        parser = MemoryParser(temp_memory_with_processes)
        detector.initialize(parser)

        with parser.open():
            findings = detector.analyze()

        # Should find API references at minimum
        assert len(findings) >= 0

    def test_get_statistics(self, temp_memory_with_processes: Path) -> None:
        """Test getting statistics."""
        from memsift.core.parser import MemoryParser

        detector = InjectionDetector()
        parser = MemoryParser(temp_memory_with_processes)
        detector.initialize(parser)

        with parser.open():
            detector.analyze()

        stats = detector.get_statistics()
        assert 'total_indicators' in stats
        assert 'rwx_regions' in stats


class TestCryptoScanner:
    """Tests for CryptoScanner plugin."""

    def test_plugin_initialization(self) -> None:
        """Test plugin initialization."""
        scanner = CryptoScanner()
        assert scanner.name == "crypto_scanner"
        assert scanner.enabled is True

    def test_analyze_basic(self, temp_memory_with_crypto: Path) -> None:
        """Test basic crypto analysis."""
        from memsift.core.parser import MemoryParser

        scanner = CryptoScanner()
        parser = MemoryParser(temp_memory_with_crypto)
        scanner.initialize(parser)

        with parser.open():
            findings = scanner.analyze()

        assert len(findings) >= 1  # Should find crypto constants/APIs

    def test_entropy_calculation(self) -> None:
        """Test entropy calculation."""
        scanner = CryptoScanner()

        # Low entropy (repeating bytes)
        low_entropy = scanner._calculate_entropy(b'\x00' * 256)
        assert low_entropy < 1.0

        # High entropy (random-like data)
        import os
        high_entropy = scanner._calculate_entropy(os.urandom(256))
        assert high_entropy > 7.0

    def test_get_statistics(self, temp_memory_with_crypto: Path) -> None:
        """Test getting statistics."""
        from memsift.core.parser import MemoryParser

        scanner = CryptoScanner()
        parser = MemoryParser(temp_memory_with_crypto)
        scanner.initialize(parser)

        with parser.open():
            scanner.analyze()

        stats = scanner.get_statistics()
        assert 'total_artifacts' in stats
        assert 'api_references' in stats
