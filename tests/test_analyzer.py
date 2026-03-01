"""Tests for the MemSift analyzer module."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from memsift.core.analyzer import (
    AnalysisFinding,
    AnalysisResult,
    AnalysisStatus,
    AnalysisPlugin,
    MemoryAnalyzer,
)
from memsift.core.parser import MemoryFormat, MemoryDumpInfo, MemoryRegion


class TestAnalysisFinding:
    """Tests for AnalysisFinding dataclass."""

    def test_finding_creation(self) -> None:
        """Test finding creation with required fields."""
        finding = AnalysisFinding(
            category="test",
            severity="high",
            title="Test Finding",
            description="Test description"
        )
        assert finding.category == "test"
        assert finding.severity == "high"
        assert finding.title == "Test Finding"
        assert finding.description == "Test description"
        assert finding.offset is None
        assert finding.address is None
        assert finding.evidence == b''
        assert finding.context == {}

    def test_finding_with_offset(self) -> None:
        """Test finding with offset."""
        finding = AnalysisFinding(
            category="test",
            severity="medium",
            title="Test",
            description="Test",
            offset=0x1000
        )
        assert finding.offset == 0x1000

    def test_finding_with_address(self) -> None:
        """Test finding with address."""
        finding = AnalysisFinding(
            category="test",
            severity="low",
            title="Test",
            description="Test",
            address=0x400000
        )
        assert finding.address == 0x400000

    def test_finding_to_dict(self) -> None:
        """Test conversion to dictionary."""
        finding = AnalysisFinding(
            category="network",
            severity="high",
            title="Suspicious IP",
            description="Found suspicious IP",
            offset=0x100,
            address=0x400000,
            evidence=b'\x7f\x00\x00\x01',
            context={'ip': '127.0.0.1'}
        )
        result = finding.to_dict()
        assert result['category'] == "network"
        assert result['severity'] == "high"
        assert result['offset'] == 0x100
        assert result['address'] == '0x400000'
        assert result['evidence'] == '7f000001'
        assert result['context'] == {'ip': '127.0.0.1'}

    def test_finding_to_dict_null_values(self) -> None:
        """Test to_dict with null values."""
        finding = AnalysisFinding(
            category="test",
            severity="info",
            title="Test",
            description="Test"
        )
        result = finding.to_dict()
        assert result['offset'] is None
        assert result['address'] is None
        assert result['evidence'] is None


class TestAnalysisResult:
    """Tests for AnalysisResult dataclass."""

    @pytest.fixture
    def sample_dump_info(self) -> MemoryDumpInfo:
        """Create sample MemoryDumpInfo for testing."""
        return MemoryDumpInfo(
            format=MemoryFormat.RAW,
            size=1024,
            architecture='x64',
            os_type='linux'
        )

    def test_result_creation(self, sample_dump_info: MemoryDumpInfo) -> None:
        """Test result creation."""
        result = AnalysisResult(dump_info=sample_dump_info)
        assert result.dump_info is sample_dump_info
        assert result.findings == []
        assert result.statistics == {}
        assert result.duration == 0.0
        assert result.status == AnalysisStatus.PENDING
        assert result.errors == []

    def test_result_with_findings(self, sample_dump_info: MemoryDumpInfo) -> None:
        """Test result with findings."""
        findings = [
            AnalysisFinding("cat1", "critical", "Title1", "Desc1"),
            AnalysisFinding("cat2", "high", "Title2", "Desc2"),
            AnalysisFinding("cat3", "medium", "Title3", "Desc3"),
            AnalysisFinding("cat4", "low", "Title4", "Desc4"),
        ]
        result = AnalysisResult(dump_info=sample_dump_info, findings=findings)
        assert result.total_findings == 4
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1

    def test_result_summary(self, sample_dump_info: MemoryDumpInfo) -> None:
        """Test summary generation."""
        result = AnalysisResult(
            dump_info=sample_dump_info,
            duration=1.5,
            status=AnalysisStatus.COMPLETED
        )
        summary = result.summary()
        assert "COMPLETED" in summary
        assert "1.50" in summary
        assert "Total Findings: 0" in summary

    def test_result_summary_with_errors(self, sample_dump_info: MemoryDumpInfo) -> None:
        """Test summary with errors."""
        result = AnalysisResult(
            dump_info=sample_dump_info,
            errors=["Error 1", "Error 2"]
        )
        summary = result.summary()
        assert "Errors: 2" in summary


class TestAnalysisPlugin:
    """Tests for AnalysisPlugin base class."""

    def test_plugin_defaults(self) -> None:
        """Test plugin default attributes."""
        plugin = AnalysisPlugin()
        assert plugin.name == "base_plugin"
        assert plugin.description == "Base analysis plugin"
        assert plugin.version == "1.0.0"
        assert plugin.enabled is True
        assert plugin._parser is None

    def test_plugin_initialize(self) -> None:
        """Test plugin initialization."""
        plugin = AnalysisPlugin()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test')
            filepath = Path(f.name)

        try:
            from memsift.core.parser import MemoryParser
            parser = MemoryParser(filepath)
            plugin.initialize(parser)
            assert plugin._parser is parser
        finally:
            Path(filepath).unlink()

    def test_plugin_analyze_not_implemented(self) -> None:
        """Test that analyze raises NotImplementedError."""
        plugin = AnalysisPlugin()
        with pytest.raises(NotImplementedError):
            plugin.analyze()

    def test_plugin_get_statistics(self) -> None:
        """Test default statistics."""
        plugin = AnalysisPlugin()
        assert plugin.get_statistics() == {}


class TestMemoryAnalyzer:
    """Tests for MemoryAnalyzer class."""

    @pytest.fixture
    def temp_memory_file(self) -> Path:
        """Create a temporary memory dump file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.dump') as f:
            # Write test data
            f.write(b'\x00' * 100)
            f.write(b'mimikatz\x00')  # Suspicious string
            f.write(b'\x00' * 100)
            filepath = Path(f.name)
        yield filepath
        filepath.unlink()

    def test_analyzer_initialization(self, temp_memory_file: Path) -> None:
        """Test analyzer initialization."""
        analyzer = MemoryAnalyzer(temp_memory_file)
        assert analyzer.filepath == temp_memory_file
        assert analyzer.plugins == []
        assert analyzer.plugin_names == []

    def test_analyzer_register_plugin(self, temp_memory_file: Path) -> None:
        """Test plugin registration."""
        analyzer = MemoryAnalyzer(temp_memory_file)
        plugin = AnalysisPlugin()
        plugin.name = "test_plugin"
        analyzer.register_plugin(plugin)

        assert len(analyzer.plugins) == 1
        assert "test_plugin" in analyzer.plugin_names

    def test_analyzer_unregister_plugin(self, temp_memory_file: Path) -> None:
        """Test plugin unregistration."""
        analyzer = MemoryAnalyzer(temp_memory_file)
        plugin = AnalysisPlugin()
        plugin.name = "test_plugin"
        analyzer.register_plugin(plugin)

        result = analyzer.unregister_plugin("test_plugin")
        assert result is True
        assert len(analyzer.plugins) == 0

        result = analyzer.unregister_plugin("nonexistent")
        assert result is False

    def test_analyzer_enable_disable_plugin(self, temp_memory_file: Path) -> None:
        """Test enabling and disabling plugins."""
        analyzer = MemoryAnalyzer(temp_memory_file)
        plugin = AnalysisPlugin()
        plugin.name = "test_plugin"
        analyzer.register_plugin(plugin)

        assert analyzer.disable_plugin("test_plugin") is True
        assert analyzer._plugin_registry["test_plugin"].enabled is False

        assert analyzer.enable_plugin("test_plugin") is True
        assert analyzer._plugin_registry["test_plugin"].enabled is True

    def test_analyzer_enable_disable_nonexistent(self, temp_memory_file: Path) -> None:
        """Test enabling/disabling non-existent plugin."""
        analyzer = MemoryAnalyzer(temp_memory_file)
        assert analyzer.enable_plugin("nonexistent") is False
        assert analyzer.disable_plugin("nonexistent") is False

    def test_analyzer_analyze_basic(self, temp_memory_file: Path) -> None:
        """Test basic analysis."""
        analyzer = MemoryAnalyzer(temp_memory_file)
        result = analyzer.analyze()

        assert result.status == AnalysisStatus.COMPLETED
        assert result.duration >= 0
        assert 'general' in result.statistics

    def test_analyzer_analyze_with_plugins(self, temp_memory_file: Path) -> None:
        """Test analysis with specific plugins."""
        analyzer = MemoryAnalyzer(temp_memory_file)

        class TestPlugin(AnalysisPlugin):
            name = "test_plugin"

            def analyze(self) -> list[AnalysisFinding]:
                return [
                    AnalysisFinding(
                        category="test",
                        severity="high",
                        title="Test Finding",
                        description="Test"
                    )
                ]

        analyzer.register_plugin(TestPlugin())
        result = analyzer.analyze(["test_plugin"])

        assert result.status == AnalysisStatus.COMPLETED
        assert len(result.findings) == 1
        assert result.findings[0].severity == "high"

    def test_analyzer_analyze_plugin_error(self, temp_memory_file: Path) -> None:
        """Test analysis handles plugin errors."""
        analyzer = MemoryAnalyzer(temp_memory_file)

        class FailingPlugin(AnalysisPlugin):
            name = "failing_plugin"

            def analyze(self) -> list[AnalysisFinding]:
                raise RuntimeError("Test error")

        analyzer.register_plugin(FailingPlugin())
        result = analyzer.analyze(["failing_plugin"])

        assert result.status == AnalysisStatus.FAILED
        assert len(result.errors) == 1
        assert "failing_plugin" in result.errors[0]

    def test_analyzer_analyze_partial(self, temp_memory_file: Path) -> None:
        """Test partial analysis status."""
        analyzer = MemoryAnalyzer(temp_memory_file)

        class WorkingPlugin(AnalysisPlugin):
            name = "working_plugin"

            def analyze(self) -> list[AnalysisFinding]:
                return [AnalysisFinding("test", "low", "Test", "Test")]

        class FailingPlugin(AnalysisPlugin):
            name = "failing_plugin"

            def analyze(self) -> list[AnalysisFinding]:
                raise RuntimeError("Test error")

        analyzer.register_plugin(WorkingPlugin())
        analyzer.register_plugin(FailingPlugin())
        result = analyzer.analyze()

        assert result.status == AnalysisStatus.PARTIAL
        assert len(result.findings) == 1
        assert len(result.errors) == 1

    def test_analyzer_get_result(self, temp_memory_file: Path) -> None:
        """Test getting analysis result."""
        analyzer = MemoryAnalyzer(temp_memory_file)
        assert analyzer.get_result() is None

        analyzer.analyze()
        result = analyzer.get_result()
        assert result is not None
        assert result.status == AnalysisStatus.COMPLETED

    def test_analyzer_search(self, temp_memory_file: Path) -> None:
        """Test pattern search."""
        analyzer = MemoryAnalyzer(temp_memory_file)
        matches = analyzer.search(b'mimikatz')
        assert len(matches) == 1

    def test_analyzer_extract_at(self, temp_memory_file: Path) -> None:
        """Test byte extraction."""
        analyzer = MemoryAnalyzer(temp_memory_file)
        data = analyzer.extract_at(100, 8)
        assert data == b'mimikatz'

    def test_analyzer_get_strings(self, temp_memory_file: Path) -> None:
        """Test string extraction."""
        analyzer = MemoryAnalyzer(temp_memory_file)
        strings = analyzer.get_strings(min_length=5)
        assert len(strings) >= 1
        assert any('mimikatz' in s[1] for s in strings)
