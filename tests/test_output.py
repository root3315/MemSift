"""Tests for the MemSift output formatter module."""

from __future__ import annotations

import json
from io import StringIO

import pytest

from memsift.core.analyzer import (
    AnalysisFinding,
    AnalysisResult,
    AnalysisStatus,
)
from memsift.core.parser import MemoryFormat, MemoryDumpInfo, MemoryRegion
from memsift.utils.output import OutputFormat, OutputFormatter


@pytest.fixture
def sample_dump_info() -> MemoryDumpInfo:
    """Create sample MemoryDumpInfo for testing."""
    return MemoryDumpInfo(
        format=MemoryFormat.RAW,
        size=1048576,  # 1 MB
        architecture='x64',
        os_type='linux',
        regions=[
            MemoryRegion(start=0x400000, end=0x500000, permissions='r-x'),
            MemoryRegion(start=0x600000, end=0x700000, permissions='rw-'),
        ]
    )


@pytest.fixture
def sample_findings() -> list[AnalysisFinding]:
    """Create sample findings for testing."""
    return [
        AnalysisFinding(
            category="process",
            severity="critical",
            title="Malicious Process Detected",
            description="Found mimikatz.exe running",
            offset=0x1000,
            address=0x400000,
            context={'pid': 1234}
        ),
        AnalysisFinding(
            category="network",
            severity="high",
            title="Suspicious Network Connection",
            description="Connection to known C2 server",
            offset=0x2000,
            context={'ip': '192.168.1.100'}
        ),
        AnalysisFinding(
            category="injection",
            severity="medium",
            title="RWX Memory Region",
            description="Found executable writable memory",
            offset=0x3000
        ),
    ]


@pytest.fixture
def sample_result(
    sample_dump_info: MemoryDumpInfo,
    sample_findings: list[AnalysisFinding]
) -> AnalysisResult:
    """Create sample AnalysisResult for testing."""
    return AnalysisResult(
        dump_info=sample_dump_info,
        findings=sample_findings,
        duration=1.234,
        status=AnalysisStatus.COMPLETED,
        statistics={'test': 'value'},
    )


class TestOutputFormat:
    """Tests for OutputFormat enum."""

    def test_output_format_values(self) -> None:
        """Test output format enum values."""
        assert OutputFormat.TEXT.value == 1
        assert OutputFormat.JSON.value == 2
        assert OutputFormat.CSV.value == 3
        assert OutputFormat.TABLE.value == 4


class TestOutputFormatter:
    """Tests for OutputFormatter class."""

    def test_formatter_initialization(self) -> None:
        """Test formatter initialization."""
        formatter = OutputFormatter(OutputFormat.TEXT, use_color=True)
        assert formatter.format == OutputFormat.TEXT
        assert formatter.use_color is True

    def test_formatter_default_color(self) -> None:
        """Test default color setting."""
        formatter = OutputFormatter(OutputFormat.TEXT)
        assert formatter.use_color is True

    def test_format_result_text(self, sample_result: AnalysisResult) -> None:
        """Test text format output."""
        formatter = OutputFormatter(OutputFormat.TEXT, use_color=False)
        output = formatter.format_result(sample_result)

        assert "MemSift Memory Analysis Report" in output
        assert "COMPLETED" in output
        assert "Total Findings: 3" in output
        assert "Critical: 1" in output

    def test_format_result_json(self, sample_result: AnalysisResult) -> None:
        """Test JSON format output."""
        formatter = OutputFormatter(OutputFormat.JSON)
        output = formatter.format_result(sample_result)

        data = json.loads(output)
        assert data['summary']['status'] == 'COMPLETED'
        assert data['summary']['total_findings'] == 3
        assert data['summary']['critical_count'] == 1
        assert len(data['findings']) == 3

    def test_format_result_csv(self, sample_result: AnalysisResult) -> None:
        """Test CSV format output."""
        formatter = OutputFormatter(OutputFormat.CSV)
        output = formatter.format_result(sample_result)

        lines = output.strip().split('\n')
        assert lines[0] == "severity,category,title,description,offset,address"
        assert len(lines) == 4  # Header + 3 findings

    def test_format_result_table(self, sample_result: AnalysisResult) -> None:
        """Test table format output."""
        formatter = OutputFormatter(OutputFormat.TABLE, use_color=False)
        output = formatter.format_result(sample_result)

        assert "MemSift Analysis Summary" in output
        assert "COMPLETED" in output
        assert "Findings" in output

    def test_format_findings_json(self, sample_findings: list[AnalysisFinding]) -> None:
        """Test formatting findings as JSON."""
        formatter = OutputFormatter(OutputFormat.JSON)
        output = formatter.format_findings(sample_findings)

        data = json.loads(output)
        assert len(data) == 3
        assert data[0]['severity'] == 'critical'

    def test_format_findings_csv(self, sample_findings: list[AnalysisFinding]) -> None:
        """Test formatting findings as CSV."""
        formatter = OutputFormatter(OutputFormat.CSV)
        output = formatter.format_findings(sample_findings)

        lines = output.strip().split('\n')
        assert len(lines) == 4  # Header + 3 findings

    def test_format_findings_text(self, sample_findings: list[AnalysisFinding]) -> None:
        """Test formatting findings as text."""
        formatter = OutputFormatter(OutputFormat.TEXT, use_color=False)
        output = formatter.format_findings(sample_findings)

        assert "Malicious Process Detected" in output
        assert "Suspicious Network Connection" in output

    def test_color_enabled(self) -> None:
        """Test color application when enabled."""
        formatter = OutputFormatter(OutputFormat.TEXT, use_color=True)
        colored = formatter._color("test", 'critical')
        assert '\033[91m' in colored  # Red color code
        assert '\033[0m' in colored  # Reset code

    def test_color_disabled(self) -> None:
        """Test color application when disabled."""
        formatter = OutputFormatter(OutputFormat.TEXT, use_color=False)
        colored = formatter._color("test", 'critical')
        assert colored == "test"

    def test_severity_color(self) -> None:
        """Test severity color lookup."""
        formatter = OutputFormatter(OutputFormat.TEXT)
        assert formatter._severity_color('critical') == 'critical'
        assert formatter._severity_color('HIGH') == 'high'
        assert formatter._severity_color('unknown') == 'reset'

    def test_escape_csv_simple(self) -> None:
        """Test CSV escaping for simple values."""
        formatter = OutputFormatter(OutputFormat.TEXT)
        assert formatter._escape_csv("simple") == "simple"

    def test_escape_csv_with_comma(self) -> None:
        """Test CSV escaping for values with commas."""
        formatter = OutputFormatter(OutputFormat.TEXT)
        assert formatter._escape_csv("hello,world") == '"hello,world"'

    def test_escape_csv_with_quotes(self) -> None:
        """Test CSV escaping for values with quotes."""
        formatter = OutputFormatter(OutputFormat.TEXT)
        assert formatter._escape_csv('hello"world') == '"hello""world"'

    def test_escape_csv_with_newline(self) -> None:
        """Test CSV escaping for values with newlines."""
        formatter = OutputFormatter(OutputFormat.TEXT)
        assert formatter._escape_csv("hello\nworld") == '"hello\nworld"'

    def test_format_size_bytes(self) -> None:
        """Test size formatting for bytes."""
        formatter = OutputFormatter(OutputFormat.TEXT)
        assert formatter._format_size(100) == "100.00 B"

    def test_format_size_kb(self) -> None:
        """Test size formatting for KB."""
        formatter = OutputFormatter(OutputFormat.TEXT)
        assert formatter._format_size(1024) == "1.00 KB"

    def test_format_size_mb(self) -> None:
        """Test size formatting for MB."""
        formatter = OutputFormatter(OutputFormat.TEXT)
        assert formatter._format_size(1048576) == "1.00 MB"

    def test_format_size_gb(self) -> None:
        """Test size formatting for GB."""
        formatter = OutputFormatter(OutputFormat.TEXT)
        assert formatter._format_size(1073741824) == "1.00 GB"

    def test_format_size_tb(self) -> None:
        """Test size formatting for TB."""
        formatter = OutputFormatter(OutputFormat.TEXT)
        assert formatter._format_size(1099511627776) == "1.00 TB"

    def test_print_result_stdout(self, sample_result: AnalysisResult) -> None:
        """Test printing result to stdout."""
        formatter = OutputFormatter(OutputFormat.TEXT, use_color=False)
        # Just verify it doesn't raise
        formatter.print_result(sample_result)

    def test_print_result_to_file(self, sample_result: AnalysisResult) -> None:
        """Test printing result to file."""
        formatter = OutputFormatter(OutputFormat.TEXT, use_color=False)
        output = StringIO()
        formatter.print_result(sample_result, file=output)
        assert "MemSift Memory Analysis Report" in output.getvalue()

    def test_text_summary_section(self, sample_result: AnalysisResult) -> None:
        """Test text summary section formatting."""
        formatter = OutputFormatter(OutputFormat.TEXT, use_color=False)
        output = formatter.format_result(sample_result)

        assert "File Size: 1.00 MB" in output
        assert "Format: RAW" in output
        assert "Architecture: x64" in output
        assert "Memory Regions: 2" in output

    def test_text_findings_by_severity(self, sample_result: AnalysisResult) -> None:
        """Test findings grouped by severity."""
        formatter = OutputFormatter(OutputFormat.TEXT, use_color=False)
        output = formatter.format_result(sample_result)

        critical_idx = output.find("[CRITICAL]")
        high_idx = output.find("[HIGH]")
        medium_idx = output.find("[MEDIUM]")

        assert critical_idx != -1
        assert high_idx != -1
        assert medium_idx != -1
        assert critical_idx < high_idx < medium_idx

    def test_json_metadata(self, sample_result: AnalysisResult) -> None:
        """Test JSON metadata section."""
        formatter = OutputFormatter(OutputFormat.JSON)
        output = formatter.format_result(sample_result)
        data = json.loads(output)

        assert 'metadata' in data
        assert data['metadata']['tool'] == 'MemSift'
        assert data['metadata']['version'] == '1.0.0'
        assert 'generated' in data['metadata']

    def test_json_dump_info(self, sample_result: AnalysisResult) -> None:
        """Test JSON dump info section."""
        formatter = OutputFormatter(OutputFormat.JSON)
        output = formatter.format_result(sample_result)
        data = json.loads(output)

        assert data['dump_info']['format'] == 'RAW'
        assert data['dump_info']['size'] == 1048576
        assert data['dump_info']['architecture'] == 'x64'
        assert data['dump_info']['regions_count'] == 2

    def test_table_row_formatting(self) -> None:
        """Test table row formatting."""
        formatter = OutputFormatter(OutputFormat.TABLE)
        row = formatter._table_row("Label", "Value")
        assert "│" in row
        assert "Label" in row
        assert "Value" in row

    def test_table_multi_row_formatting(self) -> None:
        """Test multi-column table row formatting."""
        formatter = OutputFormatter(OutputFormat.TABLE)
        row = formatter._table_row_multi("Sev", "Cat", "Title")
        assert "│" in row
        assert "Sev" in row
        assert "Cat" in row
        assert "Title" in row

    def test_empty_findings(self, sample_dump_info: MemoryDumpInfo) -> None:
        """Test formatting with no findings."""
        result = AnalysisResult(dump_info=sample_dump_info)

        formatter = OutputFormatter(OutputFormat.TEXT, use_color=False)
        output = formatter.format_result(result)
        assert "Total Findings: 0" in output

        formatter = OutputFormatter(OutputFormat.JSON)
        output = formatter.format_result(result)
        data = json.loads(output)
        assert data['findings'] == []

    def test_result_with_errors(self, sample_dump_info: MemoryDumpInfo) -> None:
        """Test formatting with errors."""
        result = AnalysisResult(
            dump_info=sample_dump_info,
            errors=["Error 1", "Error 2"]
        )

        formatter = OutputFormatter(OutputFormat.TEXT, use_color=False)
        output = formatter.format_result(result)
        assert "ERRORS" in output
        assert "Error 1" in output
        assert "Error 2" in output
