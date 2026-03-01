"""
Output Formatting Module

Provides formatted output for analysis results in multiple formats.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence
    from io import TextIO

    from ..core.analyzer import AnalysisFinding, AnalysisResult


class OutputFormat(Enum):
    """Supported output formats."""
    TEXT = auto()
    JSON = auto()
    CSV = auto()
    TABLE = auto()


class OutputFormatter:
    """
    Formats analysis results for output.

    Supports multiple output formats including text, JSON, CSV, and table.

    Example:
        >>> formatter = OutputFormatter(OutputFormat.JSON)
        >>> output = formatter.format_result(result)
    """

    # ANSI color codes for terminal output
    COLORS: dict[str, str] = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[94m',    # Blue
        'low': '\033[96m',       # Cyan
        'info': '\033[92m',      # Green
        'reset': '\033[0m',
        'bold': '\033[1m',
    }

    # Severity icons for visual output
    SEVERITY_ICONS: dict[str, str] = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🔵',
        'info': '🟢',
    }

    def __init__(
        self,
        output_format: OutputFormat = OutputFormat.TEXT,
        use_color: bool = True
    ) -> None:
        """Initialize the output formatter.

        Args:
            output_format: Desired output format.
            use_color: Whether to use ANSI colors in text output.
        """
        self.format = output_format
        self.use_color = use_color

    def format_result(self, result: AnalysisResult) -> str:
        """Format a complete analysis result.

        Args:
            result: AnalysisResult to format.

        Returns:
            Formatted string representation.
        """
        formatters: dict[OutputFormat, callable] = {
            OutputFormat.JSON: self._format_json,
            OutputFormat.CSV: self._format_csv,
            OutputFormat.TABLE: self._format_table,
            OutputFormat.TEXT: self._format_text,
        }
        formatter = formatters.get(self.format, self._format_text)
        return formatter(result)

    def format_findings(self, findings: list[AnalysisFinding]) -> str:
        """Format a list of findings.

        Args:
            findings: List of AnalysisFinding objects.

        Returns:
            Formatted string representation.
        """
        if self.format == OutputFormat.JSON:
            return json.dumps([f.to_dict() for f in findings], indent=2)
        elif self.format == OutputFormat.CSV:
            return self._findings_to_csv(findings)
        else:
            return self._format_findings_text(findings)

    def _color(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled.

        Args:
            text: Text to colorize.
            color: Color name from COLORS dict.

        Returns:
            Colorized text or original if colors disabled.
        """
        if self.use_color and color in self.COLORS:
            return f"{self.COLORS[color]}{text}{self.COLORS['reset']}"
        return text

    def _severity_color(self, severity: str) -> str:
        """Get color key for severity level.

        Args:
            severity: Severity level string.

        Returns:
            Color key for the severity.
        """
        return severity.lower() if severity.lower() in self.COLORS else 'reset'

    def _format_text(self, result: AnalysisResult) -> str:
        """Format result as human-readable text.

        Args:
            result: AnalysisResult to format.

        Returns:
            Formatted text string.
        """
        lines: list[str] = []

        # Header
        lines.append(self._color("=" * 60, 'bold'))
        lines.append(self._color("MemSift Memory Analysis Report", 'bold'))
        lines.append(self._color("=" * 60, 'bold'))
        lines.append("")

        # Summary
        lines.extend(self._format_text_summary(result))

        # Findings Summary
        lines.extend(self._format_text_findings_summary(result))

        # Detailed Findings
        if result.findings:
            lines.extend(self._format_text_detailed_findings(result))

        # Errors
        if result.errors:
            lines.extend(self._format_text_errors(result))

        # Footer
        lines.extend(self._format_text_footer())

        return '\n'.join(lines)

    def _format_text_summary(self, result: AnalysisResult) -> list[str]:
        """Format the summary section of text output.

        Args:
            result: AnalysisResult.

        Returns:
            List of formatted lines.
        """
        lines: list[str] = [
            self._color("SUMMARY", 'bold'),
            "-" * 40,
            f"Status: {result.status.name}",
            f"Duration: {result.duration:.2f} seconds",
            f"File Size: {self._format_size(result.dump_info.size)}",
            f"Format: {result.dump_info.format.name}",
            f"Architecture: {result.dump_info.architecture}",
            f"OS Type: {result.dump_info.os_type}",
            f"Memory Regions: {len(result.dump_info.regions)}",
            "",
        ]
        return lines

    def _format_text_findings_summary(self, result: AnalysisResult) -> list[str]:
        """Format the findings summary section.

        Args:
            result: AnalysisResult.

        Returns:
            List of formatted lines.
        """
        lines: list[str] = [
            self._color("FINDINGS SUMMARY", 'bold'),
            "-" * 40,
            f"Total Findings: {result.total_findings}",
            f"  {self._color('Critical', 'critical')}: {result.critical_count}",
            f"  {self._color('High', 'high')}: {result.high_count}",
            f"  {self._color('Medium', 'medium')}: {result.medium_count}",
            "",
        ]
        return lines

    def _format_text_detailed_findings(self, result: AnalysisResult) -> list[str]:
        """Format the detailed findings section.

        Args:
            result: AnalysisResult.

        Returns:
            List of formatted lines.
        """
        lines: list[str] = [
            self._color("DETAILED FINDINGS", 'bold'),
            "-" * 40,
        ]

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            severity_findings = [
                f for f in result.findings if f.severity.lower() == severity
            ]
            if severity_findings:
                lines.append("")
                lines.append(self._color(f"[{severity.upper()}]", self._severity_color(severity)))

                for i, finding in enumerate(severity_findings, 1):
                    lines.extend(self._format_single_finding(finding, i))

        lines.append("")
        return lines

    def _format_single_finding(
        self,
        finding: AnalysisFinding,
        index: int
    ) -> list[str]:
        """Format a single finding for text output.

        Args:
            finding: AnalysisFinding to format.
            index: Finding index number.

        Returns:
            List of formatted lines.
        """
        lines: list[str] = []
        icon = self.SEVERITY_ICONS.get(finding.severity.lower(), '')
        lines.append(f"  {icon} #{index}: {finding.title}")
        lines.append(f"      Category: {finding.category}")
        lines.append(f"      {finding.description}")
        if finding.address is not None:
            lines.append(f"      Address: {hex(finding.address)}")
        if finding.offset is not None:
            lines.append(f"      Offset: {hex(finding.offset)}")
        lines.append("")
        return lines

    def _format_text_errors(self, result: AnalysisResult) -> list[str]:
        """Format the errors section.

        Args:
            result: AnalysisResult.

        Returns:
            List of formatted lines.
        """
        lines: list[str] = [
            self._color("ERRORS", 'bold'),
            "-" * 40,
        ]
        for error in result.errors:
            lines.append(self._color(f"  ✗ {error}", 'critical'))
        lines.append("")
        return lines

    def _format_text_footer(self) -> list[str]:
        """Format the report footer.

        Returns:
            List of formatted lines.
        """
        return [
            self._color("=" * 60, 'bold'),
            f"Report generated: {datetime.now().isoformat()}",
            self._color("=" * 60, 'bold'),
        ]

    def _format_json(self, result: AnalysisResult) -> str:
        """Format result as JSON.

        Args:
            result: AnalysisResult to format.

        Returns:
            JSON string.
        """
        data: dict[str, Any] = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'tool': 'MemSift',
                'version': '1.0.0',
            },
            'summary': {
                'status': result.status.name,
                'duration': result.duration,
                'total_findings': result.total_findings,
                'critical_count': result.critical_count,
                'high_count': result.high_count,
                'medium_count': result.medium_count,
            },
            'dump_info': {
                'format': result.dump_info.format.name,
                'size': result.dump_info.size,
                'architecture': result.dump_info.architecture,
                'os_type': result.dump_info.os_type,
                'regions_count': len(result.dump_info.regions),
            },
            'findings': [f.to_dict() for f in result.findings],
            'statistics': result.statistics,
            'errors': result.errors,
        }
        return json.dumps(data, indent=2, default=str)

    def _format_csv(self, result: AnalysisResult) -> str:
        """Format findings as CSV.

        Args:
            result: AnalysisResult to format.

        Returns:
            CSV string.
        """
        return self._findings_to_csv(result.findings)

    def _findings_to_csv(self, findings: list[AnalysisFinding]) -> str:
        """Convert findings to CSV format.

        Args:
            findings: List of AnalysisFinding objects.

        Returns:
            CSV string.
        """
        lines: list[str] = [
            "severity,category,title,description,offset,address"
        ]

        for finding in findings:
            row = [
                self._escape_csv(finding.severity),
                self._escape_csv(finding.category),
                self._escape_csv(finding.title),
                self._escape_csv(finding.description),
                str(finding.offset) if finding.offset is not None else '',
                hex(finding.address) if finding.address is not None else '',
            ]
            lines.append(','.join(row))

        return '\n'.join(lines)

    def _escape_csv(self, value: str) -> str:
        """Escape a value for CSV output.

        Args:
            value: Value to escape.

        Returns:
            Escaped CSV-safe string.
        """
        if ',' in value or '"' in value or '\n' in value:
            return '"' + value.replace('"', '""') + '"'
        return value

    def _format_table(self, result: AnalysisResult) -> str:
        """Format findings as a table.

        Args:
            result: AnalysisResult to format.

        Returns:
            Table-formatted string.
        """
        lines: list[str] = []

        # Summary table
        lines.extend(self._format_table_summary(result))
        lines.append("")

        # Findings table
        if result.findings:
            lines.extend(self._format_table_findings(result))

        return '\n'.join(lines)

    def _format_table_summary(self, result: AnalysisResult) -> list[str]:
        """Format the summary table.

        Args:
            result: AnalysisResult.

        Returns:
            List of table lines.
        """
        lines: list[str] = [
            "┌" + "─" * 58 + "┐",
            "│" + "MemSift Analysis Summary".center(58) + "│",
            "├" + "─" * 58 + "┤",
            self._table_row("Status", result.status.name),
            self._table_row("Duration", f"{result.duration:.2f}s"),
            self._table_row("Total Findings", str(result.total_findings)),
            self._table_row("Critical", str(result.critical_count)),
            self._table_row("High", str(result.high_count)),
            self._table_row("Medium", str(result.medium_count)),
            "└" + "─" * 58 + "┘",
        ]
        return lines

    def _format_table_findings(self, result: AnalysisResult) -> list[str]:
        """Format the findings table.

        Args:
            result: AnalysisResult.

        Returns:
            List of table lines.
        """
        lines: list[str] = [
            "┌" + "─" * 90 + "┐",
            "│" + "Findings".center(90) + "│",
            "├" + "─" * 10 + "┬" + "─" * 12 + "┬" + "─" * 66 + "┤",
            "│ Severity   │ Category     │ Title" + " " * 57 + "│",
            "├" + "─" * 90 + "┤",
        ]

        for finding in result.findings[:50]:
            icon = self.SEVERITY_ICONS.get(finding.severity.lower(), '')
            title = f"{icon} {finding.title}"[:66]
            lines.append(self._table_row_multi(
                finding.severity[:10],
                finding.category[:12],
                title
            ))

        if len(result.findings) > 50:
            lines.append(self._table_row_multi(
                "...", "", f"... and {len(result.findings) - 50} more"
            ))

        lines.append("└" + "─" * 90 + "┘")
        return lines

    def _table_row(self, label: str, value: str) -> str:
        """Create a single-column table row.

        Args:
            label: Row label.
            value: Row value.

        Returns:
            Formatted table row string.
        """
        return f"│ {label:<20} │ {value:<34} │"

    def _table_row_multi(self, *cells: str) -> str:
        """Create a multi-column table row.

        Args:
            cells: Cell values for each column.

        Returns:
            Formatted table row string.
        """
        widths: list[int] = [10, 12, 66]
        row = "│"
        for cell, width in zip(cells, widths):
            row += f" {cell:<{width}} │"
        return row

    def _format_findings_text(self, findings: list[AnalysisFinding]) -> str:
        """Format findings as text.

        Args:
            findings: List of AnalysisFinding objects.

        Returns:
            Formatted text string.
        """
        lines: list[str] = []

        for i, finding in enumerate(findings, 1):
            icon = self.SEVERITY_ICONS.get(finding.severity.lower(), '')
            lines.append(f"{icon} [{i}] {finding.title}")
            lines.append(f"    Severity: {finding.severity}")
            lines.append(f"    Category: {finding.category}")
            lines.append(f"    {finding.description}")
            if finding.address is not None:
                lines.append(f"    Address: {hex(finding.address)}")
            lines.append("")

        return '\n'.join(lines)

    def _format_size(self, size: int) -> str:
        """Format a size in bytes to human-readable format.

        Args:
            size: Size in bytes.

        Returns:
            Human-readable size string.
        """
        units: list[str] = ['B', 'KB', 'MB', 'GB']
        for unit in units:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"

    def print_result(
        self,
        result: AnalysisResult,
        file: TextIO | None = None
    ) -> None:
        """Print formatted result to file or stdout.

        Args:
            result: AnalysisResult to print.
            file: Optional file object (defaults to stdout).
        """
        output = self.format_result(result)
        if file is not None:
            file.write(output)
        else:
            print(output)
