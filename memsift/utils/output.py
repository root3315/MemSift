"""
Output Formatting Module

Provides formatted output for analysis results in multiple formats.
"""

from __future__ import annotations
import json
from enum import Enum, auto
from typing import Any, Optional, TextIO
from datetime import datetime

from ..core.analyzer import AnalysisResult, AnalysisFinding


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
    """
    
    # ANSI color codes
    COLORS = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[94m',    # Blue
        'low': '\033[96m',       # Cyan
        'info': '\033[92m',      # Green
        'reset': '\033[0m',
        'bold': '\033[1m',
    }
    
    SEVERITY_ICONS = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🔵',
        'info': '🟢',
    }
    
    def __init__(self, output_format: OutputFormat = OutputFormat.TEXT, use_color: bool = True):
        self.format = output_format
        self.use_color = use_color
    
    def format_result(self, result: AnalysisResult) -> str:
        """Format a complete analysis result."""
        if self.format == OutputFormat.JSON:
            return self._format_json(result)
        elif self.format == OutputFormat.CSV:
            return self._format_csv(result)
        elif self.format == OutputFormat.TABLE:
            return self._format_table(result)
        else:
            return self._format_text(result)
    
    def format_findings(self, findings: list[AnalysisFinding]) -> str:
        """Format a list of findings."""
        if self.format == OutputFormat.JSON:
            return json.dumps([f.to_dict() for f in findings], indent=2)
        elif self.format == OutputFormat.CSV:
            return self._findings_to_csv(findings)
        else:
            return self._format_findings_text(findings)
    
    def _color(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled."""
        if self.use_color and color in self.COLORS:
            return f"{self.COLORS[color]}{text}{self.COLORS['reset']}"
        return text
    
    def _severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        return severity.lower() if severity.lower() in self.COLORS else 'reset'
    
    def _format_text(self, result: AnalysisResult) -> str:
        """Format result as human-readable text."""
        lines = []
        
        # Header
        lines.append(self._color("=" * 60, 'bold'))
        lines.append(self._color("MemSift Memory Analysis Report", 'bold'))
        lines.append(self._color("=" * 60, 'bold'))
        lines.append("")
        
        # Summary
        lines.append(self._color("SUMMARY", 'bold'))
        lines.append("-" * 40)
        lines.append(f"Status: {result.status.name}")
        lines.append(f"Duration: {result.duration:.2f} seconds")
        lines.append(f"File Size: {self._format_size(result.dump_info.size)}")
        lines.append(f"Format: {result.dump_info.format.name}")
        lines.append(f"Architecture: {result.dump_info.architecture}")
        lines.append(f"OS Type: {result.dump_info.os_type}")
        lines.append(f"Memory Regions: {len(result.dump_info.regions)}")
        lines.append("")
        
        # Findings Summary
        lines.append(self._color("FINDINGS SUMMARY", 'bold'))
        lines.append("-" * 40)
        lines.append(f"Total Findings: {result.total_findings}")
        lines.append(f"  {self._color('Critical', 'critical')}: {result.critical_count}")
        lines.append(f"  {self._color('High', 'high')}: {result.high_count}")
        lines.append(f"  {self._color('Medium', 'medium')}: {result.medium_count}")
        lines.append("")
        
        # Detailed Findings
        if result.findings:
            lines.append(self._color("DETAILED FINDINGS", 'bold'))
            lines.append("-" * 40)
            
            # Group by severity
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                severity_findings = [f for f in result.findings if f.severity.lower() == severity]
                if severity_findings:
                    lines.append("")
                    lines.append(self._color(f"[{severity.upper()}]", self._severity_color(severity)))
                    
                    for i, finding in enumerate(severity_findings, 1):
                        icon = self.SEVERITY_ICONS.get(severity, '')
                        lines.append(f"  {icon} #{i}: {finding.title}")
                        lines.append(f"      Category: {finding.category}")
                        lines.append(f"      {finding.description}")
                        if finding.address:
                            lines.append(f"      Address: {hex(finding.address)}")
                        if finding.offset:
                            lines.append(f"      Offset: {hex(finding.offset)}")
                        lines.append("")
        
        # Errors
        if result.errors:
            lines.append(self._color("ERRORS", 'bold'))
            lines.append("-" * 40)
            for error in result.errors:
                lines.append(self._color(f"  ✗ {error}", 'critical'))
            lines.append("")
        
        # Footer
        lines.append(self._color("=" * 60, 'bold'))
        lines.append(f"Report generated: {datetime.now().isoformat()}")
        lines.append(self._color("=" * 60, 'bold'))
        
        return '\n'.join(lines)
    
    def _format_json(self, result: AnalysisResult) -> str:
        """Format result as JSON."""
        data = {
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
        """Format findings as CSV."""
        return self._findings_to_csv(result.findings)
    
    def _findings_to_csv(self, findings: list[AnalysisFinding]) -> str:
        """Convert findings to CSV format."""
        lines = []
        
        # Header
        lines.append("severity,category,title,description,offset,address")
        
        # Data rows
        for finding in findings:
            row = [
                self._escape_csv(finding.severity),
                self._escape_csv(finding.category),
                self._escape_csv(finding.title),
                self._escape_csv(finding.description),
                str(finding.offset) if finding.offset else '',
                hex(finding.address) if finding.address else '',
            ]
            lines.append(','.join(row))
        
        return '\n'.join(lines)
    
    def _escape_csv(self, value: str) -> str:
        """Escape a value for CSV output."""
        if ',' in value or '"' in value or '\n' in value:
            return '"' + value.replace('"', '""') + '"'
        return value
    
    def _format_table(self, result: AnalysisResult) -> str:
        """Format findings as a table."""
        lines = []
        
        # Summary table
        lines.append("┌" + "─" * 58 + "┐")
        lines.append("│" + "MemSift Analysis Summary".center(58) + "│")
        lines.append("├" + "─" * 58 + "┤")
        lines.append(self._table_row("Status", result.status.name))
        lines.append(self._table_row("Duration", f"{result.duration:.2f}s"))
        lines.append(self._table_row("Total Findings", str(result.total_findings)))
        lines.append(self._table_row("Critical", str(result.critical_count)))
        lines.append(self._table_row("High", str(result.high_count)))
        lines.append(self._table_row("Medium", str(result.medium_count)))
        lines.append("└" + "─" * 58 + "┘")
        lines.append("")
        
        # Findings table
        if result.findings:
            lines.append("┌" + "─" * 90 + "┐")
            lines.append("│" + "Findings".center(90) + "│")
            lines.append("├" + "─" * 10 + "┬" + "─" * 12 + "┬" + "─" * 66 + "┤")
            lines.append("│ Severity   │ Category     │ Title" + " " * 57 + "│")
            lines.append("├" + "─" * 90 + "┤")
            
            for finding in result.findings[:50]:  # Limit to 50 rows
                icon = self.SEVERITY_ICONS.get(finding.severity.lower(), '')
                title = f"{icon} {finding.title}"[:66]
                lines.append(self._table_row_multi(
                    finding.severity[:10],
                    finding.category[:12],
                    title
                ))
            
            if len(result.findings) > 50:
                lines.append(self._table_row_multi("...", "", f"... and {len(result.findings) - 50} more"))
            
            lines.append("└" + "─" * 90 + "┘")
        
        return '\n'.join(lines)
    
    def _table_row(self, label: str, value: str) -> str:
        """Create a table row."""
        return f"│ {label:<20} │ {value:<34} │"
    
    def _table_row_multi(self, *cells: str) -> str:
        """Create a multi-column table row."""
        widths = [10, 12, 66]
        row = "│"
        for cell, width in zip(cells, widths):
            row += f" {cell:<{width}} │"
        return row
    
    def _format_findings_text(self, findings: list[AnalysisFinding]) -> str:
        """Format findings as text."""
        lines = []
        
        for i, finding in enumerate(findings, 1):
            icon = self.SEVERITY_ICONS.get(finding.severity.lower(), '')
            lines.append(f"{icon} [{i}] {finding.title}")
            lines.append(f"    Severity: {finding.severity}")
            lines.append(f"    Category: {finding.category}")
            lines.append(f"    {finding.description}")
            if finding.address:
                lines.append(f"    Address: {hex(finding.address)}")
            lines.append("")
        
        return '\n'.join(lines)
    
    def _format_size(self, size: int) -> str:
        """Format a size in bytes to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    def print_result(self, result: AnalysisResult, file: Optional[TextIO] = None) -> None:
        """Print formatted result to file or stdout."""
        output = self.format_result(result)
        if file:
            file.write(output)
        else:
            print(output)
