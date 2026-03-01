"""
Command-Line Interface for MemSift

Provides a comprehensive CLI for memory forensics analysis.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback as traceback_module
from pathlib import Path
from typing import TYPE_CHECKING

from . import __version__
from .core.analyzer import MemoryAnalyzer, AnalysisStatus
from .plugins import (
    ProcessScanner,
    NetworkAnalyzer,
    StringExtractor,
    InjectionDetector,
    CryptoScanner,
)
from .utils.output import OutputFormatter, OutputFormat

if TYPE_CHECKING:
    from collections.abc import Sequence


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog='memsift',
        description='MemSift - Memory Forensics and RAM Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze memory.dump                    # Full analysis
  %(prog)s analyze memory.dump -p processes       # Only process scan
  %(prog)s analyze memory.dump -f json -o out.json  # JSON output
  %(prog)s strings memory.dump -m 8               # Extract strings (min length 8)
  %(prog)s info memory.dump                       # Show memory dump info
        """
    )

    parser.add_argument(
        '-V', '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    _create_analyze_parser(subparsers)
    _create_info_parser(subparsers)
    _create_strings_parser(subparsers)
    _create_search_parser(subparsers)

    return parser


def _create_analyze_parser(subparsers: argparse._SubParsersAction) -> None:
    """Create the analyze subcommand parser.

    Args:
        subparsers: Subparsers action to add to.
    """
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Perform full memory analysis',
        description='Analyze a memory dump for security artifacts'
    )
    analyze_parser.add_argument(
        'memory_dump',
        type=Path,
        help='Path to memory dump file'
    )
    analyze_parser.add_argument(
        '-p', '--plugins',
        nargs='+',
        choices=['processes', 'network', 'strings', 'injection', 'crypto', 'all'],
        default=['all'],
        help='Plugins to run (default: all)'
    )
    analyze_parser.add_argument(
        '-f', '--format',
        choices=['text', 'json', 'csv', 'table'],
        default='text',
        help='Output format (default: text)'
    )
    analyze_parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Output file (default: stdout)'
    )
    analyze_parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Only show findings (no summary)'
    )


def _create_info_parser(subparsers: argparse._SubParsersAction) -> None:
    """Create the info subcommand parser.

    Args:
        subparsers: Subparsers action to add to.
    """
    info_parser = subparsers.add_parser(
        'info',
        help='Show memory dump information',
        description='Display information about a memory dump'
    )
    info_parser.add_argument(
        'memory_dump',
        type=Path,
        help='Path to memory dump file'
    )
    info_parser.add_argument(
        '-f', '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )


def _create_strings_parser(subparsers: argparse._SubParsersAction) -> None:
    """Create the strings subcommand parser.

    Args:
        subparsers: Subparsers action to add to.
    """
    strings_parser = subparsers.add_parser(
        'strings',
        help='Extract strings from memory',
        description='Extract printable strings from a memory dump'
    )
    strings_parser.add_argument(
        'memory_dump',
        type=Path,
        help='Path to memory dump file'
    )
    strings_parser.add_argument(
        '-m', '--min-length',
        type=int,
        default=4,
        help='Minimum string length (default: 4)'
    )
    strings_parser.add_argument(
        '-n', '--limit',
        type=int,
        default=0,
        help='Maximum number of strings to show (0 = unlimited)'
    )
    strings_parser.add_argument(
        '--with-offsets',
        action='store_true',
        help='Show string offsets'
    )


def _create_search_parser(subparsers: argparse._SubParsersAction) -> None:
    """Create the search subcommand parser.

    Args:
        subparsers: Subparsers action to add to.
    """
    search_parser = subparsers.add_parser(
        'search',
        help='Search for patterns in memory',
        description='Search for byte patterns or strings in memory'
    )
    search_parser.add_argument(
        'memory_dump',
        type=Path,
        help='Path to memory dump file'
    )
    search_parser.add_argument(
        'pattern',
        help='Pattern to search for (hex or string)'
    )
    search_parser.add_argument(
        '-x', '--hex',
        action='store_true',
        help='Treat pattern as hex bytes'
    )
    search_parser.add_argument(
        '-c', '--count',
        action='store_true',
        help='Only show match count'
    )


def cmd_analyze(args: argparse.Namespace) -> int:
    """Execute the analyze command.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0=success, 1=high findings, 2=critical findings).
    """
    if not _validate_file_exists(args.memory_dump):
        return 1

    # Create analyzer and register plugins
    analyzer = MemoryAnalyzer(args.memory_dump)
    _register_all_plugins(analyzer)

    # Determine plugins to run
    plugin_names = None if 'all' in args.plugins else args.plugins

    # Run analysis
    try:
        result = analyzer.analyze(plugin_names)
    except Exception as exc:
        _handle_analysis_error(exc, args.verbose)
        return 1

    # Format and output results
    return _output_analysis_result(result, args)


def _validate_file_exists(filepath: Path) -> bool:
    """Validate that a file exists.

    Args:
        filepath: Path to validate.

    Returns:
        True if file exists, False otherwise.
    """
    if not filepath.exists():
        print(f"Error: Memory dump not found: {filepath}", file=sys.stderr)
        return False
    return True


def _register_all_plugins(analyzer: MemoryAnalyzer) -> None:
    """Register all available plugins with the analyzer.

    Args:
        analyzer: MemoryAnalyzer instance.
    """
    analyzer.register_plugin(ProcessScanner())
    analyzer.register_plugin(NetworkAnalyzer())
    analyzer.register_plugin(StringExtractor())
    analyzer.register_plugin(InjectionDetector())
    analyzer.register_plugin(CryptoScanner())


def _handle_analysis_error(error: Exception, verbose: bool) -> None:
    """Handle analysis errors.

    Args:
        error: Exception that occurred.
        verbose: Whether to print verbose error details.
    """
    print(f"Error during analysis: {error}", file=sys.stderr)
    if verbose:
        traceback_module.print_exc()


def _output_analysis_result(result: AnalysisStatus, args: argparse.Namespace) -> int:
    """Output analysis results in the specified format.

    Args:
        result: Analysis result to output.
        args: Command-line arguments.

    Returns:
        Exit code based on findings severity.
    """
    use_color = not args.no_color and sys.stdout.isatty()
    output_format = OutputFormat[args.format.upper()]
    formatter = OutputFormatter(output_format, use_color)

    if args.quiet:
        _output_quiet_mode(result, output_format)
    else:
        _output_full_result(result, formatter, args)

    # Return exit code based on findings
    if result.critical_count > 0:
        return 2
    elif result.high_count > 0:
        return 1
    return 0


def _output_quiet_mode(result: AnalysisStatus, output_format: OutputFormat) -> None:
    """Output results in quiet mode (findings only).

    Args:
        result: Analysis result.
        output_format: Desired output format.
    """
    if output_format == OutputFormat.JSON:
        print(json.dumps([f.to_dict() for f in result.findings], indent=2))
    else:
        for finding in result.findings:
            print(f"[{finding.severity.upper()}] {finding.title}")
            print(f"  {finding.description}")
            print()


def _output_full_result(
    result: AnalysisStatus,
    formatter: OutputFormatter,
    args: argparse.Namespace
) -> None:
    """Output full analysis results.

    Args:
        result: Analysis result.
        formatter: Output formatter.
        args: Command-line arguments.
    """
    output = formatter.format_result(result)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Report written to: {args.output}")
    else:
        print(output)


def cmd_info(args: argparse.Namespace) -> int:
    """Execute the info command.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0=success, 1=error).
    """
    if not _validate_file_exists(args.memory_dump):
        return 1

    from .core.parser import MemoryParser

    parser = MemoryParser(args.memory_dump)

    try:
        with parser.open():
            info = parser.info
            _display_dump_info(args.memory_dump, info, args.format)
    except Exception as exc:
        _handle_info_error(exc, args.verbose)
        return 1

    return 0


def _display_dump_info(
    filepath: Path,
    info: MemoryParser.info.__class__,
    output_format: str
) -> None:
    """Display memory dump information.

    Args:
        filepath: Path to the memory dump.
        info: Memory dump information.
        output_format: Output format (text or json).
    """
    if output_format == 'json':
        _display_dump_info_json(filepath, info)
    else:
        _display_dump_info_text(filepath, info)


def _display_dump_info_json(filepath: Path, info: MemoryParser.info.__class__) -> None:
    """Display memory dump info as JSON.

    Args:
        filepath: Path to the memory dump.
        info: Memory dump information.
    """
    data = {
        'file': str(filepath),
        'size': info.size,
        'format': info.format.name,
        'architecture': info.architecture,
        'os_type': info.os_type,
        'regions': [
            {
                'start': hex(r.start),
                'end': hex(r.end),
                'size': r.size,
                'permissions': r.permissions,
                'path': r.path,
            }
            for r in info.regions
        ],
    }
    print(json.dumps(data, indent=2))


def _display_dump_info_text(filepath: Path, info: MemoryParser.info.__class__) -> None:
    """Display memory dump info as text.

    Args:
        filepath: Path to the memory dump.
        info: Memory dump information.
    """
    print(f"File: {filepath}")
    print(f"Size: {info.size:,} bytes ({info.size / (1024*1024):.2f} MB)")
    print(f"Format: {info.format.name}")
    print(f"Architecture: {info.architecture}")
    print(f"OS Type: {info.os_type}")
    print(f"Regions: {len(info.regions)}")
    print()

    if info.regions:
        print("Memory Regions:")
        print("-" * 70)
        for region in info.regions[:20]:
            print(f"  {hex(region.start):>18} - {hex(region.end):>18}  "
                  f"[{region.permissions}]  ({region.size:,} bytes)")
        if len(info.regions) > 20:
            print(f"  ... and {len(info.regions) - 20} more regions")


def _handle_info_error(error: Exception, verbose: bool) -> None:
    """Handle info command errors.

    Args:
        error: Exception that occurred.
        verbose: Whether to print verbose error details.
    """
    print(f"Error reading memory dump: {error}", file=sys.stderr)
    if verbose:
        traceback_module.print_exc()


def cmd_strings(args: argparse.Namespace) -> int:
    """Execute the strings command.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0=success, 1=error).
    """
    if not _validate_file_exists(args.memory_dump):
        return 1

    from .core.parser import MemoryParser

    parser = MemoryParser(args.memory_dump)

    try:
        with parser.open():
            count = 0
            for offset, string in parser.get_strings(min_length=args.min_length):
                if args.limit > 0 and count >= args.limit:
                    break

                if args.with_offsets:
                    print(f"{hex(offset):>12}  {string}")
                else:
                    print(string)
                count += 1

            if args.verbose:
                print(f"\nTotal strings extracted: {count}", file=sys.stderr)
    except Exception as exc:
        print(f"Error extracting strings: {exc}", file=sys.stderr)
        return 1

    return 0


def cmd_search(args: argparse.Namespace) -> int:
    """Execute the search command.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0=success, 1=error).
    """
    if not _validate_file_exists(args.memory_dump):
        return 1

    from .core.parser import MemoryParser

    # Parse pattern
    pattern = _parse_search_pattern(args.pattern, args.hex)
    if pattern is None:
        return 1

    parser = MemoryParser(args.memory_dump)

    try:
        with parser.open():
            matches = list(parser.find_pattern(pattern))
            _display_search_results(matches, args.count)
    except Exception as exc:
        print(f"Error searching memory: {exc}", file=sys.stderr)
        return 1

    return 0


def _parse_search_pattern(pattern: str, is_hex: bool) -> bytes | None:
    """Parse search pattern from user input.

    Args:
        pattern: Pattern string from user.
        is_hex: Whether pattern is hex-encoded.

    Returns:
        Bytes pattern or None if invalid.
    """
    if is_hex:
        try:
            return bytes.fromhex(pattern.replace(' ', ''))
        except ValueError as exc:
            print(f"Invalid hex pattern: {exc}", file=sys.stderr)
            return None
    return pattern.encode('utf-8', errors='replace')


def _display_search_results(matches: list[int], count_only: bool) -> None:
    """Display search results.

    Args:
        matches: List of match offsets.
        count_only: Whether to only show count.
    """
    if count_only:
        print(f"Found {len(matches)} matches")
    else:
        for offset in matches:
            print(f"Match at offset: {hex(offset)}")

        if not matches:
            print("No matches found")


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point.

    Args:
        argv: Command-line arguments (defaults to sys.argv).

    Returns:
        Exit code.
    """
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    # Dispatch to command handler
    commands: dict[str, callable] = {
        'analyze': cmd_analyze,
        'info': cmd_info,
        'strings': cmd_strings,
        'search': cmd_search,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 1


if __name__ == '__main__':
    sys.exit(main())
