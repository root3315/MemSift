"""
Command-Line Interface for MemSift

Provides a comprehensive CLI for memory forensics analysis.
"""

from __future__ import annotations
import argparse
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .core.analyzer import MemoryAnalyzer, AnalysisStatus
from .plugins import (
    ProcessScanner,
    NetworkAnalyzer,
    StringExtractor,
    InjectionDetector,
    CryptoScanner,
    RegistryScanner,
    FileSystemScanner,
)
from .utils.output import OutputFormatter, OutputFormat


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
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
  %(prog)s registry memory.dump                   # Scan registry artifacts
  %(prog)s filesystem memory.dump                 # Scan file system artifacts
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

    # Analyze command
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
        choices=['processes', 'network', 'strings', 'injection', 'crypto', 'registry', 'filesystem', 'all'],
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

    # Info command
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

    # Strings command
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

    # Search command
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

    # Registry command
    registry_parser = subparsers.add_parser(
        'registry',
        help='Scan for registry artifacts',
        description='Scan memory dump for Windows registry artifacts'
    )
    registry_parser.add_argument(
        'memory_dump',
        type=Path,
        help='Path to memory dump file'
    )
    registry_parser.add_argument(
        '-f', '--format',
        choices=['text', 'json', 'csv', 'table'],
        default='text',
        help='Output format (default: text)'
    )
    registry_parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Output file (default: stdout)'
    )
    registry_parser.add_argument(
        '--suspicious-only',
        action='store_true',
        help='Only show suspicious registry artifacts'
    )

    # Filesystem command
    filesystem_parser = subparsers.add_parser(
        'filesystem',
        help='Scan for file system artifacts',
        description='Scan memory dump for file system artifacts'
    )
    filesystem_parser.add_argument(
        'memory_dump',
        type=Path,
        help='Path to memory dump file'
    )
    filesystem_parser.add_argument(
        '-f', '--format',
        choices=['text', 'json', 'csv', 'table'],
        default='text',
        help='Output format (default: text)'
    )
    filesystem_parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Output file (default: stdout)'
    )
    filesystem_parser.add_argument(
        '--suspicious-only',
        action='store_true',
        help='Only show suspicious file artifacts'
    )

    return parser


def cmd_analyze(args: argparse.Namespace) -> int:
    """Execute the analyze command."""
    if not args.memory_dump.exists():
        print(f"Error: Memory dump not found: {args.memory_dump}", file=sys.stderr)
        return 1

    # Determine plugins to run
    if 'all' in args.plugins:
        plugin_names = None  # Run all
    else:
        plugin_names = args.plugins

    # Create analyzer and register plugins
    analyzer = MemoryAnalyzer(args.memory_dump)
    analyzer.register_plugin(ProcessScanner())
    analyzer.register_plugin(NetworkAnalyzer())
    analyzer.register_plugin(StringExtractor())
    analyzer.register_plugin(InjectionDetector())
    analyzer.register_plugin(CryptoScanner())
    analyzer.register_plugin(RegistryScanner())
    analyzer.register_plugin(FileSystemScanner())

    # Run analysis
    try:
        result = analyzer.analyze(plugin_names)
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    # Format output
    use_color = not args.no_color and sys.stdout.isatty()
    output_format = OutputFormat[args.format.upper()]
    formatter = OutputFormatter(output_format, use_color)

    # Handle quiet mode
    if args.quiet:
        output_format = OutputFormat.TEXT if output_format == OutputFormat.TABLE else output_format
        formatter = OutputFormatter(output_format, use_color)
        # Only output findings
        if output_format == OutputFormat.JSON:
            import json
            print(json.dumps([f.to_dict() for f in result.findings], indent=2))
        else:
            for finding in result.findings:
                print(f"[{finding.severity.upper()}] {finding.title}")
                print(f"  {finding.description}")
                print()
    else:
        # Full output
        output = formatter.format_result(result)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Report written to: {args.output}")
        else:
            print(output)

    # Return exit code based on findings
    if result.critical_count > 0:
        return 2
    elif result.high_count > 0:
        return 1
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """Execute the info command."""
    if not args.memory_dump.exists():
        print(f"Error: Memory dump not found: {args.memory_dump}", file=sys.stderr)
        return 1

    from .core.parser import MemoryParser

    parser = MemoryParser(args.memory_dump)

    try:
        with parser.open():
            info = parser.info

            if args.format == 'json':
                import json
                data = {
                    'file': str(args.memory_dump),
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
            else:
                print(f"File: {args.memory_dump}")
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
    except Exception as e:
        print(f"Error reading memory dump: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    return 0


def cmd_strings(args: argparse.Namespace) -> int:
    """Execute the strings command."""
    if not args.memory_dump.exists():
        print(f"Error: Memory dump not found: {args.memory_dump}", file=sys.stderr)
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
    except Exception as e:
        print(f"Error extracting strings: {e}", file=sys.stderr)
        return 1

    return 0


def cmd_search(args: argparse.Namespace) -> int:
    """Execute the search command."""
    if not args.memory_dump.exists():
        print(f"Error: Memory dump not found: {args.memory_dump}", file=sys.stderr)
        return 1

    from .core.parser import MemoryParser

    # Parse pattern
    if args.hex:
        try:
            pattern = bytes.fromhex(args.pattern.replace(' ', ''))
        except ValueError as e:
            print(f"Invalid hex pattern: {e}", file=sys.stderr)
            return 1
    else:
        pattern = args.pattern.encode('utf-8', errors='replace')

    parser = MemoryParser(args.memory_dump)

    try:
        with parser.open():
            matches = list(parser.find_pattern(pattern))

            if args.count:
                print(f"Found {len(matches)} matches")
            else:
                for offset in matches:
                    print(f"Match at offset: {hex(offset)}")

                if not matches:
                    print("No matches found")
    except Exception as e:
        print(f"Error searching memory: {e}", file=sys.stderr)
        return 1

    return 0


def cmd_registry(args: argparse.Namespace) -> int:
    """Execute the registry scan command."""
    if not args.memory_dump.exists():
        print(f"Error: Memory dump not found: {args.memory_dump}", file=sys.stderr)
        return 1

    # Create analyzer and register only registry plugin
    analyzer = MemoryAnalyzer(args.memory_dump)
    analyzer.register_plugin(RegistryScanner())

    # Run analysis
    try:
        result = analyzer.analyze(['registry_scanner'])
    except Exception as e:
        print(f"Error during registry scan: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    # Format output
    use_color = not args.no_color and sys.stdout.isatty()
    output_format = OutputFormat[args.format.upper()]
    formatter = OutputFormatter(output_format, use_color)

    # Filter findings if suspicious-only
    if args.suspicious_only:
        # Get plugin and filter artifacts
        registry_plugin = analyzer.plugins[0]
        artifacts = [a for a in registry_plugin.get_artifacts() if a.is_suspicious]
        
        if output_format == OutputFormat.JSON:
            import json
            output = json.dumps([{
                'artifact_type': a.artifact_type,
                'key_path': a.key_path,
                'offset': hex(a.offset),
                'reasons': a.suspicion_reasons,
            } for a in artifacts], indent=2)
        else:
            lines = [f"Found {len(artifacts)} suspicious registry artifacts:"]
            for a in artifacts:
                lines.append(f"  [{a.artifact_type.upper()}] {a.key_path[:80]}")
                lines.append(f"    Reasons: {'; '.join(a.suspicion_reasons)}")
            output = '\n'.join(lines)
    else:
        output = formatter.format_result(result)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Report written to: {args.output}")
    else:
        print(output)

    return 0


def cmd_filesystem(args: argparse.Namespace) -> int:
    """Execute the filesystem scan command."""
    if not args.memory_dump.exists():
        print(f"Error: Memory dump not found: {args.memory_dump}", file=sys.stderr)
        return 1

    # Create analyzer and register only filesystem plugin
    analyzer = MemoryAnalyzer(args.memory_dump)
    analyzer.register_plugin(FileSystemScanner())

    # Run analysis
    try:
        result = analyzer.analyze(['filesystem_scanner'])
    except Exception as e:
        print(f"Error during filesystem scan: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    # Format output
    use_color = not args.no_color and sys.stdout.isatty()
    output_format = OutputFormat[args.format.upper()]
    formatter = OutputFormatter(output_format, use_color)

    # Filter findings if suspicious-only
    if args.suspicious_only:
        # Get plugin and filter artifacts
        fs_plugin = analyzer.plugins[0]
        artifacts = [a for a in fs_plugin.get_artifacts() if a.is_suspicious]
        
        if output_format == OutputFormat.JSON:
            import json
            output = json.dumps([{
                'artifact_type': a.artifact_type,
                'path': a.path,
                'file_type': a.file_type,
                'offset': hex(a.offset),
                'reasons': a.suspicion_reasons,
            } for a in artifacts], indent=2)
        else:
            lines = [f"Found {len(artifacts)} suspicious file artifacts:"]
            for a in artifacts:
                lines.append(f"  [{a.artifact_type.upper()}] {a.path[:80]}")
                lines.append(f"    Type: {a.file_type}, Reasons: {'; '.join(a.suspicion_reasons)}")
            output = '\n'.join(lines)
    else:
        output = formatter.format_result(result)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Report written to: {args.output}")
    else:
        print(output)

    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    # Dispatch to command handler
    commands = {
        'analyze': cmd_analyze,
        'info': cmd_info,
        'strings': cmd_strings,
        'search': cmd_search,
        'registry': cmd_registry,
        'filesystem': cmd_filesystem,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 1


if __name__ == '__main__':
    sys.exit(main())
