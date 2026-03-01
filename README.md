# MemSift

**Memory Forensics and RAM Analysis Tool for Security Investigations**

MemSift is a professional, modular Python toolkit for memory forensics and incident response. It analyzes memory dumps to detect malware, extract artifacts, identify code injection, and uncover evidence of compromise.

## Features

- **Multi-Format Support**: Analyzes raw memory dumps and ELF core dumps
- **Plugin Architecture**: Extensible design with specialized analysis plugins
- **Process Detection**: Identifies running processes and suspicious executables
- **Network Analysis**: Detects C2 indicators, suspicious IPs, and network artifacts
- **String Extraction**: Categorizes strings including credentials, URLs, and commands
- **Injection Detection**: Finds RWX memory, shellcode, API hooks, and hollowing
- **Crypto Analysis**: Identifies encryption activity and ransomware indicators
- **Multiple Output Formats**: Text, JSON, CSV, and table formats
- **Memory Efficient**: Uses memory-mapped files for large dump analysis

## Installation

### From Source

```bash
git clone https://github.com/memsift/memsift.git
cd memsift
pip install -e .
```

### Using pip

```bash
pip install memsift
```

## Quick Start

```bash
# Run full analysis on a memory dump
memsift analyze memory.dump

# Analyze with specific plugins only
memsift analyze memory.dump -p processes network injection

# Output results as JSON
memsift analyze memory.dump -f json -o report.json

# View memory dump information
memsift info memory.dump

# Extract strings from memory
memsift strings memory.dump -m 8 --with-offsets

# Search for a pattern
memsift search memory.dump "mimikatz"
memsift search memory.dump "4d 69 6d 69 6b 61 74 7a" --hex
```

## Commands

### `analyze` - Full Memory Analysis

Perform comprehensive analysis using all or selected plugins.

```bash
memsift analyze <memory_dump> [options]

Options:
  -p, --plugins     Plugins to run: processes, network, strings, injection, crypto, all
  -f, --format      Output format: text, json, csv, table
  -o, --output      Output file path
  -q, --quiet       Only show findings (no summary)
```

### `info` - Memory Dump Information

Display metadata about a memory dump file.

```bash
memsift info <memory_dump> [-f text|json]
```

### `strings` - Extract Strings

Extract printable strings from memory.

```bash
memsift strings <memory_dump> [options]

Options:
  -m, --min-length  Minimum string length (default: 4)
  -n, --limit       Maximum strings to show (0 = unlimited)
  --with-offsets    Show string offsets
```

### `search` - Pattern Search

Search for byte patterns or strings in memory.

```bash
memsift search <memory_dump> <pattern> [options]

Options:
  -x, --hex         Treat pattern as hex bytes
  -c, --count       Only show match count
```

## Plugins

MemSift includes five analysis plugins:

### Process Scanner (`processes`)
- Detects process names and structures
- Identifies suspicious process characteristics
- Flags known malicious tools (Mimikatz, Metasploit, etc.)
- Detects process masquerading attempts

### Network Analyzer (`network`)
- Extracts IP addresses, URLs, and domains
- Identifies suspicious ports and C2 patterns
- Detects DGA-like domain names
- Flags high-frequency network indicators

### String Extractor (`strings`)
- Categorizes strings (paths, URLs, commands, credentials)
- Detects sensitive data (passwords, API keys, tokens)
- Identifies encoded commands (PowerShell -enc)
- Finds connection strings and configuration data

### Injection Detector (`injection`)
- Detects RWX (Read-Write-Execute) memory regions
- Identifies shellcode patterns (Metasploit, egg hunters)
- Finds API hooking signatures
- Locates suspicious API references

### Crypto Scanner (`crypto`)
- Detects cryptographic constants (AES S-box, SHA constants)
- Identifies crypto API usage
- Finds ransomware indicators
- Locates high-entropy encrypted data regions

## Output Formats

### Text (Default)
Human-readable formatted output with colors.

### JSON
Machine-readable format for integration with other tools.

```json
{
  "summary": {
    "status": "COMPLETED",
    "total_findings": 15,
    "critical_count": 2,
    "high_count": 5
  },
  "findings": [...]
}
```

### CSV
Spreadsheet-compatible format for further analysis.

### Table
Compact tabular view of findings.

## Programmatic Usage

```python
from memsift import MemoryAnalyzer
from memsift.plugins import ProcessScanner, NetworkAnalyzer, InjectionDetector
from memsift.utils import OutputFormatter, OutputFormat

# Create analyzer
analyzer = MemoryAnalyzer("memory.dump")

# Register plugins
analyzer.register_plugin(ProcessScanner())
analyzer.register_plugin(NetworkAnalyzer())
analyzer.register_plugin(InjectionDetector())

# Run analysis
result = analyzer.analyze()

# Check results
print(f"Status: {result.status.name}")
print(f"Findings: {result.total_findings}")
print(f"Critical: {result.critical_count}")

# Output as JSON
formatter = OutputFormatter(OutputFormat.JSON)
print(formatter.format_result(result))

# Access specific plugin data
process_plugin = analyzer.plugins[0]
for process in process_plugin.get_processes():
    if process.is_suspicious:
        print(f"Suspicious: {process.name} (PID: {process.pid})")
```

## Creating Custom Plugins

```python
from memsift.core.analyzer import AnalysisPlugin, AnalysisFinding

class MyPlugin(AnalysisPlugin):
    name = "my_plugin"
    description = "Custom analysis plugin"
    version = "1.0.0"
    
    def analyze(self) -> list[AnalysisFinding]:
        findings = []
        
        with self._parser.open():
            # Access memory via self._parser
            for offset, string in self._parser.get_strings(min_length=8):
                if "suspicious" in string.lower():
                    findings.append(AnalysisFinding(
                        category="custom",
                        severity="medium",
                        title=f"Suspicious String: {string}",
                        description="Found suspicious content",
                        offset=offset,
                    ))
        
        return findings
    
    def get_statistics(self) -> dict:
        return {"custom_metric": 42}

# Use the plugin
analyzer = MemoryAnalyzer("memory.dump")
analyzer.register_plugin(MyPlugin())
result = analyzer.analyze()
```

## Use Cases

### Incident Response
```bash
# Quick triage of suspected compromise
memsift analyze memory.dump -p processes,injection -f table

# Full forensic analysis
memsift analyze memory.dump -f json -o forensic_report.json
```

### Malware Analysis
```bash
# Detect injection techniques
memsift analyze memory.dump -p injection,crypto

# Extract IOCs
memsift analyze memory.dump -p network,strings -f json | jq '.findings'
```

### Threat Hunting
```bash
# Search for known malware signatures
memsift search memory.dump "mimikatz" -c
memsift search memory.dump "meterpreter" -c

# Find encoded commands
memsift strings memory.dump -m 50 | grep -i "powershell.*-enc"
```

## Requirements

- Python 3.10+
- No external dependencies (uses standard library only)

## Project Structure

```
memsift/
├── __init__.py          # Package initialization
├── __main__.py          # Entry point
├── cli.py               # Command-line interface
├── core/
│   ├── __init__.py
│   ├── parser.py        # Memory dump parsing
│   └── analyzer.py      # Analysis engine
├── plugins/
│   ├── __init__.py
│   ├── base.py          # Plugin base class
│   ├── processes.py     # Process scanner
│   ├── network.py       # Network analyzer
│   ├── strings.py       # String extractor
│   ├── injection.py     # Injection detector
│   └── crypto.py        # Crypto scanner
└── utils/
    ├── __init__.py
    ├── output.py        # Output formatting
    └── patterns.py      # Pattern matching
```

## Changelog

### [Unreleased]

#### Improved
- **Type hints consistency**: Updated `MemoryParser` class to use modern type hints (`io.BufferedReader`, `mmap.mmap`, `int | None`) for better IDE support and type checking.
- **Context manager error handling**: Enhanced `MemoryParser.open()` with explicit exception handling for `FileNotFoundError`, `PermissionError`, and `OSError`. Resources are now properly cleaned up even when exceptions occur during initialization.
- **Memory efficiency**: Added `__slots__` to high-frequency dataclasses (`ProcessInfo`, `NetworkArtifact`, `InjectionIndicator`, `CryptoArtifact`, `ExtractedString`) reducing memory footprint by ~40-50% per instance during large-scale analysis.

#### Changed
- Replaced `Optional[T]` with modern `T | None` syntax across plugin dataclasses for Python 3.10+ consistency.
- Removed unused `BinaryIO` import from `parser.py` in favor of concrete `io.BufferedReader` type.

---

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest`
5. Submit a pull request

## Disclaimer

MemSift is designed for legitimate security research, incident response, and educational purposes. Only use this tool on systems you own or have explicit permission to analyze.
