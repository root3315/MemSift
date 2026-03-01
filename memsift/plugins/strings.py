"""
String Extractor Plugin

Extracts and categorizes strings from memory dumps:
- ASCII and Unicode strings
- Paths, commands, and URLs
- Potential credentials and secrets
- Encoded strings
"""

from __future__ import annotations

import base64
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.analyzer import AnalysisPlugin, AnalysisFinding

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass(slots=True)
class ExtractedString:
    """Represents an extracted string with metadata."""
    value: str
    offset: int
    string_type: str  # ascii, unicode, base64, encoded
    category: str = "general"
    is_sensitive: bool = False
    sensitivity_reasons: list[str] = field(default_factory=list)


class StringExtractor(AnalysisPlugin):
    """
    Extracts and categorizes strings from memory.

    Identifies paths, URLs, commands, potential credentials,
    and other sensitive strings that may indicate malicious activity.
    """

    name = "string_extractor"
    description = "Extract and categorize strings, detect sensitive data"
    version = "1.0.0"

    # Minimum string length for analysis
    MIN_STRING_LENGTH = 6
    # Maximum string length to store
    MAX_STRING_LENGTH = 4096
    # Minimum printable character ratio
    MIN_PRINTABLE_RATIO = 0.8
    # Truncate length for output
    TRUNCATE_LENGTH = 500

    # String category patterns
    CATEGORY_PATTERNS: dict[str, list[str]] = {
        'path': [
            r'[A-Za-z]:\\[^\s<>"|?*]+',  # Windows paths
            r'/(?:usr|home|var|tmp|etc|opt|root)[^\s]*',  # Unix paths
        ],
        'url': [
            r'https?://[^\s<>"{}|\\^`\[\]]+',
        ],
        'command': [
            r'(?i)\b(cmd|powershell|bash|sh|wget|curl|nc|netcat)\b',
            r'(?i)\b(exec|system|shell|eval)\s*\(',
        ],
        'registry': [
            r'HKEY_[A-Z_]+\\[^\s]+',
            r'(?i)HKLM\\[^\s]+',
            r'(?i)HKCU\\[^\s]+',
        ],
        'ip': [
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        ],
        'email': [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        ],
    }

    # Sensitive patterns
    SENSITIVE_PATTERNS: dict[str, str] = {
        'password_keyword': (
            r'(?i)(password|passwd|pwd|pass|secret|token|api[_-]?key|auth)\s*[:=]\s*[^\s]+'
        ),
        'base64_blob': (
            r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        ),
        'private_key': r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
        'jwt': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'github_token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
        'connection_string': r'(?i)(server|database|uid|pwd)=.*;',
    }

    # Suspicious command patterns
    SUSPICIOUS_COMMAND_PATTERNS: tuple[str, ...] = (
        r'(?i)-enc\s+[A-Za-z0-9+/=]+',  # PowerShell encoded command
        r'(?i)frombase64string',  # Base64 decode
        r'(?i)iex\s*\(',  # Invoke-Expression
        r'(?i)invoke-expression',
        r'(?i)downloadstring',
        r'(?i)downloadfile',
        r'(?i)bypass.*executionpolicy',
        r'(?i)hidden.*windowstyle',
        r'(?i)wscript\.shell',
        r'(?i)reg\s+add',
        r'(?i)schtasks\s+/create',
    )

    def __init__(self) -> None:
        """Initialize the string extractor."""
        super().__init__()
        self._strings: list[ExtractedString] = []
        self._category_counter: Counter = Counter()
        self._sensitive_count = 0
        self._compiled_category_patterns = self._compile_category_patterns()
        self._compiled_sensitive_patterns = self._compile_sensitive_patterns()
        self._compiled_suspicious_commands = [
            re.compile(pattern) for pattern in self.SUSPICIOUS_COMMAND_PATTERNS
        ]

    def _compile_category_patterns(self) -> dict[str, list[re.Pattern]]:
        """Compile category regex patterns.

        Returns:
            Dictionary of compiled patterns by category.
        """
        compiled: dict[str, list[re.Pattern]] = {}
        for category, patterns in self.CATEGORY_PATTERNS.items():
            compiled[category] = [re.compile(pattern) for pattern in patterns]
        return compiled

    def _compile_sensitive_patterns(self) -> dict[str, re.Pattern]:
        """Compile sensitive data regex patterns.

        Returns:
            Dictionary of compiled sensitive patterns.
        """
        compiled: dict[str, re.Pattern] = {}
        for name, pattern in self.SENSITIVE_PATTERNS.items():
            compiled[name] = re.compile(pattern)
        return compiled

    def analyze(self) -> list[AnalysisFinding]:
        """Extract and analyze strings from memory.

        Returns:
            List of analysis findings for sensitive strings.
        """
        findings: list[AnalysisFinding] = []
        self._strings = []
        self._category_counter = Counter()
        self._sensitive_count = 0

        if self._parser is None:
            return findings

        # Extract strings from memory
        for offset, string in self._parser.get_strings(min_length=self.MIN_STRING_LENGTH):
            extracted = self._analyze_string(string, offset)
            if extracted is not None:
                self._strings.append(extracted)
                self._category_counter[extracted.category] += 1

                if extracted.is_sensitive:
                    self._sensitive_count += 1
                    findings.append(self._create_finding(extracted))

        # Check for encoded command chains
        findings.extend(self._detect_encoded_commands())

        return findings

    def _analyze_string(self, string: str, offset: int) -> ExtractedString | None:
        """Analyze a string and categorize it.

        Args:
            string: String to analyze.
            offset: Offset in memory.

        Returns:
            ExtractedString object or None if invalid.
        """
        if len(string) < self.MIN_STRING_LENGTH or len(string) > self.MAX_STRING_LENGTH:
            return None

        # Skip strings with too many non-printable characters
        printable_ratio = sum(1 for c in string if 32 <= ord(c) <= 126) / len(string)
        if printable_ratio < self.MIN_PRINTABLE_RATIO:
            return None

        category = "general"
        sensitivity_reasons: list[str] = []
        is_sensitive = False

        # Categorize the string
        category = self._categorize_string(string)

        # Check for sensitive content
        for sens_type, pattern in self._compiled_sensitive_patterns.items():
            if pattern.search(string):
                is_sensitive = True
                sensitivity_reasons.append(f"Sensitive pattern: {sens_type}")

        # Check for suspicious commands
        for pattern in self._compiled_suspicious_commands:
            if pattern.search(string):
                is_sensitive = True
                sensitivity_reasons.append("Suspicious command pattern")
                break

        # Determine string type
        string_type = "base64" if self._looks_like_base64(string) else "ascii"

        return ExtractedString(
            value=string[:self.TRUNCATE_LENGTH],
            offset=offset,
            string_type=string_type,
            category=category,
            is_sensitive=is_sensitive,
            sensitivity_reasons=sensitivity_reasons
        )

    def _categorize_string(self, string: str) -> str:
        """Determine the category of a string.

        Args:
            string: String to categorize.

        Returns:
            Category name.
        """
        for category, patterns in self._compiled_category_patterns.items():
            for pattern in patterns:
                if pattern.search(string):
                    return category
        return "general"

    def _looks_like_base64(self, string: str) -> bool:
        """Check if a string looks like base64 encoded data.

        Args:
            string: String to check.

        Returns:
            True if the string appears to be base64 encoded.
        """
        if len(string) < 16:
            return False

        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        char_ratio = sum(1 for c in string if c in base64_chars) / len(string)

        # Base64 has specific length requirements
        is_valid_length = (
            len(string) % 4 == 0 or
            string.endswith(('=', '=='))
        )

        return char_ratio > 0.95 and is_valid_length

    def _detect_encoded_commands(self) -> list[AnalysisFinding]:
        """Detect encoded command chains in extracted strings.

        Returns:
            List of findings for encoded suspicious commands.
        """
        findings: list[AnalysisFinding] = []

        for extracted in self._strings:
            if extracted.string_type == "base64" and len(extracted.value) > 50:
                finding = self._try_decode_and_check_suspicious(extracted)
                if finding is not None:
                    findings.append(finding)

        return findings

    def _try_decode_and_check_suspicious(
        self,
        extracted: ExtractedString
    ) -> AnalysisFinding | None:
        """Try to decode base64 and check for suspicious content.

        Args:
            extracted: ExtractedString to check.

        Returns:
            AnalysisFinding if suspicious, None otherwise.
        """
        try:
            decoded = base64.b64decode(extracted.value).decode('utf-8', errors='ignore')

            for pattern in self._compiled_suspicious_commands:
                if pattern.search(decoded):
                    return AnalysisFinding(
                        category="encoding",
                        severity="high",
                        title="Encoded Suspicious Command Detected",
                        description=(
                            f"Base64-encoded string at offset {hex(extracted.offset)} "
                            f"decodes to content with suspicious command patterns."
                        ),
                        offset=extracted.offset,
                        context={
                            'encoded': extracted.value[:100],
                            'decoded_preview': decoded[:200],
                            'pattern': pattern.pattern,
                        }
                    )
        except Exception:
            pass
        return None

    def _create_finding(self, extracted: ExtractedString) -> AnalysisFinding:
        """Create an analysis finding for a sensitive string.

        Args:
            extracted: Sensitive ExtractedString.

        Returns:
            AnalysisFinding object.
        """
        severity = self._determine_severity(extracted)

        return AnalysisFinding(
            category="string",
            severity=severity,
            title=f"Sensitive String: {extracted.value[:50]}...",
            description=(
                f"Detected sensitive {extracted.category} string. "
                f"Reasons: {'; '.join(extracted.sensitivity_reasons)}"
            ),
            offset=extracted.offset,
            context={
                'value': extracted.value,
                'category': extracted.category,
                'string_type': extracted.string_type,
                'reasons': extracted.sensitivity_reasons,
            }
        )

    def _determine_severity(self, extracted: ExtractedString) -> str:
        """Determine the severity level for a finding.

        Args:
            extracted: ExtractedString to evaluate.

        Returns:
            Severity level string.
        """
        reasons_text = " ".join(extracted.sensitivity_reasons).lower()

        high_severity_keywords = [
            'password', 'key', 'token', 'secret',
            'suspicious command', 'encoded'
        ]
        if any(kw in reasons_text for kw in high_severity_keywords):
            return "high"

        return "medium"

    def get_statistics(self) -> dict[str, int | dict[str, int]]:
        """Return string extraction statistics.

        Returns:
            Dictionary of statistics.
        """
        type_counts: dict[str, int] = dict(Counter(s.string_type for s in self._strings))
        return {
            'total_strings': len(self._strings),
            'sensitive_count': self._sensitive_count,
            'categories': dict(self._category_counter),
            'by_type': type_counts,
        }

    def get_strings(self, category: str | None = None) -> list[ExtractedString]:
        """Get extracted strings, optionally filtered by category.

        Args:
            category: Optional category to filter by.

        Returns:
            List of ExtractedString objects.
        """
        if category:
            return [s for s in self._strings if s.category == category]
        return self._strings.copy()
