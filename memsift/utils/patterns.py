"""
Pattern Matching Module

Provides advanced pattern matching capabilities for memory analysis.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Iterator
from enum import Enum, auto


class PatternType(Enum):
    """Type of pattern matching."""
    LITERAL = auto()
    REGEX = auto()
    HEX = auto()
    STRUCT = auto()


@dataclass(slots=True)
class Pattern:
    """Represents a search pattern."""
    name: str
    pattern_type: PatternType
    value: bytes | str
    description: str = ""
    severity: str = "info"
    category: str = "general"
    _compiled_regex: re.Pattern | None = field(default=None, repr=False)

    def __post_init__(self):
        if self.pattern_type == PatternType.REGEX and isinstance(self.value, str):
            self._compiled_regex = re.compile(self.value)


@dataclass(slots=True)
class PatternMatch:
    """Represents a pattern match result."""
    pattern: Pattern
    offset: int
    matched_data: bytes
    context_before: bytes = field(default_factory=bytes)
    context_after: bytes = field(default_factory=bytes)

    @property
    def context(self) -> bytes:
        """Get matched data with context."""
        return self.context_before + self.matched_data + self.context_after


class PatternSet:
    """
    A collection of patterns for matching.

    Provides efficient pattern management and matching operations.
    """

    def __init__(self, name: str = "default"):
        self.name = name
        self._patterns: list[Pattern] = []
        self._patterns_by_category: dict[str, list[Pattern]] = {}

    def add(self, pattern: Pattern) -> None:
        """Add a pattern to the set."""
        self._patterns.append(pattern)
        if pattern.category not in self._patterns_by_category:
            self._patterns_by_category[pattern.category] = []
        self._patterns_by_category[pattern.category].append(pattern)

    def remove(self, name: str) -> bool:
        """Remove a pattern by name."""
        for i, pattern in enumerate(self._patterns):
            if pattern.name == name:
                del self._patterns[i]
                return True
        return False

    def get(self, name: str) -> Pattern | None:
        """Get a pattern by name."""
        for pattern in self._patterns:
            if pattern.name == name:
                return pattern
        return None

    def get_by_category(self, category: str) -> list[Pattern]:
        """Get all patterns in a category."""
        return self._patterns_by_category.get(category, [])

    @property
    def patterns(self) -> list[Pattern]:
        """Get all patterns."""
        return self._patterns.copy()

    @property
    def categories(self) -> list[str]:
        """Get all categories."""
        return list(self._patterns_by_category.keys())

    def __len__(self) -> int:
        return len(self._patterns)

    def __iter__(self) -> Iterator[Pattern]:
        return iter(self._patterns)


class PatternMatcher:
    """
    Advanced pattern matcher for memory analysis.

    Supports literal, regex, and hex pattern matching with context extraction.
    """

    def __init__(self, pattern_set: PatternSet | None = None):
        self.pattern_set = pattern_set or PatternSet()
        self._context_size = 32  # Bytes of context before/after match

    @property
    def context_size(self) -> int:
        """Get context size."""
        return self._context_size

    @context_size.setter
    def context_size(self, size: int) -> None:
        """Set context size."""
        self._context_size = max(0, size)

    def match(self, data: bytes, start: int = 0) -> Iterator[PatternMatch]:
        """
        Match all patterns against data.

        Args:
            data: Bytes to search
            start: Starting offset for reporting

        Yields:
            PatternMatch objects for each match found
        """
        for pattern in self.pattern_set:
            yield from self._match_pattern(pattern, data, start)

    def _match_pattern(self, pattern: Pattern, data: bytes, start: int) -> Iterator[PatternMatch]:
        """Match a single pattern against data."""
        if pattern.pattern_type == PatternType.LITERAL:
            yield from self._match_literal(pattern, data, start)
        elif pattern.pattern_type == PatternType.REGEX:
            yield from self._match_regex(pattern, data, start)
        elif pattern.pattern_type == PatternType.HEX:
            yield from self._match_hex(pattern, data, start)

    def _match_literal(self, pattern: Pattern, data: bytes, start: int) -> Iterator[PatternMatch]:
        """Match a literal byte pattern."""
        if not isinstance(pattern.value, bytes):
            return

        pos = 0
        while True:
            idx = data.find(pattern.value, pos)
            if idx == -1:
                break

            yield self._create_match(pattern, data, idx, start)
            pos = idx + 1

    def _match_regex(self, pattern: Pattern, data: bytes, start: int) -> Iterator[PatternMatch]:
        """Match a regex pattern."""
        if not isinstance(pattern.value, str) or pattern._compiled_regex is None:
            return

        for match in pattern._compiled_regex.finditer(data):
            yield self._create_match(pattern, data, match.start(), start, match.end() - match.start())

    def _match_hex(self, pattern: Pattern, data: bytes, start: int) -> Iterator[PatternMatch]:
        """Match a hex pattern (supports wildcards)."""
        if not isinstance(pattern.value, str):
            return

        # Convert hex pattern to regex
        hex_pattern = pattern.value.replace(' ', '').replace('.', '[0-9a-fA-F]{2}')
        byte_pattern = bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', pattern.value.replace(' ', '')))

        # Simple hex matching
        pos = 0
        while True:
            idx = data.find(byte_pattern, pos)
            if idx == -1:
                break

            yield self._create_match(pattern, data, idx, start)
            pos = idx + 1

    def _create_match(self, pattern: Pattern, data: bytes, idx: int,
                      start: int, length: int | None = None) -> PatternMatch:
        """Create a PatternMatch object."""
        if length is None:
            length = len(pattern.value) if isinstance(pattern.value, bytes) else 0

        context_start = max(0, idx - self._context_size)
        context_end = min(len(data), idx + length + self._context_size)

        return PatternMatch(
            pattern=pattern,
            offset=start + idx,
            matched_data=data[idx:idx + length],
            context_before=data[context_start:idx],
            context_after=data[idx + length:context_end],
        )

    @classmethod
    def create_default_patterns(cls) -> PatternSet:
        """Create a default set of security-relevant patterns."""
        pattern_set = PatternSet("default")

        # Malware signatures
        pattern_set.add(Pattern(
            name="mimikatz_signature",
            pattern_type=PatternType.LITERAL,
            value=b'mimikatz',
            description="Mimikatz credential dumping tool signature",
            severity="critical",
            category="malware"
        ))

        pattern_set.add(Pattern(
            name="metasploit_signature",
            pattern_type=PatternType.LITERAL,
            value=b'meterpreter',
            description="Metasploit Meterpreter signature",
            severity="critical",
            category="malware"
        ))

        # Network indicators
        pattern_set.add(Pattern(
            name="http_url",
            pattern_type=PatternType.REGEX,
            value=r'https?://[^\s<>"{}|\\^`\[\]]+',
            description="HTTP/HTTPS URLs",
            severity="info",
            category="network"
        ))

        pattern_set.add(Pattern(
            name="ip_address",
            pattern_type=PatternType.REGEX,
            value=r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            description="IPv4 addresses",
            severity="info",
            category="network"
        ))

        # Cryptographic indicators
        pattern_set.add(Pattern(
            name="private_key_header",
            pattern_type=PatternType.LITERAL,
            value=b'-----BEGIN',
            description="Private key or certificate header",
            severity="medium",
            category="crypto"
        ))

        # Command execution
        pattern_set.add(Pattern(
            name="powershell_encoded",
            pattern_type=PatternType.REGEX,
            value=r'(?i)powershell.*-enc',
            description="PowerShell encoded command execution",
            severity="high",
            category="execution"
        ))

        pattern_set.add(Pattern(
            name="cmd_execution",
            pattern_type=PatternType.REGEX,
            value=r'(?i)cmd\.exe\s+(/c|/k)',
            description="Command prompt execution",
            severity="medium",
            category="execution"
        ))

        return pattern_set
