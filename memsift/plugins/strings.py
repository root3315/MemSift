"""
String Extractor Plugin

Extracts and categorizes strings from memory dumps:
- ASCII and Unicode strings
- Paths, commands, and URLs
- Potential credentials and secrets
- Encoded strings
"""

from __future__ import annotations
import re
import base64
from dataclasses import dataclass, field
from collections import Counter

from ..core.analyzer import AnalysisPlugin, AnalysisFinding


@dataclass(slots=True)
class ExtractedString:
    """Represents an extracted string with metadata."""
    value: str
    offset: int
    string_type: str  # ascii, unicode, base64, encoded
    category: str = "general"  # path, url, command, credential, etc.
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
    
    # String category patterns
    CATEGORY_PATTERNS = {
        'path': [
            re.compile(r'[A-Za-z]:\\[^\s<>"|?*]+', re.IGNORECASE),  # Windows paths
            re.compile(r'/(?:usr|home|var|tmp|etc|opt|root)[^\s]*'),  # Unix paths
        ],
        'url': [
            re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
        ],
        'command': [
            re.compile(r'(?i)\b(cmd|powershell|bash|sh|wget|curl|nc|netcat)\b'),
            re.compile(r'(?i)\b(exec|system|shell|eval)\s*\('),
        ],
        'registry': [
            re.compile(r'HKEY_[A-Z_]+\\[^\s]+'),
            re.compile(r'(?i)HKLM\\[^\s]+'),
            re.compile(r'(?i)HKCU\\[^\s]+'),
        ],
        'ip': [
            re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
        ],
        'email': [
            re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        ],
    }
    
    # Sensitive patterns
    SENSITIVE_PATTERNS = {
        'password_keyword': re.compile(r'(?i)(password|passwd|pwd|pass|secret|token|api[_-]?key|auth)\s*[:=]\s*[^\s]+'),
        'base64_blob': re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
        'private_key': re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'),
        'jwt': re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
        'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'github_token': re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
        'connection_string': re.compile(r'(?i)(server|database|uid|pwd)=.*;'),
    }
    
    # Suspicious command patterns
    SUSPICIOUS_COMMANDS = [
        re.compile(r'(?i)-enc\s+[A-Za-z0-9+/=]+'),  # PowerShell encoded command
        re.compile(r'(?i)frombase64string'),  # Base64 decode
        re.compile(r'(?i)iex\s*\('),  # Invoke-Expression
        re.compile(r'(?i)invoke-expression'),
        re.compile(r'(?i)downloadstring'),
        re.compile(r'(?i)downloadfile'),
        re.compile(r'(?i)bypass.*executionpolicy'),
        re.compile(r'(?i)hidden.*windowstyle'),
        re.compile(r'(?i)wscript\.shell'),
        re.compile(r'(?i)reg\s+add'),
        re.compile(r'(?i)schtasks\s+/create'),
    ]
    
    def __init__(self):
        super().__init__()
        self._strings: list[ExtractedString] = []
        self._category_counter: Counter = Counter()
        self._sensitive_count = 0
    
    def analyze(self) -> list[AnalysisFinding]:
        """Extract and analyze strings from memory."""
        findings = []
        self._strings = []
        self._category_counter = Counter()
        self._sensitive_count = 0
        
        if self._parser is None:
            return findings
        
        # Extract strings from memory
        for offset, string in self._parser.get_strings(min_length=6):
            extracted = self._analyze_string(string, offset)
            if extracted:
                self._strings.append(extracted)
                self._category_counter[extracted.category] += 1
                
                if extracted.is_sensitive:
                    self._sensitive_count += 1
                    findings.append(self._create_finding(extracted))
        
        # Check for encoded command chains
        findings.extend(self._detect_encoded_commands())
        
        return findings
    
    def _analyze_string(self, string: str, offset: int) -> Optional[ExtractedString]:
        """Analyze a string and categorize it."""
        if len(string) < 6 or len(string) > 4096:
            return None
        
        # Skip non-printable heavy strings
        printable_ratio = sum(1 for c in string if 32 <= ord(c) <= 126) / len(string)
        if printable_ratio < 0.8:
            return None
        
        category = "general"
        sensitivity_reasons = []
        is_sensitive = False
        
        # Categorize the string
        for cat, patterns in self.CATEGORY_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(string):
                    category = cat
                    break
            if category != "general":
                break
        
        # Check for sensitive content
        for sens_type, pattern in self.SENSITIVE_PATTERNS.items():
            if pattern.search(string):
                is_sensitive = True
                sensitivity_reasons.append(f"Sensitive pattern: {sens_type}")
        
        # Check for suspicious commands
        for pattern in self.SUSPICIOUS_COMMANDS:
            if pattern.search(string):
                is_sensitive = True
                sensitivity_reasons.append(f"Suspicious command pattern")
                break
        
        # Determine string type
        string_type = "ascii"
        if self._looks_like_base64(string):
            string_type = "base64"
        
        return ExtractedString(
            value=string[:500],  # Truncate very long strings
            offset=offset,
            string_type=string_type,
            category=category,
            is_sensitive=is_sensitive,
            sensitivity_reasons=sensitivity_reasons
        )
    
    def _looks_like_base64(self, string: str) -> bool:
        """Check if a string looks like base64 encoded data."""
        if len(string) < 20:
            return False
        
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        char_ratio = sum(1 for c in string if c in base64_chars) / len(string)
        
        # Base64 has specific length requirements
        is_valid_length = len(string) % 4 == 0 or string.endswith(('=', '=='))
        
        return char_ratio > 0.95 and is_valid_length
    
    def _detect_encoded_commands(self) -> list[AnalysisFinding]:
        """Detect encoded command chains in extracted strings."""
        findings = []
        
        for extracted in self._strings:
            if extracted.string_type == "base64" and len(extracted.value) > 50:
                try:
                    # Try to decode base64
                    decoded = base64.b64decode(extracted.value).decode('utf-8', errors='ignore')
                    
                    # Check if decoded content contains suspicious patterns
                    for pattern in self.SUSPICIOUS_COMMANDS:
                        if pattern.search(decoded):
                            findings.append(AnalysisFinding(
                                category="encoding",
                                severity="high",
                                title="Encoded Suspicious Command Detected",
                                description=f"Base64-encoded string at offset {hex(extracted.offset)} "
                                          f"decodes to content with suspicious command patterns.",
                                offset=extracted.offset,
                                context={
                                    'encoded': extracted.value[:100],
                                    'decoded_preview': decoded[:200],
                                    'pattern': pattern.pattern,
                                }
                            ))
                            break
                except Exception:
                    pass  # Not valid base64 or decode failed
        
        return findings
    
    def _create_finding(self, extracted: ExtractedString) -> AnalysisFinding:
        """Create an analysis finding for a sensitive string."""
        severity = "medium"
        if any(kw in " ".join(extracted.sensitivity_reasons).lower() 
               for kw in ['password', 'key', 'token', 'secret']):
            severity = "high"
        elif any(kw in " ".join(extracted.sensitivity_reasons).lower()
                for kw in ['suspicious command', 'encoded']):
            severity = "high"
        
        return AnalysisFinding(
            category="string",
            severity=severity,
            title=f"Sensitive String: {extracted.value[:50]}...",
            description=f"Detected sensitive {extracted.category} string. "
                       f"Reasons: {'; '.join(extracted.sensitivity_reasons)}",
            offset=extracted.offset,
            context={
                'value': extracted.value,
                'category': extracted.category,
                'string_type': extracted.string_type,
                'reasons': extracted.sensitivity_reasons,
            }
        )
    
    def get_statistics(self) -> dict:
        """Return string extraction statistics."""
        return {
            'total_strings': len(self._strings),
            'sensitive_count': self._sensitive_count,
            'categories': dict(self._category_counter),
            'by_type': dict(Counter(s.string_type for s in self._strings)),
        }
    
    def get_strings(self, category: Optional[str] = None) -> list[ExtractedString]:
        """Get extracted strings, optionally filtered by category."""
        if category:
            return [s for s in self._strings if s.category == category]
        return self._strings.copy()
