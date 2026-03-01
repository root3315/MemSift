"""
File System Scanner Plugin

Scans memory dumps for file system artifacts including:
- File paths and names
- File system structures (MFT entries, inodes)
- Recently accessed files
- Suspicious file operations
- Deleted file remnants
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from collections import Counter

from ..core.analyzer import AnalysisPlugin, AnalysisFinding


@dataclass(slots=True)
class FileArtifact:
    """Represents a file system-related artifact found in memory."""
    artifact_type: str  # path, mft, inode, deleted, suspicious
    path: str
    offset: int
    file_type: str = "unknown"  # executable, document, script, archive, etc.
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)


class FileSystemScanner(AnalysisPlugin):
    """
    Scans memory for file system artifacts.

    Detects file paths, file system structures, recently accessed files,
    and suspicious file operations that may indicate malicious activity.
    """

    name = "filesystem_scanner"
    description = "Scan for file system artifacts and suspicious file operations"
    version = "1.0.0"

    # File path patterns
    PATH_PATTERNS = {
        'windows': re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'),
        'windows_unc': re.compile(r'\\\\[A-Za-z0-9_]+\\[^\s<>"|?*]+'),
        'unix': re.compile(r'/(?:usr|home|var|tmp|etc|opt|root|bin|sbin|lib|boot|mnt|media)[^\s]*'),
        'unix_absolute': re.compile(r'/[a-zA-Z0-9_./-]{3,}'),
    }

    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = {
        '.exe': 'Executable',
        '.dll': 'Dynamic Library',
        '.sys': 'System Driver',
        '.bat': 'Batch Script',
        '.cmd': 'Command Script',
        '.ps1': 'PowerShell Script',
        '.vbs': 'VBScript',
        '.js': 'JavaScript',
        '.jse': 'Encoded JavaScript',
        '.wsf': 'Windows Script File',
        '.wsh': 'Windows Script Host',
        '.msi': 'Windows Installer',
        '.msp': 'Windows Installer Patch',
        '.scr': 'Screen Saver (Executable)',
        '.pif': 'Program Information File',
        '.com': 'Command Executable',
        '.hta': 'HTML Application',
        '.lnk': 'Shortcut (potential dropper)',
        '.reg': 'Registry Script',
    }

    # Malicious filename patterns
    MALICIOUS_FILENAME_PATTERNS = [
        re.compile(r'(?i)mimikatz'),
        re.compile(r'(?i)metasploit'),
        re.compile(r'(?i)meterpreter'),
        re.compile(r'(?i)cobalt.*strike'),
        re.compile(r'(?i)empire'),
        re.compile(r'(?i)power(spell|view)'),
        re.compile(r'(?i)bloodhound'),
        re.compile(r'(?i)lazagne'),
        re.compile(r'(?i)pwdump'),
        re.compile(r'(?i)procdump'),
        re.compile(r'(?i)seatbelt'),
        re.compile(r'(?i)sharpup'),
        re.compile(r'(?i)ghostpack'),
        re.compile(r'(?i)redteam'),
        re.compile(r'(?i)payload'),
        re.compile(r'(?i)dropper'),
        re.compile(r'(?i)loader'),
        re.compile(r'(?i)stealer'),
        re.compile(r'(?i)rat[_-]?' ),
        re.compile(r'(?i)backdoor'),
    ]

    # Suspicious file paths
    SUSPICIOUS_PATHS = [
        r'(?i)\\temp\\',
        r'(?i)\\tmp\\',
        r'(?i)\\appdata\\local\\temp',
        r'(?i)\\appdata\\roaming\\',
        r'(?i)\\programdata\\',
        r'(?i)\\users\\public\\',
        r'(?i)\\windows\\temp\\',
        r'(?i)/tmp/',
        r'(?i)/var/tmp/',
        r'(?i)/dev/shm/',
    ]

    # File system structure signatures
    FS_SIGNATURES = {
        b'NTFS': "NTFS File System",
        b'FAT': "FAT File System",
        b'EXT': "EXT File System",
        b'HFS+': "HFS+ File System",
        b'APFS': "APFS File System",
    }

    # MFT entry signature (FILE)
    MFT_SIGNATURE = b'FILE'
    # Deleted file marker in MFT
    DELETED_MFT_MARKER = b'BAAD'

    def __init__(self):
        super().__init__()
        self._artifacts: list[FileArtifact] = []
        self._path_count = 0
        self._suspicious_count = 0
        self._deleted_count = 0
        self._extension_counter: Counter = Counter()

    def analyze(self) -> list[AnalysisFinding]:
        """Scan memory for file system artifacts."""
        findings = []
        self._artifacts = []
        self._path_count = 0
        self._suspicious_count = 0
        self._deleted_count = 0
        self._extension_counter = Counter()

        if self._parser is None:
            return findings

        # Search for file system signatures
        findings.extend(self._search_fs_signatures())

        # Search for MFT entries
        findings.extend(self._search_mft_entries())

        # Extract file paths from strings
        findings.extend(self._extract_file_paths())

        # Search for suspicious files
        findings.extend(self._search_suspicious_files())

        return findings

    def _search_fs_signatures(self) -> list[AnalysisFinding]:
        """Search for file system structure signatures."""
        findings = []

        for signature, name in self.FS_SIGNATURES.items():
            for offset in self._parser.find_pattern(signature, 0, min(0x10000000, self._parser.size)):
                artifact = FileArtifact(
                    artifact_type='filesystem',
                    path=f"[{name}]",
                    offset=offset,
                    file_type="filesystem_structure",
                )
                self._artifacts.append(artifact)

                findings.append(AnalysisFinding(
                    category="filesystem",
                    severity="info",
                    title=f"File System Signature: {name}",
                    description=f"Found {name} signature at offset {hex(offset)}.",
                    offset=offset,
                    context={
                        'signature_type': name,
                        'signature_hex': signature.hex(),
                    }
                ))

                # Limit findings
                if len([f for f in findings if name in f.title]) >= 3:
                    break

        return findings

    def _search_mft_entries(self) -> list[AnalysisFinding]:
        """Search for MFT (Master File Table) entries."""
        findings = []

        # Search for MFT entries (FILE signature)
        for offset in self._parser.find_pattern(self.MFT_SIGNATURE, 0, min(0x10000000, self._parser.size)):
            self._path_count += 1

            # Try to read filename from MFT entry (simplified)
            try:
                context = self._parser.read_at(offset, 64)
                # Look for filename in MFT entry (simplified heuristic)
                filename = self._extract_filename_from_mft(context)
            except Exception:
                filename = "unknown"

            artifact = FileArtifact(
                artifact_type='mft',
                path=filename,
                offset=offset,
                file_type="ntfs_entry",
            )
            self._artifacts.append(artifact)

        # Search for deleted file markers (BAAD)
        for offset in self._parser.find_pattern(self.DELETED_MFT_MARKER, 0, min(0x10000000, self._parser.size)):
            self._deleted_count += 1

            artifact = FileArtifact(
                artifact_type='deleted',
                path="[Deleted MFT Entry]",
                offset=offset,
                file_type="deleted_entry",
                is_suspicious=True,
                suspicion_reasons=["Deleted file system entry"],
            )
            self._artifacts.append(artifact)

            findings.append(AnalysisFinding(
                category="filesystem",
                severity="low",
                title="Deleted File System Entry Detected",
                description=f"Found deleted MFT entry marker at offset {hex(offset)}. "
                           f"This may indicate file deletion or anti-forensics activity.",
                offset=offset,
                context={
                    'entry_type': 'deleted_mft',
                }
            ))

            # Limit deleted findings
            if self._deleted_count >= 20:
                break

        return findings

    def _extract_file_paths(self) -> list[AnalysisFinding]:
        """Extract file paths from memory strings."""
        findings = []

        for offset, string in self._parser.get_strings(min_length=5):
            for path_type, pattern in self.PATH_PATTERNS.items():
                match = pattern.search(string)
                if match:
                    path = match.group(0)
                    self._path_count += 1

                    # Determine file type from extension
                    file_type = self._get_file_type(path)
                    ext = self._get_extension(path)
                    if ext:
                        self._extension_counter[ext] += 1

                    # Check if suspicious
                    is_suspicious, reasons = self._check_path_suspicion(path, file_type)

                    artifact = FileArtifact(
                        artifact_type='path',
                        path=path,
                        offset=offset,
                        file_type=file_type,
                        is_suspicious=is_suspicious,
                        suspicion_reasons=reasons,
                    )
                    self._artifacts.append(artifact)

                    if is_suspicious:
                        self._suspicious_count += 1
                        findings.append(self._create_finding(artifact))

                    break  # Only match first pattern

        return findings

    def _search_suspicious_files(self) -> list[AnalysisFinding]:
        """Search for suspicious file patterns."""
        findings = []

        for offset, string in self._parser.get_strings(min_length=4):
            # Check for malicious filename patterns
            for pattern in self.MALICIOUS_FILENAME_PATTERNS:
                if pattern.search(string):
                    artifact = FileArtifact(
                        artifact_type='suspicious',
                        path=string[:200],
                        offset=offset,
                        file_type="potential_malware",
                        is_suspicious=True,
                        suspicion_reasons=[f"Malicious filename pattern: {pattern.pattern}"],
                    )
                    self._artifacts.append(artifact)

                    findings.append(AnalysisFinding(
                        category="filesystem",
                        severity="critical",
                        title="Potential Malware File Detected",
                        description=f"Found filename matching known malware pattern: {string[:80]}...",
                        offset=offset,
                        context={
                            'filename': string[:200],
                            'pattern': pattern.pattern,
                        }
                    ))
                    break

            # Check for suspicious paths
            for suspicious_path in self.SUSPICIOUS_PATHS:
                if re.search(suspicious_path, string):
                    file_type = self._get_file_type(string)
                    artifact = FileArtifact(
                        artifact_type='suspicious',
                        path=string[:200],
                        offset=offset,
                        file_type=file_type,
                        is_suspicious=True,
                        suspicion_reasons=["Suspicious file path location"],
                    )
                    self._artifacts.append(artifact)

                    findings.append(AnalysisFinding(
                        category="filesystem",
                        severity="medium",
                        title="Suspicious File Path Detected",
                        description=f"Found file in suspicious location: {string[:80]}...",
                        offset=offset,
                        context={
                            'path': string[:200],
                            'suspicious_pattern': suspicious_path,
                        }
                    ))
                    break

        return findings

    def _extract_filename_from_mft(self, data: bytes) -> str:
        """Extract filename from MFT entry (simplified)."""
        # Look for Unicode filename in MFT entry
        try:
            # MFT filenames are stored as Unicode
            for i in range(len(data) - 2):
                if data[i] == 0 and data[i+1] != 0:
                    # Found potential Unicode string
                    end = data.find(b'\x00\x00', i)
                    if end == -1:
                        end = len(data)
                    filename = data[i:end].decode('utf-16-le', errors='ignore')
                    if filename and len(filename) > 1:
                        return filename.strip()
        except Exception:
            pass
        return "unknown"

    def _get_file_type(self, path: str) -> str:
        """Determine file type from path."""
        ext = self._get_extension(path).lower()

        if ext in ['.exe', '.dll', '.sys', '.com', '.scr', '.pif', '.msi', '.msp']:
            return 'executable'
        elif ext in ['.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse', '.wsf', '.wsh', '.hta']:
            return 'script'
        elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']:
            return 'archive'
        elif ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.txt', '.rtf']:
            return 'document'
        elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg']:
            return 'image'
        elif ext in ['.mp3', '.wav', '.avi', '.mp4', '.mkv', '.wmv']:
            return 'media'
        elif ext in ['.lnk']:
            return 'shortcut'
        elif ext in ['.reg']:
            return 'registry'
        elif ext in ['.key', '.pem', '.crt', '.p12', '.pfx']:
            return 'certificate'
        else:
            return 'unknown'

    def _get_extension(self, path: str) -> str:
        """Extract file extension from path."""
        # Get the filename part
        filename = path.split('\\')[-1].split('/')[-1]
        if '.' in filename:
            return '.' + filename.rsplit('.', 1)[-1]
        return ''

    def _check_path_suspicion(self, path: str, file_type: str) -> tuple[bool, list[str]]:
        """Check if a file path is suspicious."""
        reasons = []
        is_suspicious = False

        # Check extension
        ext = self._get_extension(path).lower()
        if ext in self.SUSPICIOUS_EXTENSIONS:
            is_suspicious = True
            reasons.append(f"Suspicious extension: {ext} ({self.SUSPICIOUS_EXTENSIONS[ext]})")

        # Check path location
        for suspicious_path in self.SUSPICIOUS_PATHS:
            if re.search(suspicious_path, path):
                is_suspicious = True
                reasons.append("Suspicious path location")
                break

        # Check for malicious patterns
        for pattern in self.MALICIOUS_FILENAME_PATTERNS:
            if pattern.search(path):
                is_suspicious = True
                reasons.append(f"Malicious filename pattern")
                break

        # Executable in temp location is very suspicious
        if file_type == 'executable':
            for temp_pattern in [r'(?i)\\temp\\', r'(?i)/tmp/', r'(?i)\\appdata\\local\\temp']:
                if re.search(temp_pattern, path):
                    is_suspicious = True
                    reasons.append("Executable in temporary location")
                    break

        return is_suspicious, reasons

    def _create_finding(self, artifact: FileArtifact) -> AnalysisFinding:
        """Create an analysis finding for a suspicious file artifact."""
        severity = "medium"
        if artifact.file_type == 'executable' and any('temp' in r.lower() for r in artifact.suspicion_reasons):
            severity = "high"
        if any('malicious' in r.lower() for r in artifact.suspicion_reasons):
            severity = "critical"

        return AnalysisFinding(
            category="filesystem",
            severity=severity,
            title=f"Suspicious File: {artifact.path[:50]}...",
            description=f"Detected suspicious file artifact. Type: {artifact.file_type}. "
                       f"Reasons: {'; '.join(artifact.suspicion_reasons)}",
            offset=artifact.offset,
            context={
                'artifact_type': artifact.artifact_type,
                'path': artifact.path,
                'file_type': artifact.file_type,
                'reasons': artifact.suspicion_reasons,
            }
        )

    def get_statistics(self) -> dict:
        """Return file system scanning statistics."""
        artifact_types = Counter(a.artifact_type for a in self._artifacts)
        file_types = Counter(a.file_type for a in self._artifacts)
        return {
            'total_artifacts': len(self._artifacts),
            'path_count': self._path_count,
            'suspicious_count': self._suspicious_count,
            'deleted_entries': self._deleted_count,
            'by_type': dict(artifact_types),
            'by_file_type': dict(file_types),
            'top_extensions': dict(self._extension_counter.most_common(10)),
        }

    def get_artifacts(self) -> list[FileArtifact]:
        """Get list of detected file artifacts."""
        return self._artifacts.copy()
