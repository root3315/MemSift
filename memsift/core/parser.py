"""
Memory Parser Module

Handles parsing of raw memory dumps and memory image files.
Supports multiple memory dump formats and provides structured access to memory regions.
"""

from __future__ import annotations

import io
import mmap
import struct
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path


class MemoryFormat(Enum):
    """Supported memory dump formats."""
    RAW = auto()
    ELF = auto()
    PE = auto()
    UNKNOWN = auto()


@dataclass(frozen=True)
class MemoryRegion:
    """Represents a contiguous memory region."""
    start: int
    end: int
    permissions: str
    path: str = ""
    data_offset: int = 0
    
    @property
    def size(self) -> int:
        return self.end - self.start
    
    @property
    def is_readable(self) -> bool:
        return 'r' in self.permissions.lower()
    
    @property
    def is_writable(self) -> bool:
        return 'w' in self.permissions.lower()
    
    @property
    def is_executable(self) -> bool:
        return 'x' in self.permissions.lower()
    
    def contains(self, address: int) -> bool:
        """Check if an address falls within this region."""
        return self.start <= address < self.end
    
    def offset_of(self, address: int) -> int | None:
        """Get the offset within this region for an address."""
        if self.contains(address):
            return address - self.start + self.data_offset
        return None


@dataclass
class MemoryDumpInfo:
    """Metadata about a memory dump."""
    format: MemoryFormat
    size: int
    architecture: str = "unknown"
    os_type: str = "unknown"
    regions: list[MemoryRegion] = field(default_factory=list)
    timestamp: str | None = None
    additional_info: dict = field(default_factory=dict)


class MemoryParser:
    """
    Parser for memory dump files.

    Supports raw dumps, ELF core dumps, and other formats.
    Provides memory-mapped access for efficient large file handling.
    """

    # ELF magic number
    ELF_MAGIC = b'\x7fELF'
    # Common page sizes
    PAGE_SIZES = [4096, 8192, 16384, 65536]

    def __init__(self, filepath: str | Path):
        self.filepath = Path(filepath)
        self._mmap: mmap.mmap | None = None
        self._file: io.BufferedReader | None = None
        self._info: MemoryDumpInfo | None = None
        
    @property
    def info(self) -> MemoryDumpInfo:
        """Get parsed memory dump information."""
        if self._info is None:
            self._info = self._parse_header()
        return self._info
    
    @property
    def size(self) -> int:
        """Get the size of the memory dump."""
        return self.filepath.stat().st_size
    
    @contextmanager
    def open(self):
        """Context manager for memory-mapped file access.
        
        Raises:
            FileNotFoundError: If the memory dump file does not exist.
            PermissionError: If the file cannot be read due to permissions.
            OSError: If memory mapping fails.
        """
        self._file = None
        self._mmap = None
        try:
            self._file = open(self.filepath, 'rb')
            self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
            yield self
        except FileNotFoundError:
            self.close()
            raise
        except PermissionError:
            self.close()
            raise
        except OSError as e:
            self.close()
            raise OSError(f"Failed to memory-map file {self.filepath}: {e}") from e
        except Exception:
            self.close()
            raise
    
    def close(self) -> None:
        """Close memory-mapped file."""
        if self._mmap:
            self._mmap.close()
            self._mmap = None
        if self._file:
            self._file.close()
            self._file = None
    
    def read_at(self, offset: int, size: int) -> bytes:
        """Read bytes at a specific offset."""
        if self._mmap is None:
            raise RuntimeError("File not opened. Use 'with parser.open()' context manager.")
        if offset + size > len(self._mmap):
            raise ValueError(f"Read exceeds file bounds: offset={offset}, size={size}")
        self._mmap.seek(offset)
        return self._mmap.read(size)
    
    def read_string_at(self, offset: int, max_length: int = 256) -> str:
        """Read a null-terminated string at offset."""
        data = self.read_at(offset, max_length)
        null_pos = data.find(b'\x00')
        if null_pos != -1:
            data = data[:null_pos]
        try:
            return data.decode('utf-8', errors='replace')
        except Exception:
            return data.decode('latin-1', errors='replace')
    
    def find_pattern(self, pattern: bytes, start: int = 0, end: int | None = None) -> Iterator[int]:
        """Find all occurrences of a byte pattern."""
        if self._mmap is None:
            raise RuntimeError("File not opened. Use 'with parser.open()' context manager.")
        
        end = end or len(self._mmap)
        pos = start
        
        while True:
            self._mmap.seek(pos)
            chunk = self._mmap.read(end - pos)
            idx = chunk.find(pattern)
            if idx == -1:
                break
            yield pos + idx
            pos += idx + 1
    
    def _parse_header(self) -> MemoryDumpInfo:
        """Parse the memory dump header to determine format and metadata.
        
        Returns:
            MemoryDumpInfo containing format and metadata.
        """
        with open(self.filepath, 'rb') as f:
            magic = f.read(16)

        # Detect format
        if magic.startswith(self.ELF_MAGIC):
            fmt = MemoryFormat.ELF
            info = self._parse_elf_header()
        else:
            fmt = MemoryFormat.RAW
            info = self._parse_raw_header()

        info.format = fmt
        return info
    
    def _parse_elf_header(self) -> MemoryDumpInfo:
        """Parse ELF core dump header."""
        info = MemoryDumpInfo(
            format=MemoryFormat.ELF,
            size=self.size,
            architecture="unknown",
            os_type="linux"
        )
        
        with open(self.filepath, 'rb') as f:
            # ELF header parsing
            f.seek(4)  # After magic
            ei_class = struct.unpack('B', f.read(1))[0]  # 32 or 64 bit
            ei_data = struct.unpack('B', f.read(1))[0]  # Endianness
            
            info.architecture = "x64" if ei_class == 2 else "x86"
            endian = '<' if ei_data == 1 else '>'
            
            f.seek(16)
            e_type = struct.unpack(f'{endian}H', f.read(2))[0]
            
            if e_type == 4:  # ET_CORE
                info.additional_info['type'] = 'core_dump'
            
            # Parse program headers for memory regions
            f.seek(54 if ei_class == 2 else 42)  # e_phoff
            e_phoff = struct.unpack(f'{endian}Q' if ei_class == 2 else f'{endian}I', f.read(8 if ei_class == 2 else 4))[0]
            e_phentsize = struct.unpack(f'{endian}H', f.read(2))[0]
            e_phnum = struct.unpack(f'{endian}H', f.read(2))[0]
            
            # Parse PT_LOAD segments as memory regions
            for i in range(e_phnum):
                f.seek(e_phoff + i * e_phentsize)
                p_type = struct.unpack(f'{endian}I', f.read(4))[0]
                
                if p_type == 1:  # PT_LOAD
                    if ei_class == 2:
                        f.read(4)  # p_flags (32-bit padding)
                        p_offset = struct.unpack(f'{endian}Q', f.read(8))[0]
                        p_vaddr = struct.unpack(f'{endian}Q', f.read(8))[0]
                        p_filesz = struct.unpack(f'{endian}Q', f.read(8))[0]
                        p_memsz = struct.unpack(f'{endian}Q', f.read(8))[0]
                        p_flags = struct.unpack(f'{endian}I', f.read(4))[0]
                    else:
                        p_offset = struct.unpack(f'{endian}I', f.read(4))[0]
                        p_vaddr = struct.unpack(f'{endian}I', f.read(4))[0]
                        p_filesz = struct.unpack(f'{endian}I', f.read(4))[0]
                        p_memsz = struct.unpack(f'{endian}I', f.read(4))[0]
                        p_flags = struct.unpack(f'{endian}I', f.read(4))[0]
                    
                    perms = ''
                    perms += 'r' if p_flags & 4 else '-'
                    perms += 'w' if p_flags & 2 else '-'
                    perms += 'x' if p_flags & 1 else '-'
                    
                    region = MemoryRegion(
                        start=p_vaddr,
                        end=p_vaddr + p_memsz,
                        permissions=perms,
                        data_offset=p_offset
                    )
                    info.regions.append(region)
        
        return info
    
    def _parse_raw_header(self) -> MemoryDumpInfo:
        """Parse raw memory dump (heuristic analysis).
        
        Returns:
            MemoryDumpInfo with raw dump metadata.
        """
        info = MemoryDumpInfo(
            format=MemoryFormat.RAW,
            size=self.size,
            architecture="unknown",
            os_type="unknown"
        )

        # Create a single region for raw dumps
        info.regions.append(MemoryRegion(
            start=0,
            end=self.size,
            permissions='rw-',
            data_offset=0
        ))
        
        # Architecture detection is done lazily when parser is opened
        # to avoid opening/closing the file multiple times
        info.additional_info['_detect_arch_on_open'] = True
        
        return info
    
    def detect_architecture(self) -> str:
        """Detect architecture from memory patterns. Call with parser open.
        
        Returns:
            Architecture string (x64, x86, or unknown).
        """
        if self._mmap is None:
            return "unknown"

        if self._detect_x64_patterns():
            return "x64"
        elif self._detect_x86_patterns():
            return "x86"
        return "unknown"
    
    def _detect_x64_patterns(self) -> bool:
        """Detect x64 architecture patterns.
        
        Returns:
            True if x64 patterns are detected.
        """
        patterns = [
            b'\x48\x89\xe5',  # mov rbp, rsp
            b'\x48\x83\xec',  # sub rsp, imm8
            b'\x4c\x8d',      # lea rXX,
        ]
        for pattern in patterns:
            try:
                next(self.find_pattern(pattern, 0, min(0x100000, self.size)))
                return True
            except StopIteration:
                continue
        return False
    
    def _detect_x86_patterns(self) -> bool:
        """Detect x86 architecture patterns.
        
        Returns:
            True if x86 patterns are detected.
        """
        patterns = [
            b'\x55\x89\xe5',  # push ebp; mov ebp, esp
            b'\x83\xec',      # sub esp, imm8
        ]
        for pattern in patterns:
            try:
                next(self.find_pattern(pattern, 0, min(0x100000, self.size)))
                return True
            except StopIteration:
                continue
        return False
    
    def get_strings(self, min_length: int = 4) -> Iterator[tuple[int, str]]:
        """Extract printable strings from memory.
        
        Args:
            min_length: Minimum string length to extract.
            
        Yields:
            Tuples of (offset, string) for each printable string found.
        """
        if self._mmap is None:
            raise RuntimeError("File not opened. Use 'with parser.open()' context manager.")

        current_string = bytearray()
        current_offset = 0

        for i in range(len(self._mmap)):
            byte = self._mmap[i]
            byte_val = byte if isinstance(byte, int) else byte[0]  # Handle bytes vs int
            if 32 <= byte_val <= 126:  # Printable ASCII
                if not current_string:
                    current_offset = i
                current_string.append(byte_val)
            else:
                if len(current_string) >= min_length:
                    yield (current_offset, current_string.decode('ascii'))
                current_string = bytearray()

        # Handle string at end of file
        if len(current_string) >= min_length:
            yield (current_offset, current_string.decode('ascii'))
