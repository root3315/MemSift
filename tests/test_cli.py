"""Tests for MemSift CLI module."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from memsift.cli import (
    main,
    create_parser,
    cmd_analyze,
    cmd_info,
    cmd_strings,
    cmd_search,
    _parse_search_pattern,
    _validate_file_exists,
)


@pytest.fixture
def temp_memory_file() -> Path:
    """Create a temporary memory dump file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.dump') as f:
        f.write(b'\x00' * 100)
        f.write(b'mimikatz\x00')
        f.write(b'\x00' * 100)
        filepath = Path(f.name)
    yield filepath
    filepath.unlink()


class TestCreateParser:
    """Tests for argument parser creation."""

    def test_parser_creation(self) -> None:
        """Test parser is created correctly."""
        parser = create_parser()
        assert parser is not None
        assert parser.prog == 'memsift'

    def test_parser_version(self) -> None:
        """Test version argument."""
        parser = create_parser()
        # Version action exits with code 0
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(['--version'])
        assert exc_info.value.code == 0

    def test_parser_verbose(self) -> None:
        """Test verbose argument."""
        parser = create_parser()
        args = parser.parse_args(['--verbose'])
        assert args.verbose is True

    def test_parser_no_color(self) -> None:
        """Test no-color argument."""
        parser = create_parser()
        args = parser.parse_args(['--no-color'])
        assert args.no_color is True

    def test_parser_subcommands(self) -> None:
        """Test subcommands are available."""
        parser = create_parser()
        help_text = parser.format_help()
        assert 'analyze' in help_text
        assert 'info' in help_text
        assert 'strings' in help_text
        assert 'search' in help_text


class TestValidateFileExists:
    """Tests for file validation."""

    def test_file_exists(self, temp_memory_file: Path) -> None:
        """Test validation passes for existing file."""
        assert _validate_file_exists(temp_memory_file) is True

    def test_file_not_exists(self) -> None:
        """Test validation fails for non-existent file."""
        result = _validate_file_exists(Path('/nonexistent/file'))
        assert result is False


class TestParseSearchPattern:
    """Tests for search pattern parsing."""

    def test_parse_string_pattern(self) -> None:
        """Test parsing string pattern."""
        result = _parse_search_pattern("test", is_hex=False)
        assert result == b"test"

    def test_parse_hex_pattern(self) -> None:
        """Test parsing hex pattern."""
        result = _parse_search_pattern("74 65 73 74", is_hex=True)
        assert result == b"test"

    def test_parse_hex_pattern_no_spaces(self) -> None:
        """Test parsing hex pattern without spaces."""
        result = _parse_search_pattern("74657374", is_hex=True)
        assert result == b"test"

    def test_parse_invalid_hex_pattern(self) -> None:
        """Test parsing invalid hex pattern."""
        result = _parse_search_pattern("invalid", is_hex=True)
        assert result is None


class TestCmdStrings:
    """Tests for strings command."""

    def test_cmd_strings_basic(self, temp_memory_file: Path) -> None:
        """Test basic strings extraction."""
        import argparse
        args = argparse.Namespace(
            memory_dump=temp_memory_file,
            min_length=4,
            limit=0,
            with_offsets=False,
            verbose=False
        )
        result = cmd_strings(args)
        assert result == 0

    def test_cmd_strings_with_offsets(self, temp_memory_file: Path) -> None:
        """Test strings with offsets."""
        import argparse
        args = argparse.Namespace(
            memory_dump=temp_memory_file,
            min_length=4,
            limit=0,
            with_offsets=True,
            verbose=False
        )
        result = cmd_strings(args)
        assert result == 0

    def test_cmd_strings_not_found(self) -> None:
        """Test strings command with non-existent file."""
        import argparse
        args = argparse.Namespace(
            memory_dump=Path('/nonexistent/file'),
            min_length=4,
            limit=0,
            with_offsets=False,
            verbose=False
        )
        result = cmd_strings(args)
        assert result == 1


class TestCmdSearch:
    """Tests for search command."""

    def test_cmd_search_string(self, temp_memory_file: Path) -> None:
        """Test searching for string pattern."""
        import argparse
        args = argparse.Namespace(
            memory_dump=temp_memory_file,
            pattern='mimikatz',
            hex=False,
            count=False
        )
        result = cmd_search(args)
        assert result == 0

    def test_cmd_search_hex(self, temp_memory_file: Path) -> None:
        """Test searching for hex pattern."""
        import argparse
        args = argparse.Namespace(
            memory_dump=temp_memory_file,
            pattern='6d 69 6d 69 6b 61 74 7a',  # mimikatz
            hex=True,
            count=False
        )
        result = cmd_search(args)
        assert result == 0

    def test_cmd_search_count(self, temp_memory_file: Path) -> None:
        """Test search with count only."""
        import argparse
        args = argparse.Namespace(
            memory_dump=temp_memory_file,
            pattern='mimikatz',
            hex=False,
            count=True
        )
        result = cmd_search(args)
        assert result == 0

    def test_cmd_search_not_found(self) -> None:
        """Test search with non-existent file."""
        import argparse
        args = argparse.Namespace(
            memory_dump=Path('/nonexistent/file'),
            pattern='test',
            hex=False,
            count=False
        )
        result = cmd_search(args)
        assert result == 1


class TestMain:
    """Tests for main entry point."""

    def test_main_no_command(self) -> None:
        """Test main with no command shows help."""
        result = main([])
        assert result == 0

    def test_main_version(self) -> None:
        """Test main with version flag."""
        with pytest.raises(SystemExit) as exc_info:
            main(['--version'])
        assert exc_info.value.code == 0

    def test_main_help(self) -> None:
        """Test main with help flag."""
        with pytest.raises(SystemExit) as exc_info:
            main(['--help'])
        assert exc_info.value.code == 0

    def test_main_analyze(self, temp_memory_file: Path) -> None:
        """Test main with analyze command."""
        result = main(['analyze', str(temp_memory_file), '-q'])
        # May return 0, 1, or 2 depending on findings
        assert result in (0, 1, 2)

    def test_main_info(self, temp_memory_file: Path) -> None:
        """Test main with info command."""
        result = main(['info', str(temp_memory_file)])
        assert result == 0

    def test_main_strings(self, temp_memory_file: Path) -> None:
        """Test main with strings command."""
        result = main(['strings', str(temp_memory_file), '-m', '4'])
        assert result == 0

    def test_main_search(self, temp_memory_file: Path) -> None:
        """Test main with search command."""
        result = main(['search', str(temp_memory_file), 'mimikatz'])
        assert result == 0

    def test_main_unknown_command(self) -> None:
        """Test main with unknown command."""
        with pytest.raises(SystemExit) as exc_info:
            main(['unknown'])
        assert exc_info.value.code != 0


class TestCmdAnalyze:
    """Tests for analyze command."""

    def test_cmd_analyze_basic(self, temp_memory_file: Path) -> None:
        """Test basic analysis."""
        import argparse
        args = argparse.Namespace(
            memory_dump=temp_memory_file,
            plugins=['all'],
            format='text',
            output=None,
            quiet=True,
            verbose=False,
            no_color=True
        )
        result = cmd_analyze(args)
        # May return 0, 1, or 2 depending on findings
        assert result in (0, 1, 2)

    def test_cmd_analyze_json_output(self, temp_memory_file: Path) -> None:
        """Test analysis with JSON output."""
        import argparse
        args = argparse.Namespace(
            memory_dump=temp_memory_file,
            plugins=['all'],
            format='json',
            output=None,
            quiet=True,
            verbose=False,
            no_color=True
        )
        result = cmd_analyze(args)
        assert result in (0, 1, 2)

    def test_cmd_analyze_specific_plugins(self, temp_memory_file: Path) -> None:
        """Test analysis with specific plugins."""
        import argparse
        args = argparse.Namespace(
            memory_dump=temp_memory_file,
            plugins=['processes'],
            format='text',
            output=None,
            quiet=True,
            verbose=False,
            no_color=True
        )
        result = cmd_analyze(args)
        assert result in (0, 1, 2)

    def test_cmd_analyze_not_found(self) -> None:
        """Test analyze with non-existent file."""
        import argparse
        args = argparse.Namespace(
            memory_dump=Path('/nonexistent/file'),
            plugins=['all'],
            format='text',
            output=None,
            quiet=False,
            verbose=False,
            no_color=True
        )
        result = cmd_analyze(args)
        assert result == 1

    def test_cmd_analyze_output_to_file(self, temp_memory_file: Path) -> None:
        """Test analysis with output to file."""
        import argparse
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            output_path = Path(f.name)

        try:
            args = argparse.Namespace(
                memory_dump=temp_memory_file,
                plugins=['all'],
                format='text',
                output=output_path,
                quiet=False,
                verbose=False,
                no_color=True
            )
            result = cmd_analyze(args)
            assert result in (0, 1, 2)
            assert output_path.exists()
            assert output_path.stat().st_size > 0
        finally:
            output_path.unlink()


class TestCmdInfo:
    """Tests for info command."""

    def test_cmd_info_text(self, temp_memory_file: Path) -> None:
        """Test info with text output."""
        import argparse
        args = argparse.Namespace(
            memory_dump=temp_memory_file,
            format='text',
            verbose=False
        )
        result = cmd_info(args)
        assert result == 0

    def test_cmd_info_json(self, temp_memory_file: Path) -> None:
        """Test info with JSON output."""
        import argparse
        args = argparse.Namespace(
            memory_dump=temp_memory_file,
            format='json',
            verbose=False
        )
        result = cmd_info(args)
        assert result == 0

    def test_cmd_info_not_found(self) -> None:
        """Test info with non-existent file."""
        import argparse
        args = argparse.Namespace(
            memory_dump=Path('/nonexistent/file'),
            format='text',
            verbose=False
        )
        result = cmd_info(args)
        assert result == 1
