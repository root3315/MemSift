"""Pytest configuration and fixtures for MemSift tests."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_file() -> Path:
    """Create a temporary file that is cleaned up after the test."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        filepath = Path(f.name)
    yield filepath
    filepath.unlink()


@pytest.fixture
def temp_binary_file() -> Path:
    """Create a temporary binary file with test data."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b'\x00' * 50)
        f.write(b'test data\x00')
        f.write(b'\x00' * 50)
        filepath = Path(f.name)
    yield filepath
    filepath.unlink()


@pytest.fixture
def temp_text_file() -> Path:
    """Create a temporary text file with test content."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("Hello World\n")
        f.write("Test content\n")
        filepath = Path(f.name)
    yield filepath
    filepath.unlink()
