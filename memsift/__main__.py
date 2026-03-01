#!/usr/bin/env python3
"""
MemSift - Memory Forensics and RAM Analysis Tool

Main entry point for the MemSift CLI.
"""

import sys
from memsift.cli import main

if __name__ == '__main__':
    sys.exit(main())
