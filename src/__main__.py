#!/usr/bin/env python3
"""
Entry point for running TMDD as a module: python -m src
"""
import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())

