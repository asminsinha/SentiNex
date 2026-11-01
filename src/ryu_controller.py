"""
SentiNex SDN Ryu Controller Entry Point.
Direct entry point for ryu-manager.
Usage:
    ryu-manager src/ryu_controller.py
    python3 run_ryu.py src/ryu_controller.py
"""

import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
src_dir = os.path.join(BASE_DIR, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from ryu_sentinex_app import SentiNexRyuController, SentiNexRyuApp

# Expose SentiNexRyuController as primary RyuApp for ryu-manager
__all__ = ['SentiNexRyuController', 'SentiNexRyuApp']
