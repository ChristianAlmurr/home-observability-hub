"""Sentinel: the threat-scanning engine of Home Observability Hub (docs/CONTRACT.md, version 3).

Deterministic scanners that only read. Python 3.9, standard library only.

    python3 -m sentinel scan [scanner]     # run once from a terminal
    python3 -m sentinel status             # print the summary
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from .util import Config  # noqa: E402,F401
from .store import Store  # noqa: E402,F401
from .engine import Engine, SCANNERS  # noqa: E402,F401
