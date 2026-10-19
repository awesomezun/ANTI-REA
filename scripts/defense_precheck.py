"""Absolute-path-safe scheduled precheck; idle checks never invoke a model."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from antirea.defense_loop import main

if __name__ == "__main__":
    raise SystemExit(main(["precheck"]))
