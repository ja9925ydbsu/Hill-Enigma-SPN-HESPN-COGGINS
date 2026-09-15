"""Compatibility entry point for the current HESPN reference implementation.

The former v4 script at this path contained stale commentary about rotation
invertibility. The current construction proves R(M) = M^T J, so rotations of
an invertible seed are invertible. Import all public names from the corrected
reference implementation to preserve older command lines and imports.
"""
from hespn_reference import *  # noqa: F401,F403

if __name__ == "__main__":
    main()
