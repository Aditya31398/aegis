"""`python -m aegis` is the same as the `aegis` command."""
import sys

from .conformance.cli import main

sys.exit(main())
