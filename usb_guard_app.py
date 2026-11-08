"""Packaged entry point for USB Guard.

The application is intentionally launched by the installed executable, not by
USB autorun. Windows starts it at the user's login and the monitor then watches
for newly mounted removable drives.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from main import main


if __name__ == "__main__":
    main()
