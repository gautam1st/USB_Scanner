r"""Configuration and persistent local settings for USB-Guard SOC.

API keys are never hardcoded in source control. They are loaded from either:
1. The VT_API_KEY environment variable, or
2. A local user settings file in %LOCALAPPDATA%\USB_Guard_SOC\settings.json.
"""

import json
import os
from pathlib import Path


APP_NAME = "USB-Guard SOC"
APP_VERSION = "2.0.0"
APP_REG_NAME = "USBGuardSOC"
SINGLE_INSTANCE_MUTEX_NAME = r"Global\USBGuardSOC_SingleInstance_Mutex"

APP_DATA_DIR = (
    Path(os.getenv("LOCALAPPDATA", str(Path.home()))) / "USB_Guard_SOC"
)
SETTINGS_FILE_PATH = APP_DATA_DIR / "settings.json"
VT_CACHE_FILE_PATH = APP_DATA_DIR / "vt_hash_cache.json"

QUARANTINE_DIR_NAME = ".usb_quarantine"
QUARANTINE_MANIFEST_NAME = "manifest.json"
QUARANTINE_EXTENSION = ".quarantined"

# Primary SIEM-ready JSONL log path on Windows, with user-writable fallback
FALLBACK_LOG_FILE_PATH = str(APP_DATA_DIR / "logs" / "usb_security_events.json")
LOG_FILE_PATH = (
    r"C:\ProgramData\USB_Guard_SOC\logs\usb_security_events.json"
    if os.name == "nt"
    else FALLBACK_LOG_FILE_PATH
)

# VirusTotal API v3 settings (Public API free tier: 4 req/min, 500 req/day)
VT_API_URL = "https://www.virustotal.com/api/v3/files"
VT_TIMEOUT_SECONDS = 15
VT_MAX_RATE_LIMIT_RETRIES = 2
VT_MAX_RETRY_AFTER_SECONDS = 30
VT_FREE_TIER_MAX_PER_MINUTE = 4
VT_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days

# USB monitoring & local heuristic analysis settings
USB_POLL_INTERVAL_MS = 2000
MAX_SCRIPT_INSPECT_BYTES = 512 * 1024  # 512 KB
MAX_ENTROPY_SAMPLE_BYTES = 2 * 1024 * 1024  # 2 MB
HIGH_ENTROPY_THRESHOLD = 7.25

# High-risk file extensions commonly abused by USB malware & worms
SCAN_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".pif",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".lnk",
    ".jar",
    ".reg",
    ".inf",
    ".docm",
    ".xlsm",
    ".pptm",
}

SCRIPT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".inf",
    ".reg",
}

BINARY_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".pif",
    ".msi",
}

DECOY_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".jpg",
    ".jpeg",
    ".png",
    ".mp4",
    ".mp3",
    ".txt",
    ".zip",
    ".rar",
}

DEFAULT_SETTINGS = {
    "vt_api_key": "",
    "auto_scan": True,
    "auto_quarantine": False,
    "vt_respect_free_tier_pacing": True,
}


def load_settings():
    """Load user settings from local app data, merged with defaults."""
    settings = dict(DEFAULT_SETTINGS)
    if SETTINGS_FILE_PATH.exists():
        try:
            loaded = json.loads(SETTINGS_FILE_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                settings.update(loaded)
        except (OSError, ValueError):
            pass
    return settings


def save_settings(updates):
    """Persist updated user settings outside the repository."""
    settings = load_settings()
    settings.update(updates)
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = SETTINGS_FILE_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    tmp_path.replace(SETTINGS_FILE_PATH)
    return settings


def get_vt_api_key():
    """Return VirusTotal API key from environment variable or local settings."""
    env_key = os.getenv("VT_API_KEY", "").strip()
    if env_key:
        return env_key
    return str(load_settings().get("vt_api_key", "")).strip()


def save_vt_api_key(api_key):
    """Save VirusTotal API key to local user settings."""
    save_settings({"vt_api_key": api_key.strip()})
