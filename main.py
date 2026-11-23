"""USB-Guard SOC - Automatic Windows USB Malware Detector & Quarantine Dashboard.

Features:
- Automatically detects newly inserted removable USB drives and scans them.
- Hybrid dual-layer detection:
    1. Instant Offline Heuristic Engine (autorun.inf, double extensions,
       hidden+system executables, suspicious .lnk commands, malicious script
       patterns, PE header spoofing, and Shannon entropy packer detection).
    2. Cloud Multi-Engine Verification via VirusTotal API v3 hash lookups
       (never uploads file contents; includes persistent local hash cache and
       free-tier 4-requests/minute sliding-window rate pacing).
- Interactive Quarantine Manager (disarm/move, restore, or permanently delete).
- One-click Windows Startup auto-launch (--minimized) and single-instance lock.
- SIEM-ready JSONL security event logging.
"""

from collections import deque
import csv
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import queue
import re
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

if os.name == "nt":
    import winreg

import config
import quarantine_utils


RUN_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"

MAJOR_VENDORS = {
    "kaspersky",
    "microsoft defender",
    "microsoft",
    "crowdstrike",
    "sophos",
    "eset-nod32",
    "bitdefender",
    "malwarebytes",
}

FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_SYSTEM = 0x04

# High-signal regex indicators for malicious USB scripts & launchers
SCRIPT_PATTERNS = [
    (
        re.compile(
            r"powershell[^\r\n]{0,120}(?:-enc|-encodedcommand|\biex\b|invoke-expression|downloadstring|frombase64string|-w\s+hidden|-windowstyle\s+hidden|bypass)",
            re.IGNORECASE,
        ),
        45,
        "Obfuscated or hidden PowerShell execution",
    ),
    (
        re.compile(
            r"\b(?:mshta|wscript|cscript|rundll32|regsvr32)\b[^\r\n]{0,120}(?:http://|https://|javascript:|vbscript:|scrobj)",
            re.IGNORECASE,
        ),
        45,
        "LOLBin script/remote payload execution",
    ),
    (
        re.compile(
            r"\bcertutil\b[^\r\n]{0,80}-urlcache|\bbitsadmin\b[^\r\n]{0,80}/transfer",
            re.IGNORECASE,
        ),
        40,
        "Living-off-the-land file downloader",
    ),
    (
        re.compile(
            r"\bvssadmin\b[^\r\n]{0,80}delete\s+shadows|\bwbadmin\b[^\r\n]{0,80}delete\s+catalog",
            re.IGNORECASE,
        ),
        60,
        "Ransomware shadow-copy deletion command",
    ),
    (
        re.compile(
            r"\breg\s+add\b[^\r\n]{0,120}(?:\\Run\b|\\RunOnce\b)|\bschtasks\b[^\r\n]{0,80}/create",
            re.IGNORECASE,
        ),
        35,
        "Windows persistence mechanism",
    ),
    (
        re.compile(
            r"\battrib\b[^\r\n]{0,60}\+h[^\r\n]{0,40}\+s|\battrib\b[^\r\n]{0,60}\+s[^\r\n]{0,40}\+h",
            re.IGNORECASE,
        ),
        35,
        "USB worm folder-hiding command (attrib +h +s)",
    ),
    (
        re.compile(
            r"(?:WScript\.Shell|Scripting\.FileSystemObject|Shell\.Application|ADODB\.Stream)",
            re.IGNORECASE,
        ),
        25,
        "Windows Script Host system automation object",
    ),
    (
        re.compile(
            r"\b(?:open|shellexecute|shell\\open\\command)\s*=",
            re.IGNORECASE,
        ),
        45,
        "Autorun auto-execution directive",
    ),
]

LNK_SUSPICIOUS_TOKENS = [
    (b"powershell", 40, "Shortcut invokes PowerShell"),
    (b"cmd.exe", 35, "Shortcut invokes cmd.exe"),
    (b"mshta", 45, "Shortcut invokes mshta.exe"),
    (b"wscript", 35, "Shortcut invokes wscript.exe"),
    (b"cscript", 35, "Shortcut invokes cscript.exe"),
    (b"rundll32", 35, "Shortcut invokes rundll32.exe"),
    (b"regsvr32", 35, "Shortcut invokes regsvr32.exe"),
    (b"certutil", 40, "Shortcut invokes certutil.exe"),
    (b"http://", 30, "Shortcut contains remote HTTP URL"),
    (b"https://", 25, "Shortcut contains remote HTTPS URL"),
    (b"-enc", 35, "Shortcut contains encoded command flag"),
    (b"bypass", 25, "Shortcut attempts ExecutionPolicy bypass"),
]


class DriveInfo:
    def __init__(self, root, volume_name):
        self.root = root
        self.volume_name = volume_name


# ---------------------------------------------------------------------------
# Windows Platform Helpers (Drives, Startup Registry, Single-Instance Mutex)
# ---------------------------------------------------------------------------

def acquire_single_instance_mutex():
    """Prevent duplicate background instances on Windows. Returns handle or None."""
    if os.name != "nt":
        return True
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateMutexW(
        None, False, ctypes.c_wchar_p(config.SINGLE_INSTANCE_MUTEX_NAME)
    )
    ERROR_ALREADY_EXISTS = 183
    if kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
        if handle:
            kernel32.CloseHandle(handle)
        return None
    return handle


def _volume_name(root):
    """Return a volume label, or an empty string when Windows cannot read it."""
    get_volume_information = ctypes.windll.kernel32.GetVolumeInformationW
    volume_name = ctypes.create_unicode_buffer(261)
    file_system_name = ctypes.create_unicode_buffer(261)
    serial_number = wintypes.DWORD()
    max_component_length = wintypes.DWORD()
    file_system_flags = wintypes.DWORD()
    success = get_volume_information(
        ctypes.c_wchar_p(root),
        volume_name,
        len(volume_name),
        ctypes.byref(serial_number),
        ctypes.byref(max_component_length),
        ctypes.byref(file_system_flags),
        file_system_name,
        len(file_system_name),
    )
    return volume_name.value if success else ""


def find_removable_drives():
    """Enumerate currently attached Windows drives marked as removable."""
    if os.name != "nt":
        return []

    kernel32 = ctypes.windll.kernel32
    drive_mask = kernel32.GetLogicalDrives()
    drives = []
    for index in range(26):
        if not drive_mask & (1 << index):
            continue
        root = "{}:\\".format(chr(ord("A") + index))
        # Drive type 2 == DRIVE_REMOVABLE
        if kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 2:
            drives.append(DriveInfo(root, _volume_name(root)))
    return drives


def _is_hidden_or_system(file_path):
    """Check whether a file has Windows Hidden or System attributes set."""
    if os.name != "nt":
        return False, False
    attrs = ctypes.windll.kernel32.GetFileAttributesW(
        ctypes.c_wchar_p(str(file_path))
    )
    if attrs == -1 or attrs == 0xFFFFFFFF:
        return False, False
    return bool(attrs & FILE_ATTRIBUTE_HIDDEN), bool(attrs & FILE_ATTRIBUTE_SYSTEM)


def _startup_command():
    """Build the Windows Run registry command for either .exe or .py execution."""
    if getattr(sys, "frozen", False):
        return '"{}" --minimized'.format(sys.executable)
    python_exe = Path(sys.executable)
    pythonw = python_exe.with_name("pythonw.exe")
    runner = str(pythonw if pythonw.exists() else python_exe)
    script = str(Path(__file__).resolve())
    return '"{}" "{}" --minimized'.format(runner, script)


def is_autostart_enabled():
    if os.name != "nt":
        return False
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, RUN_REG_PATH, 0, winreg.KEY_READ
        ) as key:
            winreg.QueryValueEx(key, config.APP_REG_NAME)
            return True
    except OSError:
        return False


def set_autostart(enabled):
    if os.name != "nt":
        return
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, RUN_REG_PATH, 0, winreg.KEY_SET_VALUE
    ) as key:
        if enabled:
            winreg.SetValueEx(
                key, config.APP_REG_NAME, 0, winreg.REG_SZ, _startup_command()
            )
        else:
            try:
                winreg.DeleteValue(key, config.APP_REG_NAME)
            except FileNotFoundError:
                pass


# ---------------------------------------------------------------------------
# Offline Local Heuristic Engine (Works Without Internet or VT API Quota)
# ---------------------------------------------------------------------------

def calculate_shannon_entropy(file_path):
    """Calculate Shannon entropy (0.0 to 8.0) on up to 2 MB of a file."""
    counts = [0] * 256
    with open(file_path, "rb") as handle:
        data = handle.read(config.MAX_ENTROPY_SAMPLE_BYTES)
    total = len(data)
    if total == 0:
        return 0.0
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return round(entropy, 3)


def analyze_local_heuristics(file_path):
    """Run fast, offline heuristic checks on a file.

    Returns a dict: {"score": int, "findings": list[str], "entropy": float|None}
    """
    path = Path(file_path)
    name_lower = path.name.casefold()
    suffix = path.suffix.casefold()
    score = 0
    findings = []
    entropy = None

    # 1. Classic USB worm autorun.inf
    if name_lower == "autorun.inf":
        score += 45
        findings.append("USB autorun.inf file detected (common USB worm vector)")

    # 2. Double-extension spoofing (e.g., resume.pdf.exe, photo.jpg.scr)
    suffixes = [ext.casefold() for ext in path.suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in config.SCAN_EXTENSIONS:
        if suffixes[-2] in config.DECOY_EXTENSIONS:
            score += 50
            findings.append(
                "Double-extension spoofing detected ({}{})".format(
                    suffixes[-2], suffixes[-1]
                )
            )

    # 3. Hidden / System attribute on an executable or shortcut
    is_hidden, is_system = _is_hidden_or_system(file_path)
    if is_hidden and is_system:
        score += 35
        findings.append("Hidden + System attributes set (typical USB worm stealth)")
    elif is_hidden:
        score += 15
        findings.append("Hidden attribute set on executable/script file")

    # 4. Read header bytes safely for magic-byte / LNK / script analysis
    try:
        with open(file_path, "rb") as handle:
            header = handle.read(4096)
    except OSError as exc:
        return {
            "score": score,
            "findings": findings,
            "entropy": None,
            "read_error": str(exc),
        }

    # Disguised Windows PE executable (MZ magic header on non-binary extension)
    if header.startswith(b"MZ") and suffix not in config.BINARY_EXTENSIONS:
        score += 55
        findings.append(
            "Disguised Windows executable (MZ header inside {} file)".format(
                suffix or "no-extension"
            )
        )

    # 5. Shortcut (.lnk) command-line abuse inspection
    if suffix == ".lnk":
        try:
            raw_lnk = Path(file_path).read_bytes()[:65536]
            raw_lower = raw_lnk.lower()
            utf16_ascii = (
                raw_lnk.decode("utf-16le", errors="ignore")
                .lower()
                .encode("ascii", errors="ignore")
            )
            combined = raw_lower + b"\n" + utf16_ascii
            for token, points, description in LNK_SUSPICIOUS_TOKENS:
                if token in combined:
                    score += points
                    findings.append(description)
        except OSError:
            pass

    # 6. Malicious script pattern scanning
    if suffix in config.SCRIPT_EXTENSIONS:
        try:
            with open(file_path, "rb") as handle:
                raw_script = handle.read(config.MAX_SCRIPT_INSPECT_BYTES)
            text = raw_script.decode("utf-8", errors="ignore")
            for pattern, points, description in SCRIPT_PATTERNS:
                if pattern.search(text):
                    score += points
                    findings.append(description)
        except OSError:
            pass

    # 7. High Shannon entropy (packed/encrypted PE executables)
    if suffix in config.BINARY_EXTENSIONS or header.startswith(b"MZ"):
        try:
            entropy = calculate_shannon_entropy(file_path)
            if entropy >= config.HIGH_ENTROPY_THRESHOLD:
                score += 25
                findings.append(
                    "High binary entropy ({:.2f}/8.00) - possible packed or obfuscated executable".format(
                        entropy
                    )
                )
        except OSError:
            pass

    return {
        "score": min(score, 100),
        "findings": findings,
        "entropy": entropy,
    }


# ---------------------------------------------------------------------------
# VirusTotal API v3 Client with Persistent Hash Cache & Sliding-Window Pacing
# ---------------------------------------------------------------------------

class VirusTotalClient:
    """Thread-safe VirusTotal v3 hash lookup client with caching & pacing."""

    def __init__(self):
        self._lock = threading.Lock()
        self._recent_calls = deque()
        self._cache = self._load_cache()

    @staticmethod
    def _load_cache():
        if not config.VT_CACHE_FILE_PATH.exists():
            return {}
        try:
            data = json.loads(config.VT_CACHE_FILE_PATH.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_cache(self):
        try:
            config.APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
            tmp = config.VT_CACHE_FILE_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._cache), encoding="utf-8")
            tmp.replace(config.VT_CACHE_FILE_PATH)
        except OSError:
            pass

    def _get_cached(self, sha256):
        with self._lock:
            entry = self._cache.get(sha256)
            if not entry:
                return None
            age = time.time() - float(entry.get("cached_at", 0))
            if age > config.VT_CACHE_TTL_SECONDS:
                self._cache.pop(sha256, None)
                return None
            result = dict(entry["result"])
            result["from_cache"] = True
            return result

    def _store_cached(self, sha256, result):
        if result["status"] not in {"Safe", "Vulnerable", "Suspicious", "Unknown"}:
            return
        with self._lock:
            clean_copy = dict(result)
            clean_copy["from_cache"] = False
            self._cache[sha256] = {
                "cached_at": time.time(),
                "result": clean_copy,
            }
            self._save_cache()

    def _pace_free_tier(self, cancel_event, status_callback=None):
        """Ensure <= 4 uncached VT requests per 60 seconds when pacing is enabled."""
        with self._lock:
            now = time.monotonic()
            while self._recent_calls and (now - self._recent_calls[0]) >= 60.5:
                self._recent_calls.popleft()
            if len(self._recent_calls) < config.VT_FREE_TIER_MAX_PER_MINUTE:
                self._recent_calls.append(now)
                return True
            wait_seconds = max(1.0, 60.5 - (now - self._recent_calls[0]))

        end_time = time.monotonic() + wait_seconds
        while time.monotonic() < end_time:
            if cancel_event.is_set():
                return False
            remaining = int(math.ceil(end_time - time.monotonic()))
            if status_callback:
                status_callback(
                    "VirusTotal free-tier pacing: waiting {}s before next cloud lookup...".format(
                        remaining
                    )
                )
            time.sleep(min(0.5, max(0.1, end_time - time.monotonic())))

        with self._lock:
            now = time.monotonic()
            while self._recent_calls and (now - self._recent_calls[0]) >= 60.5:
                self._recent_calls.popleft()
            self._recent_calls.append(now)
        return True

    def lookup_hash(self, sha256, cancel_event, respect_pacing=True, status_callback=None):
        """Look up a SHA-256 hash on VirusTotal (never uploads file contents)."""
        cached = self._get_cached(sha256)
        if cached is not None:
            return cached

        api_key = config.get_vt_api_key()
        if not api_key:
            return _empty_vt_result(
                "Not checked",
                "No VirusTotal API key set (running local heuristics only).",
            )

        if respect_pacing:
            proceed = self._pace_free_tier(cancel_event, status_callback)
            if not proceed:
                return _empty_vt_result("Cancelled", "Scan cancelled by user.")

        request = Request(
            "{}/{}".format(config.VT_API_URL.rstrip("/"), sha256),
            headers={"x-apikey": api_key, "Accept": "application/json"},
        )
        retries = 0
        while not cancel_event.is_set():
            try:
                with urlopen(request, timeout=config.VT_TIMEOUT_SECONDS) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                parsed = _parse_virustotal(payload)
                self._store_cached(sha256, parsed)
                return parsed
            except HTTPError as exc:
                if exc.code == 404:
                    unknown = _empty_vt_result("Unknown", "Hash not found in VirusTotal.")
                    self._store_cached(sha256, unknown)
                    return unknown
                if exc.code == 401:
                    return _empty_vt_result(
                        "Invalid API Key",
                        "VirusTotal rejected the API key (HTTP 401). Click 'Set VT API Key'.",
                    )
                if exc.code == 429 and retries < config.VT_MAX_RATE_LIMIT_RETRIES:
                    retries += 1
                    retry_after = exc.headers.get("Retry-After", "")
                    try:
                        delay = min(
                            max(int(retry_after), 1),
                            config.VT_MAX_RETRY_AFTER_SECONDS,
                        )
                    except (TypeError, ValueError):
                        delay = min(2 ** retries * 5, config.VT_MAX_RETRY_AFTER_SECONDS)
                    if status_callback:
                        status_callback(
                            "VirusTotal rate limit hit (HTTP 429); retrying in {}s...".format(
                                delay
                            )
                        )
                    if cancel_event.wait(delay):
                        return _empty_vt_result("Cancelled", "Scan cancelled by user.")
                    continue
                if exc.code == 429:
                    return _empty_vt_result(
                        "Rate limited",
                        "VirusTotal rate limit exceeded (free tier: 4/min, 500/day).",
                    )
                return _empty_vt_result(
                    "API error", "VirusTotal returned HTTP {}.".format(exc.code)
                )
            except (URLError, TimeoutError, OSError) as exc:
                return _empty_vt_result("Offline", "Network/lookup error: {}".format(exc))
            except (ValueError, KeyError, TypeError) as exc:
                return _empty_vt_result(
                    "Invalid API response",
                    "Could not parse VirusTotal response: {}".format(exc),
                )
        return _empty_vt_result("Cancelled", "Scan cancelled by user.")


def _empty_vt_result(status, error):
    return {
        "status": status,
        "malicious": 0,
        "suspicious": 0,
        "total": 0,
        "taxonomy": [],
        "vendors": [],
        "error": error,
        "from_cache": False,
    }


def _parse_virustotal(payload):
    attributes = payload["data"]["attributes"]
    stats = attributes.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(value) for value in stats.values())
    analyses = attributes.get("last_analysis_results", {})

    taxonomy = set()
    vendors = []
    for vendor, analysis in analyses.items():
        category = str(analysis.get("category", "")).casefold()
        if category not in {"malicious", "suspicious"}:
            continue
        result = analysis.get("result")
        if result:
            taxonomy.add(str(result))
        if vendor.casefold() in MAJOR_VENDORS:
            vendors.append("{}: {}".format(vendor, result or category))

    if malicious > 0:
        status = "Vulnerable"
    elif suspicious > 0:
        status = "Suspicious"
    else:
        status = "Safe"

    return {
        "status": status,
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "taxonomy": sorted(taxonomy),
        "vendors": sorted(vendors),
        "error": "",
        "from_cache": False,
    }


# ---------------------------------------------------------------------------
# SOC Logging & Combined Risk Verdict Engine
# ---------------------------------------------------------------------------

def append_json_log(event):
    """Append a structured JSONL event to ProgramData or fallback user log."""
    for candidate in (config.LOG_FILE_PATH, config.FALLBACK_LOG_FILE_PATH):
        try:
            log_path = Path(candidate)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(event, ensure_ascii=False) + "\n")
            return candidate
        except OSError:
            continue
    raise OSError("Could not write to primary or fallback SOC log path.")


def _detection_ratio(vt_result):
    if not vt_result["total"]:
        return vt_result["status"]
    flagged = vt_result["malicious"] + vt_result["suspicious"]
    suffix = " (cached)" if vt_result.get("from_cache") else ""
    return "{} / {} engines{}".format(flagged, vt_result["total"], suffix)


def combine_verdict(vt_result, heuristics):
    """Combine VirusTotal and offline heuristic findings into a final verdict."""
    vt_malicious = vt_result["malicious"]
    vt_suspicious = vt_result["suspicious"]
    h_score = heuristics["score"]

    if vt_malicious >= 1 or h_score >= 60:
        return "Malicious"
    if vt_suspicious >= 1 or h_score >= 30:
        return "Suspicious"
    if vt_result["status"] == "Safe":
        return "Safe"
    if vt_result["status"] in {"Unknown", "Not checked", "Offline", "Rate limited"}:
        return "Clean Locally" if h_score == 0 else "Suspicious"
    return vt_result["status"]


def scan_drive(
    drive,
    message_queue,
    vt_client,
    cancel_event,
    auto_quarantine=False,
    respect_pacing=True,
):
    """Scan a removable drive with local heuristics + VirusTotal hash lookups."""
    skip_dir = config.QUARANTINE_DIR_NAME.casefold()
    file_count = 0
    malicious_count = 0
    suspicious_count = 0
    quarantined_count = 0
    cache_hits = 0
    issues = []

    def report_walk_error(error):
        issues.append(str(error))
        message_queue.put(
            ("error", "Could not read part of {}: {}".format(drive.root, error))
        )

    def emit_status(msg):
        message_queue.put(("status", msg))

    for current_root, directories, filenames in os.walk(
        drive.root, onerror=report_walk_error
    ):
        if cancel_event.is_set():
            break

        directories[:] = [
            name for name in directories
            if name.casefold() != skip_dir
        ]

        for filename in filenames:
            if cancel_event.is_set():
                break

            path_obj = Path(filename)
            suffix = path_obj.suffix.casefold()
            is_autorun = filename.casefold() == "autorun.inf"
            if suffix not in config.SCAN_EXTENSIONS and not is_autorun:
                continue

            file_path = os.path.join(current_root, filename)
            file_count += 1
            emit_status("Scanning {} ({})...".format(drive.root, filename))

            sha256 = None
            heuristics = {"score": 0, "findings": [], "entropy": None}
            try:
                heuristics = analyze_local_heuristics(file_path)
                sha256 = quarantine_utils.sha256_file(file_path)
                vt_result = vt_client.lookup_hash(
                    sha256,
                    cancel_event=cancel_event,
                    respect_pacing=respect_pacing,
                    status_callback=emit_status,
                )
                if vt_result.get("from_cache"):
                    cache_hits += 1
                verdict = combine_verdict(vt_result, heuristics)
            except OSError as exc:
                issues.append(str(exc))
                vt_result = _empty_vt_result("Unavailable", str(exc))
                verdict = "Unavailable"

            if verdict == "Malicious":
                malicious_count += 1
            elif verdict == "Suspicious":
                suspicious_count += 1

            action = "No threat indicators; allowed"
            quarantined = False
            if verdict == "Malicious":
                if auto_quarantine:
                    try:
                        reason = (
                            "; ".join(heuristics["findings"][:2])
                            or _detection_ratio(vt_result)
                        )
                        quarantine_utils.quarantine_file(
                            file_path, drive.root, reason=reason, mode="move"
                        )
                        quarantined = True
                        quarantined_count += 1
                        action = "AUTO-QUARANTINED (disarmed & moved)"
                    except OSError as exc:
                        issues.append(str(exc))
                        action = "THREAT! Auto-quarantine failed: {}".format(exc)
                else:
                    action = "THREAT DETECTED - Quarantine recommended"
            elif verdict == "Suspicious":
                action = "Suspicious - Review details before opening"
            elif verdict == "Clean Locally":
                action = "No local threats found (cloud check: {})".format(
                    vt_result["status"]
                )

            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "usb_file_scan",
                "drive_letter": drive.root,
                "volume_name": drive.volume_name,
                "file_name": filename,
                "absolute_path": os.path.abspath(file_path),
                "sha256": sha256,
                "verdict": verdict,
                "local_risk_score": heuristics["score"],
                "local_findings": heuristics["findings"],
                "entropy": heuristics["entropy"],
                "virustotal_status": vt_result["status"],
                "virustotal_malicious": vt_result["malicious"],
                "virustotal_suspicious": vt_result["suspicious"],
                "virustotal_detection_ratio": _detection_ratio(vt_result),
                "quarantined": quarantined,
                "action_taken": action,
            }
            try:
                append_json_log(event)
            except OSError as exc:
                issues.append(str(exc))
                message_queue.put(("error", "Could not write SOC log: {}".format(exc)))

            message_queue.put(
                (
                    "result",
                    {
                        "drive_root": drive.root,
                        "file_name": filename,
                        "file_type": (suffix[1:].upper() if suffix else "FILE"),
                        "verdict": verdict,
                        "local_risk": "{}/100".format(heuristics["score"]),
                        "local_score": heuristics["score"],
                        "local_findings": heuristics["findings"],
                        "entropy": heuristics["entropy"],
                        "scan_result": _detection_ratio(vt_result),
                        "action": action,
                        "quarantined": quarantined,
                        "path": os.path.abspath(file_path),
                        "sha256": sha256 or "Unavailable",
                        "taxonomy": vt_result["taxonomy"],
                        "vendors": vt_result["vendors"],
                        "details_error": vt_result["error"],
                    },
                )
            )

    message_queue.put(
        (
            "complete",
            {
                "drive": drive.root,
                "files": file_count,
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "quarantined": quarantined_count,
                "cache_hits": cache_hits,
                "issues": len(issues),
                "cancelled": cancel_event.is_set(),
            },
        )
    )


# ---------------------------------------------------------------------------
# Tkinter SOC Dashboard UI
# ---------------------------------------------------------------------------

class USBGuardDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title(
            "{} v{} - Automatic USB Endpoint Defense".format(
                config.APP_NAME, config.APP_VERSION
            )
        )
        self.root.geometry("1220x700")
        self.root.minsize(920, 520)

        self.settings = config.load_settings()
        self.vt_client = VirusTotalClient()
        self.message_queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.results = {}
        self.scan_in_progress = False
        self.pending_drives = []
        self.drives = []
        self.known_drive_roots = set()

        self.stats = {"files": 0, "malicious": 0, "suspicious": 0, "quarantined": 0}

        self._configure_style()
        self._build_ui()
        self.refresh_drives(initial=True)
        self.root.after(100, self._process_messages)
        self.root.after(config.USB_POLL_INTERVAL_MS, self._poll_usb_drives)

    def _configure_style(self):
        style = ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Header.TLabel", font=("Segoe UI", 17, "bold"))
        style.configure("Subheader.TLabel", font=("Segoe UI", 9))
        style.configure("Stat.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", rowheight=27, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_ui(self):
        container = ttk.Frame(self.root, padding=16)
        container.pack(fill=tk.BOTH, expand=True)

        # Header
        header_row = ttk.Frame(container)
        header_row.pack(fill=tk.X)
        ttk.Label(
            header_row,
            text="USB-Guard SOC — Automatic USB Malware Scanner",
            style="Header.TLabel",
        ).pack(side=tk.LEFT)
        ttk.Button(
            header_row, text="Set VT API Key", command=self.prompt_api_key
        ).pack(side=tk.RIGHT)
        ttk.Button(
            header_row, text="Manage Quarantine", command=self.open_quarantine_manager
        ).pack(side=tk.RIGHT, padx=(0, 8))

        ttk.Label(
            container,
            text=(
                "Dual-layer protection: Instant offline heuristic analysis + "
                "VirusTotal v3 hash verification (files are never uploaded)."
            ),
            style="Subheader.TLabel",
        ).pack(anchor=tk.W, pady=(2, 12))

        # Drive controls
        controls = ttk.Frame(container)
        controls.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(controls, text="Removable drive:").pack(side=tk.LEFT)
        self.drive_var = tk.StringVar()
        self.drive_combo = ttk.Combobox(
            controls, textvariable=self.drive_var, state="readonly", width=34
        )
        self.drive_combo.pack(side=tk.LEFT, padx=(8, 8))
        ttk.Button(
            controls, text="Refresh", command=self.refresh_drives
        ).pack(side=tk.LEFT, padx=(0, 6))
        self.scan_button = ttk.Button(
            controls, text="Scan Drive", command=self.start_selected_scan
        )
        self.scan_button.pack(side=tk.LEFT, padx=(0, 6))
        self.stop_button = ttk.Button(
            controls, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            controls, text="Clear Table", command=self.clear_results
        ).pack(side=tk.LEFT)

        # Automation checkboxes
        options_bar = ttk.Frame(container)
        options_bar.pack(fill=tk.X, pady=(0, 10))

        self.auto_scan_var = tk.BooleanVar(
            value=bool(self.settings.get("auto_scan", True))
        )
        ttk.Checkbutton(
            options_bar,
            text="Auto-scan newly plugged USB drives",
            variable=self.auto_scan_var,
            command=self._save_toggle_settings,
        ).pack(side=tk.LEFT, padx=(0, 16))

        self.auto_quarantine_var = tk.BooleanVar(
            value=bool(self.settings.get("auto_quarantine", False))
        )
        ttk.Checkbutton(
            options_bar,
            text="Auto-quarantine confirmed malware",
            variable=self.auto_quarantine_var,
            command=self._save_toggle_settings,
        ).pack(side=tk.LEFT, padx=(0, 16))

        self.pacing_var = tk.BooleanVar(
            value=bool(self.settings.get("vt_respect_free_tier_pacing", True))
        )
        ttk.Checkbutton(
            options_bar,
            text="VT free-tier pacing (4/min)",
            variable=self.pacing_var,
            command=self._save_toggle_settings,
        ).pack(side=tk.LEFT, padx=(0, 16))

        self.autostart_var = tk.BooleanVar(value=is_autostart_enabled())
        ttk.Checkbutton(
            options_bar,
            text="Start automatically with Windows",
            variable=self.autostart_var,
            command=self.toggle_autostart,
        ).pack(side=tk.LEFT)

        # Live summary counters
        stats_bar = ttk.Frame(container)
        stats_bar.pack(fill=tk.X, pady=(0, 8))
        self.stats_var = tk.StringVar(
            value="Scanned: 0   |   Malicious: 0   |   Suspicious: 0   |   Quarantined: 0"
        )
        ttk.Label(stats_bar, textvariable=self.stats_var, style="Stat.TLabel").pack(
            side=tk.LEFT
        )

        # Results table
        table_frame = ttk.Frame(container)
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = (
            "file_name",
            "file_type",
            "verdict",
            "local_risk",
            "scan_result",
            "action",
        )
        self.table = ttk.Treeview(
            table_frame, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "file_name": ("File Name", 230),
            "file_type": ("Type", 70),
            "verdict": ("Verdict", 125),
            "local_risk": ("Heuristic Risk", 105),
            "scan_result": ("VirusTotal", 175),
            "action": ("Action / Status", 340),
        }
        for column, (heading, width) in headings.items():
            self.table.heading(column, text=heading)
            self.table.column(column, width=width, minwidth=65, anchor=tk.W)

        y_scroll = ttk.Scrollbar(
            table_frame, orient=tk.VERTICAL, command=self.table.yview
        )
        self.table.configure(yscrollcommand=y_scroll.set)
        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.table.tag_configure("malicious", background="#ffd6cc")
        self.table.tag_configure("suspicious", background="#fff1c2")
        self.table.tag_configure("safe", background="#e2f5e6")
        self.table.tag_configure("clean_local", background="#e8f1fa")
        self.table.tag_configure("other", background="#f2f2f2")
        self.table.bind("<Double-1>", self.show_selected_details)

        # Footer & actions
        footer = ttk.Frame(container)
        footer.pack(fill=tk.X, pady=(10, 0))
        self.status_var = tk.StringVar(
            value="Watching for newly plugged USB drives..."
        )
        ttk.Label(footer, textvariable=self.status_var).pack(side=tk.LEFT)

        ttk.Button(
            footer, text="Export CSV Report", command=self.export_csv_report
        ).pack(side=tk.RIGHT)
        ttk.Button(
            footer, text="View Details", command=self.show_selected_details
        ).pack(side=tk.RIGHT, padx=(0, 6))
        ttk.Button(
            footer, text="Quarantine Selected", command=self.quarantine_selected
        ).pack(side=tk.RIGHT, padx=(0, 6))

    def _save_toggle_settings(self):
        config.save_settings(
            {
                "auto_scan": self.auto_scan_var.get(),
                "auto_quarantine": self.auto_quarantine_var.get(),
                "vt_respect_free_tier_pacing": self.pacing_var.get(),
            }
        )

    def _update_stats_label(self):
        self.stats_var.set(
            "Scanned: {files}   |   Malicious: {malicious}   |   "
            "Suspicious: {suspicious}   |   Quarantined: {quarantined}".format(
                **self.stats
            )
        )

    def prompt_api_key(self):
        current = config.get_vt_api_key()
        key = simpledialog.askstring(
            "VirusTotal API Key",
            "Paste your personal VirusTotal v3 API key (saved locally, never in code):",
            initialvalue=current,
            show="*",
            parent=self.root,
        )
        if key is not None:
            config.save_vt_api_key(key)
            if key.strip():
                self.status_var.set("VirusTotal API key saved locally.")
            else:
                self.status_var.set(
                    "VirusTotal API key cleared (offline heuristics mode)."
                )

    def toggle_autostart(self):
        try:
            set_autostart(self.autostart_var.get())
            state = "enabled" if self.autostart_var.get() else "disabled"
            self.status_var.set("Windows startup auto-launch {}.".format(state))
        except OSError as exc:
            self.autostart_var.set(is_autostart_enabled())
            messagebox.showerror(
                "Startup Error",
                "Could not update Windows startup entry: {}".format(exc),
                parent=self.root,
            )

    def _bring_to_front(self):
        self.root.deiconify()
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.after(450, lambda: self.root.attributes("-topmost", False))

    def refresh_drives(self, initial=False):
        self.drives = find_removable_drives()
        if initial:
            self.known_drive_roots = {drive.root for drive in self.drives}
        choices = [
            "{} ({})".format(drive.root, drive.volume_name or "No label")
            for drive in self.drives
        ]
        self.drive_combo["values"] = choices
        if choices:
            self.drive_combo.current(0)
            if not self.scan_in_progress:
                self.status_var.set(
                    "{} removable drive(s) attached. Watching for newly plugged USBs.".format(
                        len(choices)
                    )
                )
        else:
            self.drive_var.set("")
            if not self.scan_in_progress:
                self.status_var.set("Watching for newly plugged USB drives...")

    def _poll_usb_drives(self):
        """Poll every 2 seconds for newly inserted USB drives."""
        try:
            current_drives = find_removable_drives()
            current_roots = {drive.root for drive in current_drives}
            new_roots = current_roots - self.known_drive_roots

            if current_roots != self.known_drive_roots:
                self.drives = current_drives
                self.known_drive_roots = current_roots
                self.refresh_drives(initial=False)

            if new_roots and self.auto_scan_var.get():
                for drive in current_drives:
                    if drive.root in new_roots:
                        self.pending_drives.append(drive)
                self._bring_to_front()
                self._start_next_queued_scan()
        except OSError:
            pass
        self.root.after(config.USB_POLL_INTERVAL_MS, self._poll_usb_drives)

    def start_selected_scan(self):
        selected = self.drive_combo.current()
        if selected < 0 or selected >= len(self.drives):
            messagebox.showinfo(
                "Select a Drive",
                "Plug in and select a removable USB drive to scan.",
                parent=self.root,
            )
            return
        self.pending_drives.append(self.drives[selected])
        self._start_next_queued_scan()

    def stop_scan(self):
        if self.scan_in_progress:
            self.cancel_event.set()
            self.pending_drives.clear()
            self.status_var.set("Stopping current scan...")

    def clear_results(self):
        for item in self.table.get_children():
            self.table.delete(item)
        self.results.clear()
        self.stats = {"files": 0, "malicious": 0, "suspicious": 0, "quarantined": 0}
        self._update_stats_label()

    def _start_next_queued_scan(self):
        if self.scan_in_progress or not self.pending_drives:
            return
        drive = self.pending_drives.pop(0)
        self.cancel_event.clear()
        self.scan_in_progress = True
        self.scan_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.status_var.set(
            "Scanning {} ({})...".format(
                drive.root, drive.volume_name or "Removable Drive"
            )
        )
        threading.Thread(
            target=scan_drive,
            args=(
                drive,
                self.message_queue,
                self.vt_client,
                self.cancel_event,
                self.auto_quarantine_var.get(),
                self.pacing_var.get(),
            ),
            daemon=True,
        ).start()

    def _process_messages(self):
        try:
            while True:
                kind, payload = self.message_queue.get_nowait()
                if kind == "result":
                    self._add_result(payload)
                elif kind == "status":
                    self.status_var.set(payload)
                elif kind == "error":
                    self.status_var.set(payload)
                elif kind == "complete":
                    self.scan_in_progress = False
                    self.scan_button.configure(state=tk.NORMAL)
                    self.stop_button.configure(state=tk.DISABLED)
                    self.status_var.set(self._completion_message(payload))
                    if payload["malicious"] > 0:
                        self._bring_to_front()
                        messagebox.showwarning(
                            "Malware Detected!",
                            "{malicious} malicious and {suspicious} suspicious file(s) found on {drive}.\n"
                            "Auto-quarantined: {quarantined}.\n\n"
                            "Do NOT open flagged files. Select red rows and click "
                            "'Quarantine Selected' or double-click for forensic details.".format(
                                **payload
                            ),
                            parent=self.root,
                        )
                    self._start_next_queued_scan()
        except queue.Empty:
            pass
        self.root.after(100, self._process_messages)

    @staticmethod
    def _completion_message(summary):
        prefix = "Scan stopped" if summary["cancelled"] else "Scan complete"
        msg = (
            "{prefix} on {drive}: {files} scanned, {malicious} malicious, "
            "{suspicious} suspicious"
        ).format(prefix=prefix, **summary)
        if summary["quarantined"]:
            msg += ", {} auto-quarantined".format(summary["quarantined"])
        if summary["cache_hits"]:
            msg += " ({} VT cache hits)".format(summary["cache_hits"])
        return msg + "."

    def _add_result(self, result):
        self.stats["files"] += 1
        if result["verdict"] == "Malicious":
            self.stats["malicious"] += 1
            tag = "malicious"
        elif result["verdict"] == "Suspicious":
            self.stats["suspicious"] += 1
            tag = "suspicious"
        elif result["verdict"] == "Safe":
            tag = "safe"
        elif result["verdict"] == "Clean Locally":
            tag = "clean_local"
        else:
            tag = "other"

        if result["quarantined"]:
            self.stats["quarantined"] += 1
        self._update_stats_label()

        item_id = self.table.insert(
            "",
            tk.END,
            values=(
                result["file_name"],
                result["file_type"],
                result["verdict"],
                result["local_risk"],
                result["scan_result"],
                result["action"],
            ),
            tags=(tag,),
        )
        self.results[item_id] = result

    def quarantine_selected(self):
        selection = self.table.selection()
        if not selection:
            messagebox.showinfo(
                "Quarantine", "Select a file from the table first.", parent=self.root
            )
            return
        item_id = selection[0]
        result = self.results[item_id]
        if result.get("quarantined"):
            messagebox.showinfo(
                "Already Quarantined",
                "This file has already been quarantined.",
                parent=self.root,
            )
            return

        confirm = messagebox.askyesno(
            "Confirm Quarantine",
            "Move and disarm this file into .usb_quarantine?\n\n"
            "File: {}\nVerdict: {}\n\n"
            "You can restore or permanently delete it later via 'Manage Quarantine'.".format(
                result["path"], result["verdict"]
            ),
            parent=self.root,
        )
        if not confirm:
            return

        try:
            reason = "; ".join(result["local_findings"][:2]) or result["scan_result"]
            record = quarantine_utils.quarantine_file(
                result["path"], result["drive_root"], reason=reason, mode="move"
            )
            result["quarantined"] = True
            result["action"] = "QUARANTINED ({})".format(record["quarantined_filename"])
            self.stats["quarantined"] += 1
            self._update_stats_label()
            self.table.item(
                item_id,
                values=(
                    result["file_name"],
                    result["file_type"],
                    result["verdict"],
                    result["local_risk"],
                    result["scan_result"],
                    result["action"],
                ),
            )
            append_json_log(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "usb_file_quarantined",
                    "drive_letter": result["drive_root"],
                    "original_path": result["path"],
                    "quarantined_filename": record["quarantined_filename"],
                    "sha256": record["sha256"],
                }
            )
            self.status_var.set("Quarantined: {}".format(result["file_name"]))
        except (OSError, ValueError) as exc:
            messagebox.showerror("Quarantine Failed", str(exc), parent=self.root)

    def open_quarantine_manager(self):
        selected = self.drive_combo.current()
        if selected < 0 or selected >= len(self.drives):
            messagebox.showinfo(
                "Manage Quarantine",
                "Select a connected USB drive first.",
                parent=self.root,
            )
            return
        drive = self.drives[selected]

        win = tk.Toplevel(self.root)
        win.title("Quarantine Manager - {}".format(drive.root))
        win.geometry("820x400")
        win.transient(self.root)

        cols = ("original_name", "quarantined_at", "reason", "sha256")
        q_table = ttk.Treeview(win, columns=cols, show="headings", selectmode="browse")
        q_table.heading("original_name", text="Original File")
        q_table.heading("quarantined_at", text="Quarantined At (UTC)")
        q_table.heading("reason", text="Reason")
        q_table.heading("sha256", text="SHA-256")
        q_table.column("original_name", width=160)
        q_table.column("quarantined_at", width=175)
        q_table.column("reason", width=250)
        q_table.column("sha256", width=200)
        q_table.pack(fill=tk.BOTH, expand=True, padx=12, pady=(12, 8))

        record_map = {}

        def reload_list():
            for row in q_table.get_children():
                q_table.delete(row)
            record_map.clear()
            for rec in quarantine_utils.list_quarantined_files(drive.root):
                iid = q_table.insert(
                    "",
                    tk.END,
                    values=(
                        rec["original_name"],
                        rec["quarantined_at"],
                        rec["reason"],
                        rec["sha256"],
                    ),
                )
                record_map[iid] = rec

        def do_restore():
            sel = q_table.selection()
            if not sel:
                return
            rec = record_map[sel[0]]
            if not messagebox.askyesno(
                "Restore File",
                "Restore '{}' back to '{}'?\nOnly restore files you trust.".format(
                    rec["original_name"], rec["original_relative_path"]
                ),
                parent=win,
            ):
                return
            try:
                restored_to = quarantine_utils.restore_file(
                    drive.root, rec["quarantined_filename"]
                )
                reload_list()
                messagebox.showinfo(
                    "Restored", "File restored to:\n{}".format(restored_to), parent=win
                )
            except (OSError, ValueError) as exc:
                messagebox.showerror("Restore Failed", str(exc), parent=win)

        def do_delete():
            sel = q_table.selection()
            if not sel:
                return
            rec = record_map[sel[0]]
            if not messagebox.askyesno(
                "Permanently Delete",
                "Permanently delete '{}' from quarantine? This cannot be undone.".format(
                    rec["original_name"]
                ),
                parent=win,
            ):
                return
            try:
                quarantine_utils.delete_quarantined_file(
                    drive.root, rec["quarantined_filename"]
                )
                reload_list()
            except (OSError, ValueError) as exc:
                messagebox.showerror("Delete Failed", str(exc), parent=win)

        btn_bar = ttk.Frame(win)
        btn_bar.pack(fill=tk.X, padx=12, pady=(0, 12))
        ttk.Button(btn_bar, text="Restore Selected", command=do_restore).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(btn_bar, text="Delete Permanently", command=do_delete).pack(
            side=tk.LEFT
        )
        ttk.Button(btn_bar, text="Close", command=win.destroy).pack(side=tk.RIGHT)

        reload_list()

    def export_csv_report(self):
        if not self.results:
            messagebox.showinfo(
                "Export Report", "No scan results to export yet.", parent=self.root
            )
            return
        save_path = filedialog.asksaveasfilename(
            title="Export Scan Report",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="usb_guard_report.csv",
            parent=self.root,
        )
        if not save_path:
            return
        try:
            with open(save_path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(
                    [
                        "File Name",
                        "Type",
                        "Verdict",
                        "Local Risk Score",
                        "Entropy",
                        "VirusTotal",
                        "Action",
                        "SHA-256",
                        "Path",
                        "Local Findings",
                    ]
                )
                for res in self.results.values():
                    writer.writerow(
                        [
                            res["file_name"],
                            res["file_type"],
                            res["verdict"],
                            res["local_score"],
                            res["entropy"] if res["entropy"] is not None else "",
                            res["scan_result"],
                            res["action"],
                            res["sha256"],
                            res["path"],
                            " | ".join(res["local_findings"]),
                        ]
                    )
            self.status_var.set("Exported CSV report to {}".format(save_path))
        except OSError as exc:
            messagebox.showerror("Export Failed", str(exc), parent=self.root)

    def show_selected_details(self, _event=None):
        selection = self.table.selection()
        if not selection:
            messagebox.showinfo(
                "View Details", "Select a scan result first.", parent=self.root
            )
            return
        result = self.results[selection[0]]
        findings = "\n- ".join(result["local_findings"])
        findings_block = "- " + findings if findings else "None detected."
        taxonomy = "\n".join(result["taxonomy"]) or "None reported."
        vendors = "\n".join(result["vendors"]) or "No major vendor detections."
        entropy_str = (
            "{:.3f} / 8.000".format(result["entropy"])
            if result["entropy"] is not None
            else "Not applicable"
        )

        details = (
            "File: {file_name}\n"
            "Path: {path}\n"
            "SHA-256: {sha256}\n"
            "Final Verdict: {verdict}\n"
            "Local Heuristic Risk: {local_risk}\n"
            "Binary Entropy: {entropy}\n"
            "VirusTotal: {scan_result}\n\n"
            "Offline Heuristic Findings:\n{findings}\n\n"
            "VirusTotal Threat Taxonomy:\n{taxonomy}\n\n"
            "Major Vendor Detections:\n{vendors}"
        ).format(
            file_name=result["file_name"],
            path=result["path"],
            sha256=result["sha256"],
            verdict=result["verdict"],
            local_risk=result["local_risk"],
            entropy=entropy_str,
            scan_result=result["scan_result"],
            findings=findings_block,
            taxonomy=taxonomy,
            vendors=vendors,
        )
        if result["details_error"]:
            details += "\n\nLookup Note: {}".format(result["details_error"])
        messagebox.showinfo("Forensic Scan Details", details, parent=self.root)


def main():
    mutex_handle = acquire_single_instance_mutex()
    if mutex_handle is None:
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(
            config.APP_NAME,
            "USB-Guard SOC is already running and watching your USB ports.",
        )
        root.destroy()
        return

    root = tk.Tk()
    USBGuardDashboard(root)
    if "--minimized" in sys.argv:
        root.iconify()
    root.mainloop()


if __name__ == "__main__":
    main()
