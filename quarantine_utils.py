"""Safe quarantine, verification, and restore utilities for USB-Guard SOC.

Supports two modes:
- mode="move" (default): Copies the threat into a hidden .usb_quarantine folder
  with a disarmed `.quarantined` extension, verifies SHA-256 integrity, records
  audit metadata in manifest.json, and removes the original threat from the USB.
- mode="copy": Non-destructive forensic review-hold copy that leaves the
  original file untouched.
"""

from datetime import datetime, timezone
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

import config


FILE_ATTRIBUTE_NORMAL = 0x80


def sha256_file(file_path):
    """Compute SHA-256 digest of a file in streaming chunks."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _clear_windows_readonly_attributes(path):
    """Remove Read-Only/Hidden/System flags so malware files can be removed."""
    try:
        os.chmod(str(path), stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass
    if os.name == "nt":
        try:
            ctypes.windll.kernel32.SetFileAttributesW(
                ctypes.c_wchar_p(str(path)), FILE_ATTRIBUTE_NORMAL
            )
        except OSError:
            pass


def _ensure_within_root(target_path, usb_root):
    """Prevent path traversal / symlink escapes outside the USB root."""
    resolved_root = Path(usb_root).resolve(strict=True)
    resolved_target = Path(target_path).resolve(strict=False)
    try:
        resolved_target.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(
            "Target path escapes the USB drive boundary: {}".format(target_path)
        ) from exc
    return resolved_root, resolved_target


def _manifest_path(usb_root):
    root = Path(usb_root).resolve(strict=True)
    return root / config.QUARANTINE_DIR_NAME / config.QUARANTINE_MANIFEST_NAME


def _load_manifest(usb_root):
    path = _manifest_path(usb_root)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_manifest(usb_root, entries):
    path = _manifest_path(usb_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    tmp.replace(path)


def _hide_quarantine_dir(hold_dir):
    """Mark the quarantine folder as Hidden on Windows to prevent casual clicks."""
    if os.name == "nt":
        try:
            FILE_ATTRIBUTE_HIDDEN = 0x02
            ctypes.windll.kernel32.SetFileAttributesW(
                ctypes.c_wchar_p(str(hold_dir)), FILE_ATTRIBUTE_HIDDEN
            )
        except OSError:
            pass


def quarantine_file(file_path, usb_root, reason="", mode="move"):
    """Quarantine a suspicious/malicious file into <usb_root>/.usb_quarantine.

    Parameters:
        file_path: Full path to the file on the removable drive.
        usb_root: Root directory of the removable drive (e.g., 'E:\\').
        reason: Human-readable detection summary for the manifest.
        mode: 'move' (disarm & remove original) or 'copy' (review-hold copy).

    Returns:
        dict containing quarantine record metadata.
    """
    if mode not in {"move", "copy"}:
        raise ValueError("Invalid quarantine mode: {}".format(mode))

    root, source = _ensure_within_root(file_path, usb_root)
    if not source.exists() or not source.is_file():
        raise FileNotFoundError("Selected file does not exist: {}".format(source))

    hold_dir = (root / config.QUARANTINE_DIR_NAME).resolve(strict=False)
    try:
        source.relative_to(hold_dir)
        raise ValueError("File is already inside the quarantine folder.")
    except ValueError as exc:
        if "already inside" in str(exc):
            raise

    hold_dir.mkdir(parents=True, exist_ok=True)
    _hide_quarantine_dir(hold_dir)

    original_hash = sha256_file(source)
    timestamp = datetime.now(timezone.utc)
    stamp = timestamp.strftime("%Y%m%dT%H%M%SZ")
    safe_name = source.name.replace("/", "_").replace("\\", "_")
    quarantined_name = "{}_{}_{}{}".format(
        stamp, original_hash[:12], safe_name, config.QUARANTINE_EXTENSION
    )
    destination = hold_dir / quarantined_name

    counter = 1
    while destination.exists():
        destination = hold_dir / "{}_{}_{}_{}{}".format(
            stamp, original_hash[:12], counter, safe_name, config.QUARANTINE_EXTENSION
        )
        counter += 1

    try:
        shutil.copy2(str(source), str(destination))
    except OSError as exc:
        if destination.exists():
            try:
                _clear_windows_readonly_attributes(destination)
                os.remove(str(destination))
            except OSError:
                pass
        raise OSError("Failed to copy file into quarantine: {}".format(exc)) from exc

    copied_hash = sha256_file(destination)
    if copied_hash != original_hash:
        try:
            _clear_windows_readonly_attributes(destination)
            os.remove(str(destination))
        except OSError:
            pass
        raise OSError("Quarantine integrity check failed (SHA-256 mismatch).")

    if mode == "move":
        _clear_windows_readonly_attributes(source)
        os.remove(str(source))

    record = {
        "id": "{}_{}".format(stamp, original_hash[:12]),
        "quarantined_at": timestamp.isoformat(),
        "mode": mode,
        "original_name": source.name,
        "original_relative_path": str(source.relative_to(root)),
        "quarantined_filename": destination.name,
        "sha256": original_hash,
        "size_bytes": destination.stat().st_size,
        "reason": reason or "Flagged by USB-Guard SOC",
    }

    manifest = _load_manifest(root)
    manifest.append(record)
    _save_manifest(root, manifest)
    return record


def list_quarantined_files(usb_root):
    """Return quarantine records whose disarmed files still exist on the USB."""
    root = Path(usb_root).resolve(strict=True)
    hold_dir = root / config.QUARANTINE_DIR_NAME
    entries = _load_manifest(root)
    valid = []
    for entry in entries:
        q_file = hold_dir / entry.get("quarantined_filename", "")
        if q_file.is_file():
            enriched = dict(entry)
            enriched["quarantined_path"] = str(q_file)
            valid.append(enriched)
    return valid


def restore_file(usb_root, quarantined_filename, overwrite=False):
    """Restore a quarantined file back to its original location after hash check."""
    root = Path(usb_root).resolve(strict=True)
    hold_dir = root / config.QUARANTINE_DIR_NAME
    entries = _load_manifest(root)

    target_entry = None
    remaining = []
    for entry in entries:
        if entry.get("quarantined_filename") == quarantined_filename and target_entry is None:
            target_entry = entry
        else:
            remaining.append(entry)

    if target_entry is None:
        raise FileNotFoundError(
            "Quarantine record not found for: {}".format(quarantined_filename)
        )

    q_path = hold_dir / quarantined_filename
    if not q_path.is_file():
        raise FileNotFoundError("Quarantined file missing on disk: {}".format(q_path))

    actual_hash = sha256_file(q_path)
    expected_hash = target_entry.get("sha256", "")
    if expected_hash and actual_hash != expected_hash:
        raise OSError("Cannot restore: quarantined file failed SHA-256 verification.")

    restore_target = root / target_entry["original_relative_path"]
    _, resolved_restore = _ensure_within_root(restore_target, root)
    if resolved_restore.exists() and not overwrite:
        raise FileExistsError(
            "A file already exists at the original path: {}".format(resolved_restore)
        )

    resolved_restore.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(q_path), str(resolved_restore))
    if sha256_file(resolved_restore) != actual_hash:
        try:
            os.remove(str(resolved_restore))
        except OSError:
            pass
        raise OSError("Restored file failed SHA-256 verification.")

    _clear_windows_readonly_attributes(q_path)
    os.remove(str(q_path))
    _save_manifest(root, remaining)
    return str(resolved_restore)


def delete_quarantined_file(usb_root, quarantined_filename):
    """Permanently delete a quarantined file and remove its manifest entry."""
    root = Path(usb_root).resolve(strict=True)
    hold_dir = root / config.QUARANTINE_DIR_NAME
    q_path = hold_dir / quarantined_filename
    _ensure_within_root(q_path, root)

    if q_path.exists():
        _clear_windows_readonly_attributes(q_path)
        os.remove(str(q_path))

    entries = _load_manifest(root)
    remaining = [
        entry for entry in entries
        if entry.get("quarantined_filename") != quarantined_filename
    ]
    _save_manifest(root, remaining)
