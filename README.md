# USB Guard desktop app

This is a defensive Windows USB monitor. The installed executable starts at the
current user's login and watches for newly mounted removable drives. It scans
configured file types, hashes them, checks VirusTotal, writes JSONL audit logs,
and displays results in the dashboard.

It does not use USB autorun or execute files from a USB drive. Windows startup
is registered transparently under the current user's Run key.

## Build and install

From the project root, in PowerShell:

```powershell
$env:USB_GUARD_VT_API_KEY = "Past here your virustotal api key"
Set-ExecutionPolicy -Scope Process Bypass
.\app\install.ps1
```

The app is installed to `%LOCALAPPDATA%\USB-Guard` and starts at the next login.
The default configuration detects threats but does not delete or quarantine
files. Enable `AUTO_QUARANTINE` in `config.py` only after testing and review.

The API key previously committed to this project should be revoked and replaced.
