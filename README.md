# USB-Guard SOC — Automatic USB Malware Scanner & Quarantine (Windows)

**USB-Guard SOC** is a free Windows security app that watches your USB ports. Whenever you plug in a pendrive, it automatically scans risky files and safely locks away (quarantines) viruses before you accidentally open them.

- **Works without internet:** Built-in rules catch USB worms, fake file extensions, hidden executables, and dangerous scripts offline.
- **100% Private:** Your personal files are **never uploaded** anywhere. Only a digital fingerprint (SHA-256 hash) is checked on VirusTotal.
- **No extra software needed:** Just download the `.exe` and double-click, or run directly with standard Python.

**Quick Jump:** [Easy 5-Step Setup Guide](#step-1-download-and-open-the-app) | [How It Works (Architecture)](#architecture-overview) | [Detection Matrix](#detection-matrix) | [Wazuh SIEM Setup](#optional-wazuh-siem-integration) | [Known Limitations](#known-limitations)

---

## Step 1: Download and Open the App

### Option A: Easiest Way — Use the `.exe` App (Recommended)
1. On this GitHub page, look on the **right side** under **Releases** and click **`USB-Guard SOC v2.1.0`**.
2. Scroll down to **Assets** and click **`USB-Guard-SOC.exe`** to download it.
3. Open your **Downloads** folder and move **`USB-Guard-SOC.exe`** to a safe folder you will not delete (for example, `C:\Apps\USB-Guard-SOC\`).
4. **Double-click** `USB-Guard-SOC.exe` to open it.
   - *If Windows shows a blue box saying **"Windows protected your PC"***: don't worry! This happens for new independent apps. Click **More info** → click **Run anyway**.

### Option B: Developer Way — Run From Python Code
*(Requires Windows 10/11 with Python 3.8+ installed.)*

1. Click the green **`<> Code`** button near the top of this page → click **Download ZIP**.
2. Right-click the downloaded `.zip` file → click **Extract All...** → click **Extract**.
3. Open the extracted folder (where you see `main.py`, `config.py`, and `quarantine_utils.py`).
4. Click the top **Address Bar** in File Explorer, type `cmd`, and press **Enter**.
5. Type this command and press **Enter**:
   ```cmd
   python main.py
   ```
6. The **USB-Guard SOC** window will open right away.

---

## Step 2: Get Your Free VirusTotal Key (Takes 2 Minutes)

> **What is an API key?** Think of it like a free library card. Without it, USB-Guard still protects you offline. With it, USB-Guard can also check files against **70+ top antivirus engines** online.

1. Open your browser and go to **[https://www.virustotal.com](https://www.virustotal.com)**.
2. Click **Sign up** (top-right corner).
3. Fill in your **Name, Username, Email, and Password**, then click **Join us**.
4. Open your email inbox, open the email from VirusTotal, and click the **Confirm / Verify** link.
5. Go back to **[https://www.virustotal.com](https://www.virustotal.com)** and click **Sign in**.
6. Go directly to **[https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)** (or click your profile icon → **API key**).
7. Click the **Copy** button next to the long code shown there.
   - *Keep this key private—never post it online.*

---

## Step 3: Paste Your Key Into USB-Guard SOC

1. Go back to the **USB-Guard SOC** window.
2. Click the **`Set VT API Key`** button in the top-right corner.
3. Click inside the small text box and press **`Ctrl + V`** on your keyboard to paste your key.
4. Click **OK**.
5. Look at the bottom-left corner—it will say **`VirusTotal API key saved locally.`**

*(Your key is stored only on your own computer and is never shared.)*

---

## Step 4: Turn On Automatic Protection

Tick these checkboxes inside the **USB-Guard SOC** window so it works on its own:

1. **`Auto-scan newly plugged USB drives`** — **ON** (automatically scans every pendrive within 2 seconds of plugging it in).
2. **`Start automatically with Windows`** — **ON** (quietly starts every time you turn on your PC).
3. **`VT free-tier pacing (4/min)`** — **ON** (stays inside VirusTotal's free limit of 4 checks per minute so you don't get errors).
4. **`Auto-quarantine confirmed malware`** — *(Optional)* turn **ON** if you want the app to automatically lock away confirmed viruses without asking.

---

## Step 5: Plug In a Pendrive and Read the Colors

1. Plug any USB pendrive into your PC.
2. Within 2 seconds, **USB-Guard SOC** pops up and scans risky files (programs, scripts, shortcuts, `autorun.inf`, and fake `.pdf`/`.jpg` files hiding Windows executables).
3. Check the row color just like a traffic light:
   - **Red (`Malicious`) — STOP!** Confirmed danger. **Do NOT open this file.** Click the row and press **`Quarantine Selected`** to safely lock it away.
   - **Yellow (`Suspicious`) — BE CAREFUL!** Something looks unusual. Double-click the row to read why before opening it.
   - **Green (`Safe`) / Blue (`Clean Locally`) — ALL GOOD!** No threats found.
4. **Check full details:** Double-click any row (or click **`View Details`**) to see the file's SHA-256 hash, risk score, and antivirus detections.
5. **Restore or permanently delete locked files:** Click **`Manage Quarantine`** (top-right). Locked files are scrambled (XOR-disarmed) so they cannot run by accident—you can safely delete them forever or restore a trusted file.
6. **Save a report:** Click **`Export CSV Report`** (bottom-right) to save the scan results as a spreadsheet.

---

## Architecture Overview

```text
USB Inserted (Windows ctypes 2-second removable-drive polling)
  -> Dual-Layer Engine:
       1. Offline Heuristics (PE magic-byte spoof, double extensions, LNK/script regex, entropy)
       2. VirusTotal API v3 SHA-256 Lookup (7-day local cache + 4 req/min pacing + FP filter)
  -> Reversible XOR-Disarmed Quarantine Vault (UGQ1 header + 0xAA mask + SHA-256 manifest)
  -> SIEM-Ready JSONL Telemetry (C:\ProgramData\USB_Guard_SOC\logs\usb_security_events.json)
  -> Wazuh SIEM Custom Alerts (MITRE ATT&CK T1091 / T1036.007)
```

---

## Detection Matrix

| Layer | Check / Technique | MITRE ATT&CK |
|---|---|---|
| Offline Heuristic | `autorun.inf` & Hidden + System attributes | `T1091` / `T1564.001` |
| Offline Heuristic | Double-extension & `MZ` PE header spoofing (on decoy/extensionless files) | `T1036.007` |
| Offline Heuristic | `.lnk` shortcut abuse & LOLBin / PowerShell / Ransomware regex | `T1059` / `T1490` |
| Offline Heuristic | Shannon Entropy (`>= 7.25`) packed/obfuscated binary check | `T1027.002` |
| Cloud Threat Intel | VirusTotal API v3 hash lookup (FP-resistant: `>= 3` hits or `>= 1` major AV) | Multi-AV Consensus |

---

## Optional: Wazuh SIEM Integration

Ready-to-use SIEM configs are included inside the `wazuh/` folder:

- **Windows Wazuh Agent:** Paste the `<localfile>` block from `wazuh/wazuh_agent_configuration_snippet.xml` inside `<ossec_config>` in `C:\Program Files (x86)\ossec-agent\ossec.conf` and restart `WazuhSvc`.
- **Wazuh Manager:** Append `wazuh/wazuh_manager_custom_rules.xml` to `/var/ossec/etc/rules/local_rules.xml` and restart `wazuh-manager` to generate alerts (`rule.id` `100500`–`100503`).

---

## Known Limitations

- **User-space file scanner:** Cannot stop hardware/firmware-level BadUSB (rogue keyboard/HID injection), which requires OS USB device-control policies or hardware blockers.
- **Polling model:** Checks for new removable drives every 2 seconds via Windows `GetLogicalDrives` instead of using a kernel-mode minifilter driver.
- **Unsigned executable:** Because the `.exe` is not signed with a paid code-signing certificate, Windows SmartScreen may show a warning. Always verify the SHA-256 checksum listed on the GitHub Release page before running.

---

## Log & Data Paths

| Purpose | Path |
|---|---|
| Settings & API Key | `%LOCALAPPDATA%\USB_Guard_SOC\settings.json` |
| 7-Day VirusTotal Cache | `%LOCALAPPDATA%\USB_Guard_SOC\vt_hash_cache.json` |
| SOC Security Event Logs | `C:\ProgramData\USB_Guard_SOC\logs\usb_security_events.json` |
| Quarantined Files | `<USB>:\.usb_quarantine\` |
| Wazuh SIEM Configs | `wazuh/` (`wazuh_agent_configuration_snippet.xml`, `wazuh_manager_custom_rules.xml`) |
