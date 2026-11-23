# USB-Guard SOC — Automatic USB Malware Scanner & Quarantine (Windows)

**USB-Guard SOC** is a Windows endpoint defense tool that automatically detects newly plugged-in USB drives, scans risky files using a **dual-layer engine** (offline heuristics + VirusTotal v3 hash verification), and safely quarantines malware.

- **Works offline too:** Built-in heuristic rules detect USB worms, fake extensions, and malicious scripts even without internet or an API key.
- **Privacy-first:** Your files are **never uploaded**—only SHA-256 hashes are sent to VirusTotal.
- **Zero extra Python packages needed** if running from source code.

---

## Step 1: Download & Run the App

### Option A: Easy Way — Download the `.exe` (No Python Required)
1. On this GitHub page, look at the right sidebar under **Releases** and click the latest version (`v2.0.0`).
2. Under **Assets**, click **`USB-Guard-SOC.exe`** to download it.
3. Move `USB-Guard-SOC.exe` into a permanent folder (for example, `C:\Apps\USB-Guard-SOC\`) so you do not accidentally delete it from Downloads.
4. Double-click **`USB-Guard-SOC.exe`** to open the app.
   - *If Windows SmartScreen shows **"Windows protected your PC"***: click **More info** → **Run anyway**.

### Option B: Developer Way — Run Using Python Source Code
*Requires Windows 10/11 with Python 3.8+ installed (with "Add python.exe to PATH" checked).*

1. Click the green **`<> Code`** button at the top of this page → click **Download ZIP**.
2. Right-click the downloaded `.zip` file → click **Extract All...** and extract it (for example, to `C:\USB_Scanner`).
3. Open the extracted folder so you can see `main.py`, `config.py`, and `quarantine_utils.py`.
4. Click the top **Address Bar** of File Explorer, type `cmd`, and press **Enter**.
5. In the Command Prompt window that opens, type:
   ```cmd
   python main.py
   ```
6. Press **Enter** — the **USB-Guard SOC** window opens immediately.

---

## Step 2: Create a Free VirusTotal Account & Copy Your API Key

> **Note:** Every user must use their own free VirusTotal API key. The app still scans locally without a key, but adding your key enables cloud checks against 70+ antivirus engines.

1. Open your browser and go to **[https://www.virustotal.com](https://www.virustotal.com)**.
2. Click **Sign up** in the top-right corner.
3. Enter your **First Name**, **Last Name**, **Username**, **Email**, and **Password**, then click **Join us**.
4. Open your email inbox, find the confirmation email from VirusTotal, and click the **verification link**.
5. Go back to **[https://www.virustotal.com](https://www.virustotal.com)** and click **Sign in** with your new account.
6. Click your **Profile Icon / Username** in the top-right corner and click **API key** (or go directly to **[https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)**).
7. Click the **Copy** icon next to your 64-character API key string.
   - *Never share your API key publicly.*

---

## Step 3: Paste Your API Key Into USB-Guard SOC

1. Open the **USB-Guard SOC** window.
2. Click the **`Set VT API Key`** button in the top-right corner.
3. Click inside the popup text box and press **`Ctrl + V`** to paste your VirusTotal API key.
4. Click **OK**.
5. Check the bottom status bar—it will say: **`VirusTotal API key saved locally.`**

*(Your key is saved privately on your PC at `%LOCALAPPDATA%\USB_Guard_SOC\settings.json` and is never shared.)*

---

## Step 4: Turn On Automatic Detection When Plugging In Any USB

Inside the **USB-Guard SOC** window, check these boxes:

1. **`Auto-scan newly plugged USB drives`** (ON) — automatically pops up and scans within 2 seconds whenever any USB drive is plugged in.
2. **`Start automatically with Windows`** (ON) — automatically starts USB-Guard SOC minimized every time your computer turns on, so you never have to open it manually again.
3. **`VT free-tier pacing (4/min)`** (ON) — respects VirusTotal's free-tier limit (4 lookups/minute, 500/day) so large USB drives do not hit API errors.
4. **`Auto-quarantine confirmed malware`** *(Optional)* — automatically disarms and moves confirmed malware into a hidden `.usb_quarantine` folder on the USB.

---

## Step 5: Plug In a USB & Review Results

1. Plug any USB flash drive into your computer.
2. Within 2 seconds, **USB-Guard SOC** detects the drive, comes to the front, and scans risky files (`.exe`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.lnk`, `.dll`, `.scr`, `.msi`, `autorun.inf`, etc.).
3. Read the color-coded results:
   - **Red (`Malicious`)**: Confirmed threat. **Do NOT open it.**
   - **Yellow (`Suspicious`)**: Suspicious behavior found—double-click the row to inspect details first.
   - **Green (`Safe`) / Blue (`Clean Locally`)**: No threats found.
4. **View Details:** Double-click any row (or click **View Details**) to see SHA-256 hash, heuristic findings, binary entropy, and antivirus vendor results.
5. **Quarantine Threats:** Select a flagged file and click **Quarantine Selected** to safely disarm and isolate it.
6. **Restore or Delete Permanently:** Click **Manage Quarantine** (top right) to restore false positives or permanently delete malware.
7. **Export Report:** Click **Export CSV Report** (bottom right) to save a spreadsheet report of the scan.

---

## Log & Data Paths

| Purpose | Path |
|---|---|
| Settings & API Key | `%LOCALAPPDATA%\USB_Guard_SOC\settings.json` |
| 7-Day VirusTotal Cache | `%LOCALAPPDATA%\USB_Guard_SOC\vt_hash_cache.json` |
| SOC Security Event Logs | `C:\ProgramData\USB_Guard_SOC\logs\usb_security_events.json` |
| Quarantined Files | `<USB>:\.usb_quarantine\` |
