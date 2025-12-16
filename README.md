# System Administration & Utility Scripts

A collection of system administration, automation, and utility scripts for Linux, macOS, and Windows environments.

## 📋 Table of Contents

- [Scripts Overview](#scripts-overview)
- [Requirements](#requirements)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [License](#license)

-----

## Scripts Overview

### 1. **eBPF Enabler** (`ebpf-enabler.sh`)

**Platform:** Linux (Bash)
**Purpose:** Enables unprivileged eBPF (extended Berkeley Packet Filter) programs on Linux systems.

**Features:**

- Checks current eBPF status (enabled/hard disabled/soft disabled)
- Automatically enables eBPF if it’s soft disabled
- Provides clear status messages about the current state

**Status Values:**

- `0` = eBPF enabled
- `1` = Hard disabled (reboot required to enable)
- `2` = Soft disabled (can be enabled without reboot)

**Usage:**

```bash
sudo ./ebpf-enabler.sh
```

**Security Warning:** Enabling unprivileged eBPF introduces security risks. Only use in trusted environments.

-----

### 2. **Backup Script** (`backup.sh`)

**Platform:** macOS/Linux (Bash)
**Purpose:** Creates backup copies of directories from one location to another.

**Features:**

- Validates source and destination paths before backup
- Creates complete directory copies using `rsync`
- Provides feedback on backup success/failure

**Configuration:**
Edit the script to set your paths:

```bash
source_path="/path/to/source"
destination_path="/path/to/destination"
main_copy_path="/path/to/main copy"
backup_copy_path="/path/to/backup copy"
```

**Usage:**

```bash
./backup.sh
```

-----

### 3. **Disable Startup Apps** (`disable-startup-apps.sh`)

**Platform:** macOS (Bash)
**Purpose:** Removes specified applications from macOS login items (startup apps).

**Features:**

- Disables multiple apps from launching at startup
- Uses AppleScript via `osascript` for system integration

**Configuration:**
Edit the `APPS` array to specify which applications to disable:

```bash
APPS=("Splice" "Spotify" "YourAppName")
```

**Usage:**

```bash
./disable-startup-apps.sh
```

-----

### 4. **Software Validation Script** (`software-validation.ps1`)

**Platform:** Windows (PowerShell)  
**Purpose:** Validates software installation/removal and sends telemetry data to Logscale/Humio.

**Features:**

- Checks for software presence via multiple methods:
  - Windows Services
  - Installation folders
  - Registry keys
- Sends validation results to CrowdStrike NGSiem (Formerly Logscale) for monitoring
- Includes logging functionality
- Example implementation for Symantec Endpoint Protection (SEP)

**Configuration:**

1. Update the Logscale URL in the `SendTo-Logscale` function
1. Add your Logscale authentication token
1. Customize the software paths and registry keys to check

**Usage:**

```powershell
.\software-validation.ps1
```

**Example Output:**

```
SEP Service       : Present
SEP Folder        : Not Present
SEP Registry Key  : Present
ComputerName      : HOSTNAME
DataType          : SEP Check
```

-----

### 5. **Car Matching Game** (`car-game.py`)

**Platform:** Cross-platform (Python)  
**Purpose:** Interactive command-line game to match car makes with their models.

**Features:**

- Match car manufacturers with correct models
- Win by finding 3 correct matches
- Input validation and error handling
- Manual exit option (enter `9`)

**Car Matches:**

- Genesis → G70
- Audi → RS3
- BMW → M3
- Cadillac → CT4-V
- Mercedes-AMG → C63
- Acura → Type S

**Usage:**

```bash
python3 car-game.py
```

-----

### 6. **Secure Password Generator** (`password-generator.py`)

**Platform:** Cross-platform (Python)  
**Purpose:** Generates cryptographically secure random 16-character passwords.

**Features:**

- Uses Python’s `secrets` module for cryptographic randomness
- Generates alphanumeric passwords (letters + digits)
- 16 characters in length
- Commented-out code for saving to temporary files (optional feature)

**Usage:**

```bash
python3 password-generator.py
```

**Output:**

```
aB3dE9fG2hI7jK1m
```

-----

## Requirements

### Bash Scripts

- **Linux/macOS:** Bash shell (usually pre-installed)
- **Permissions:** Some scripts require `sudo` privileges

### PowerShell Script

- **Windows:** PowerShell 5.1 or later
- **Network:** Access to Logscale/Humio endpoint
- **Permissions:** Administrator rights for some checks

### Python Scripts

- **Python:** Version 3.6 or later
- **Modules:** All use standard library modules (no external dependencies)

-----

## Usage

1. **Clone the repository:**

```bash
git clone https://github.com/slashroot305/programs_and_scripts.git
cd programs_and_scripts
```

1. **Make scripts executable (Linux/macOS):**

```bash
chmod +x *.sh
```

1. **Run the desired script:**

```bash
# Bash scripts
./ebpf-enabler.sh
./backup.sh
./disable-startup-apps.sh

# PowerShell script
.\software-validation.ps1

# Python scripts
python3 car-game.py
python3 password-generator.py
```

-----

## Security Considerations

### Important Security Notes

1. **eBPF Enabler:** Enabling unprivileged eBPF can expose your system to local privilege escalation vulnerabilities. Only use in controlled, trusted environments.
1. **Software Validation Script:**
- Keep your Logscale token secure
- Never commit tokens to version control
- Use environment variables or secure credential storage
1. **Backup Script:**
- Ensure proper permissions on backup destinations
- Validate backup integrity after creation
- Consider encryption for sensitive data
1. **Password Generator:**
- Store generated passwords securely (password manager recommended)
- Do not transmit passwords over insecure channels

-----

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

-----


## Author

** slashroot305 **

-----

## Version History

- **v1.0** - Initial release
  - eBPF enabler script
  - Backup automation
  - macOS startup app manager
  - Software validation with Logscale integration
  - Car matching game
  - Secure password generator

-----

## Support

For issues, questions, or contributions, please open an issue in the GitHub repository.