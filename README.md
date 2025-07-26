# STIG-GOAT.ps1
# GOAT – Governance, Orchestration, Automation, & Telemetry 
STIG-GOAT.ps1 automates the evaluation of Windows hosts and Cisco devices against Security Technical Implementation Guides (STIGs), using the Evaluate-STIG tool and live logging to a network share.  
**This script is intended as a reference template only. Review and adapt for your own environment.**

---

## ⚠️ WARNING

- **Do NOT hardcode passwords or sensitive credentials in scripts.**  
  Always use secure credential management (environment variables, vaults, etc).
- This script performs destructive file operations (`Remove-Item -Recurse -Force`).  
  **Test in a non-production environment first.**
- Scheduled tasks may be created with admin privileges.  
  Know what you’re doing.
- No warranty, no support.  
  Use at your own risk.

---

## Prerequisites

- **PowerShell 5.1+** (tested on Windows, not cross-platform)
- **Network Share**:  
  - UNC path (e.g., `\\x.x.x.x\EvalSTIG-Operational`) must exist and be accessible from all hosts.
  - All hosts must have permission to read/write required subdirectories.
- **Evaluate-STIG Tool**:  
  - Must be available in the designated directory in your share.
- **Cisco Devices (if used)**:  
  - SSH access enabled, reachable from STIGManPrep host.
  - Username/password for SSH (do **NOT** store in plaintext).
  - SSH HostKeys for each device (replace example keys in script).
  - [Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) (`plink.exe`) must be available in the share under `Tools`.
- **STIGManPrep Host**:  
  - Identify a single host to perform aggregation and Cisco operations (`$STIGManPrepHost`).
  - Must have rights to create and run scheduled tasks (if Cisco automation enabled).
- **Directory Structure**:  
  - The script expects or creates several directories both locally (default: `C:\CYBERSECURITY`) and on the network share.
  - Change `$LocalESTIGOperational` if root C: is not writable or not desirable.
- **Permissions**:  
  - Script may require Administrator rights for certain scheduled tasks and file operations.
- **PowerShell Execution Policy**:  
  - Scripts may need to be signed or run with execution policy adjusted as appropriate for your environment.

---

## Checklist Aggregation

After successful execution, **all checklists from all hosts will be aggregated into the `_STIG-Manager` directory** on your network share. This directory contains the latest consolidated results and is the central location for reporting and further processing.

If you are using the **STIGMan-Watcher** application, simply point it at the `_STIG-Manager` directory. STIGMan-Watcher will monitor this directory for new or updated checklists automatically.

---

## Setup / Initial Variable Configuration

Before running the script, set these variables:

```powershell
# Share configuration
$Share = "\\x.x.x.x\EvalSTIG-Operational" # Update to your actual network share

# Host acting as the prep/aggregation node
$STIGManPrepHost = "<hostname>" # Set to your designated STIGManPrep hostname

# Cisco automation configuration (if used)
$EnableCisco = 1 # Set to 1 to enable, 0 to disable
$Username    = "<username>"  # SSH username (do NOT hardcode in prod)
$Password    = "<password>"  # SSH password (do NOT hardcode in prod)
$CiscoDevices = @(           # List of Cisco devices to scan
    @{
        hostname = '<Hostname1>'
        IP       = 'x.x.x.x'
        HostKey  = 'ssh-rsa ...'
    }
    # Add more as needed...
)

# AnswerFile and Evaluate-STIG parameters
$ScanType   = "Unclassified"  # Or as needed
$Output     = "CombinedCKLB"
$AnswerKey  = $env:COMPUTERNAME
$ExcludeSTIG = "MSDefender,WinFirewall,Apache24SvrWin,Apache24SiteWin"

# Other script options
$PrepWaitTime = 240 # Minutes to wait for hosts to report
$VerifyFindings = 1 # Enable findings verification
$ArchiveAge = 90    # Days to retain archives
