# STIG-GOAT.ps1
$ScriptVersion = 1.0

# LastModifiedDate 25JUL2025
# ==================== GLOBAL VARIABLES & ENVIRONMENT ====================

# Replace with your share path, ensure it is accessible by all hosts. Ensure share name is "EvalSTIG-Operational"
$Share = "\\x.x.x.x\EvalSTIG-Operational"

# Wipe out local cybersecurity working directory (for testing or initial setup)
# Remove-Item -Path C:\CYBERSECURITY -Force -Recurse -ErrorAction SilentlyContinue

# ==================== GENERAL CONFIGURATION ====================
# Host that handles phase 2 STIGMAN-Prep execution
$STIGManPrepHost  = "<hostname>"
# Max wait time in minutes to wait for all hosts before running STIGMANPrep
$PrepWaitTime     = 240 
# Compares data to previous Evaluate-STIG runs and execute Evaluate-STIG again if findings increase to verify the increase was a valid result. 
$VerifyFindings   = 1
# Age in days to keep daily archives of the _STIG-Manager directory
$ArchiveAge       = 90 

# ==================== EVALUATE-STIG SETTINGS ====================
$ScanType     = "Unclassified"
$Output       = "CombinedCKLB"
# Default AnswerKey is the computer name for answer files
$AnswerKey    = $env:COMPUTERNAME 
# Exclude certain STIGs 
$ExcludeSTIG = "MSDefender,WinFirewall,Apache24SvrWin,Apache24SiteWin"

# ==================== CISCO DEVICES CONFIGURATION ====================
# Enable or disable CISCO checklist automation
$EnableCisco = 1 

$PlinkSharePath = Join-Path $Share "Tools\Plink.exe"
#Note, this account needs access to ssh into CISCO devices and run the 'show tec' command, 
# AND permissions to create and execute scheduled tasks on the $STIGManPrepHost for this automation to work.
$Username = "<username>" # Replace with your SSH username
$Password = "<password>" # Replace with your SSH password
# Use Remove-Item -Path "HKCU:\Software\SimonTatham\PuTTY\SshHostKeys" -Recurse to view HostKey again when SSHing
$CiscoDevices = @(
    @{
        hostname = '<Hostname1>'
        IP       = 'x.x.x.x' # Replace with actual IP
        HostKey  = 'ssh-rsa 4096 SHA256:kjbakjsndl;wmkjnwjbenhjbas' #example HostKey, replace with actual
    },
    @{
        hostname = '<Hostname2>'
        IP       = 'x.x.x.x' # Replace with actual IP
        HostKey  = 'ssh-rsa 2048 SHA256:dsgmaSFGhlkemklmwkejnwkncjdf' #example HostKey, replace with actual
    }
    # Add more as needed...
)

# =================== DO NOT MODIFY BELOW THIS LINE ===================
# ==================== DERIVED PATHS AND VARIABLES ====================

$hostname              = $env:COMPUTERNAME
$LocalESTIGOperational = "C:\CYBERSECURITY\EvalSTIG-Operational"
$ShareAFPath           = Join-Path $Share "AnswerFiles"
$FindingsLog           = "C:\CYBERSECURITY\FindingsLog.csv"
$LogFile               = "C:\CYBERSECURITY\$hostname-ESTIG-Log.txt"
$LocalAFPath           = "$LocalESTIGOperational\AnswerFiles"
$SumLogFile            = "$Share\Logs\STIGMANPrepSummary.log"
$Marking               = $ScanType
$ScriptStartTime       = Get-Date
$AFPath                = "$LocalESTIGOperational\AnswerFiles"
$LocalCKLDir           = Join-Path -Path $LocalESTIGOperational $hostname
$CKLDir                = Join-Path -Path $Share "Checklists"
# ==================== FUNCTIONS ====================

function LogMsg {
    param (
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$Timestamp - $Message"
}

function LogSum {
    param (
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $SumLogFile -Value "$Timestamp - $Message"
}

function Get-OpenNRTotal {
    param($LogPath)
    if (-not (Test-Path $LogPath)) { return $null }
    $OpenNRLines = Select-String -Path $LogPath -Pattern 'OpenNRTotal: (\d+)' | ForEach-Object {
        [int]($_.Matches[0].Groups[1].Value)
    }
    return ($OpenNRLines | Measure-Object -Sum).Sum
}

function Get-LastTwoFindings {
    $csv = Import-Csv $FindingsLog
    if ($csv.Count -lt 2) {
        LogMsg "Not enough entries in $FindingsLog for comparison"
        return $null
    }
    $PrevFindings = [int]$csv[-2].OpenFindings
    $CurrFindings = [int]$csv[-1].OpenFindings

    LogMsg "Previous run Open\NR findings: $PrevFindings"
    LogMsg "Current run Open\NR findings: $CurrFindings"

    return @($PrevFindings, $CurrFindings)
}

function Get-LastFinding {
    $csv = Import-Csv $FindingsLog
    if ($csv.Count -eq 0) {
        LogMsg "No entries in $FindingsLog to determine findings."
        return $null
    }
    $CurrFindings = [int]$csv[-1].OpenFindings
    LogMsg "Current run Open\NR findings: $CurrFindings"
    return $CurrFindings
}

function ESTIGRun {
    $StartTime      = Get-Date
    $ScriptPath     = "$LocalESTIGOperational\Evaluate-STIG\Evaluate-STIG.ps1"
    $OutputPath     = "$LocalESTIGOperational"

    LogMsg "Executing Evaluate-STIG..."

    if (-not (Test-Path $ScriptPath)) {
        LogMsg "The script $ScriptPath does not exist."
        return
    }

    gpupdate.exe /force | Out-Null

    $Command = "& `"$ScriptPath`" -ScanType $ScanType -Output $Output -AnswerKey $AnswerKey -AFPath `"$AFPath`" -OutputPath `"$OutputPath`" -ExcludeSTIG $ExcludeSTIG -Marking $Marking"

    Invoke-Expression $Command

    $EndTime = Get-Date
    $Duration = $EndTime - $StartTime

    $Minutes = [math]::Floor($Duration.TotalSeconds / 60)
    $Seconds = [math]::Round($Duration.TotalSeconds % 60)
    # ================== CLEANUP UN-NEEDED CHECKLISTS  ==================

    $currentCKL = Get-ChildItem -Path "$LocalESTIGOperational\$hostname\Checklist" -Filter "*.cklb" -ErrorAction SilentlyContinue
    $currentCKL | Where-Object { $_.Name -cmatch 'master|model|msdb|tempdb' } | Remove-Item -Force #removes un-needed master, model, msdb, tempdb checklists for databases 
    $CurrentLogPath = Join-Path $LocalCKLDir "Evaluate-STIG.log"
    $OpenFindings = Get-OpenNRTotal $CurrentLogPath
    $CsvExportData = [PSCustomObject]@{
        Date         = (Get-Date).ToString("s")
        Host         = $hostname
        OpenFindings = $OpenFindings
        Duration     = "{0}m {1}s" -f $Minutes, $Seconds
    }

    if (-not (Test-Path $FindingsLog)) {
        # File doesn't exist, create with headers
        $CsvExportData | Export-Csv -Path $FindingsLog -NoTypeInformation
    } else {
        # File exists, append without headers
        $CsvExportData | Export-Csv -Path $FindingsLog -NoTypeInformation -Append
    }
    LogMsg "Open\NR findings: $OpenFindings"

    LogMsg ("Evaluate-STIG completed in {0}m, {1}s" -f $Minutes, $Seconds)
    return $OpenFindings
}

# PHASE 1: Prepare and Execute Evaluate-STIG
#######################################################
# STEP 1: Ensure local and share directories exist, map to share
#######################################################
# ================== LOG & Report Cleanup ==================
# Remove old log file
Remove-Item -Path $LogFile -Force -ErrorAction SilentlyContinue

# ================== LOCAL DIRECTORY SETUP ==================
$localSubdirectories = @(
    "AnswerFiles",
    "Evaluate-STIG",
    "$hostname",
    "Scripts",
    "Tools"
)

foreach ($subdir in $localSubdirectories) {
    $fullPath = Join-Path -Path $LocalESTIGOperational -ChildPath $subdir
    if (-not (Test-Path -Path $fullPath)) {
        New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
    }
}
LogMsg "Executing Automate-STIG.ps1 script version $ScriptVersion on $hostname"
LogMsg "--------STEP 1--------"
LogMsg "Ensured required local subdirectories exist"

# ================== VERIFY SHARE ACCESS ==================
if (Test-Path -Path $Share) {

    if ($hostname -eq $STIGManPrepHost) { 
    Remove-Item -Path $SumLogFile -Force -ErrorAction SilentlyContinue
}

    # --- Move logs to share ---
    $ESTIGLogs      = "$Share\Logs\ESTIG-Logs"
    $logFileOnShare = Join-Path $ESTIGLogs "$hostname-ESTIG-Log.txt"

    if (-not (Test-Path -Path $ESTIGLogs)) {
        New-Item -ItemType Directory -Path $ESTIGLogs -Force | Out-Null
    }

    if (Test-Path -Path $logFileOnShare) {
        Remove-Item -Path $logFileOnShare -Force -ErrorAction SilentlyContinue
    }

    LogMsg "Host has share access, moving log file to $logFileOnShare"
    Copy-Item -Path $LogFile -Destination $logFileOnShare -Force

    if (Test-Path -Path $logFileOnShare) {
        $LogFile = $logFileOnShare
    } else {
        LogMsg "Failed to move $LogFile to share"
    }

    # --- Build share directory structure ---
    if ($hostname -eq $STIGManPrepHost) {
        $shareSubdirectories = @(
            "Logs\ESTIG-Logs",
            "Checklists\_STIG-Manager",
            "Checklists\$hostname",
            "Checklists\_Manual",
            "Checklists\_Archive"
        )
    } else {
        $shareSubdirectories = @(
            "Checklists\$hostname\Checklist"
        )
    }

    # --- Ensure all required share subdirectories exist ---
    foreach ($subdir in $shareSubdirectories) {
        $fullPath = Join-Path -Path $Share -ChildPath $subdir
        if (-not (Test-Path -Path $fullPath)) {
            New-Item -Path $fullPath -ItemType Directory | Out-Null
        }
    }
    LogMsg "Ensured required share subdirectories exist"
} else {
    LogMsg "Cannot access $Share with provided credentials. Exiting Script"
    exit 1
}

# Remove any existing checklists in host checklist directory just in case

$HostCKLDir = Join-Path -Path $CKLDir "$hostname\Checklist"

if (Test-Path $HostCKLDir) {
    $files = Get-ChildItem -Path $HostCKLDir -File -Recurse -ErrorAction SilentlyContinue
    if ($files.Count -gt 0) {
        Remove-Item -Path $files.FullName -Force -ErrorAction SilentlyContinue
        LogMsg "Files removed from $HostCKLDir"
    }
} else {
    Write-Host "Directory does not exist: $HostCKLDir"
}

#######################################################
# STEP 2: Update Answer Files and Evaluate-STIG
# Note: A random stagger time is added based on total number of 
#       online hosts if updates are detected to assist with saturating
#       file server network bandwidth
#######################################################
LogMsg "--------STEP 2--------"
#LogMsg "Waiting for share to stabilize..."
Start-Sleep -Seconds 30 # Initial sleep to allow share to stabilize
LogMsg "Checking for updates to Answer Files and Evaluate-STIG..."

$ESTIGLogs      = "$Share\Logs\ESTIG-Logs"
$Today = (Get-Date).Date

# Get log files modified today
$TodaysLogs = Get-ChildItem -Path $ESTIGLogs -File | Where-Object {
    $_.LastWriteTime.Date -eq $Today
}

$HostCount = $TodaysLogs.Count
$MaxStaggerSeconds = $HostCount * 3 # 3 seconds per host
if ($MaxStaggerSeconds -lt 1) {
    $StaggerSeconds = 0
} else {
    $StaggerSeconds = Get-Random -Minimum 0 -Maximum $MaxStaggerSeconds
}

# ================== ANSWER FILES UPDATE ==================

# Get latest last-modified times, rounded to nearest minute
$ShareLastModified = (Get-ChildItem -Path $ShareAFPath -File | Measure-Object -Property LastWriteTime -Maximum).Maximum
$ShareLastModifiedRounded = [datetime]::ParseExact($ShareLastModified.ToString("yyyy-MM-dd HH:mm"), "yyyy-MM-dd HH:mm", $null)

$LocalFiles = Get-ChildItem -Path $LocalAFPath -File
if ($LocalFiles) {
    $LocalLastModified = ($LocalFiles | Measure-Object -Property LastWriteTime -Maximum).Maximum
    $LocalLastModifiedRounded = [datetime]::ParseExact($LocalLastModified.ToString("yyyy-MM-dd HH:mm"), "yyyy-MM-dd HH:mm", $null)
} else {
    $LocalLastModifiedRounded = $null
}

# If local is missing or older, trigger update
if (-not $LocalLastModifiedRounded -or $LocalLastModifiedRounded -lt $ShareLastModifiedRounded) {
    LogMsg "Local Answer files are outdated or missing. Updating..."
    LogMsg "Detected $HostCount hosts reporting live today. Applying random stagger up to $MaxStaggerSeconds seconds based on total reporting hosts: Stagger for $StaggerSeconds seconds."
    Start-Sleep -Seconds $StaggerSeconds
    Remove-Item "$LocalAFPath\*" -Force -ErrorAction SilentlyContinue
    Copy-Item -Path "$ShareAFPath\*" -Destination $LocalAFPath -Force
    LogMsg "Answer files updated!"
} else {
    LogMsg "Local Answer files are current."
}

# ================== EVALUATE-STIG SCRIPTS UPDATE ==================
$ShareESTIGPath  = Join-Path $Share "Evaluate-STIG"
$LocalESTIGPath  = "$LocalESTIGOperational\Evaluate-STIG"

$ShareLastModified = (Get-ChildItem -Path $ShareESTIGPath -File | Measure-Object -Property LastWriteTime -Maximum).Maximum

$LocalFiles = Get-ChildItem -Path $LocalESTIGPath -File
if ($LocalFiles) {
    $LocalLastModified = ($LocalFiles | Measure-Object -Property LastWriteTime -Maximum).Maximum
} else {
    $LocalLastModified = $null
}

if (-not $LocalLastModified -or $LocalLastModified -lt $ShareLastModified) {
    LogMsg "Local Evaluate-STIG is outdated or missing. Updating..."
    LogMsg "Detected $HostCount hosts reporting live today. Applying random stagger up to $MaxStaggerSeconds seconds based on total reporting hosts: Stagger for $StaggerSeconds seconds."
    Start-Sleep -Seconds $StaggerSeconds
    Remove-Item "$LocalESTIGPath\*" -Force -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$ShareESTIGPath\*" -Destination $LocalESTIGPath -Force -Recurse
    LogMsg "Evaluate-STIG updated!"
} else {
    LogMsg "Evaluate-STIG is current."
}

#######################################################
# STEP 3: Run Evaluate-STIG, Process And Verify Findings
#######################################################
LogMsg "--------STEP 3--------"

# Unblock all files under CYBERSECURITY before running
Get-ChildItem -Path "C:\CYBERSECURITY" -Recurse | Unblock-File

# Verify Evaluate-STIG script exists, or exit
$EvaluateSTIGScript = "$LocalESTIGOperational\Evaluate-STIG\Evaluate-STIG.ps1"

if (-not (Test-Path -Path $EvaluateSTIGScript)) {
    LogMsg "Evaluate-STIG script not found. Exiting."
    exit 1
}

# Always run Evaluate-STIG at least once
ESTIGRun

if ($VerifyFindings -eq 1) {

    # If this is the first-ever run, do it again to ensure we have two entries
    $findingsPair = Get-LastTwoFindings
    
    if ($null -eq $findingsPair) {
        LogMsg "Running Evaluate-STIG again to initialize findings history..."
        ESTIGRun
        $findingsPair = Get-LastTwoFindings
    }

    # Now do the run-until-stable loop
    $maxAttempts = 4
    $attempt = 0

    # Only run if findingsPair is not null and the last two are not equal
    while ($null -ne $findingsPair -and $findingsPair[0] -ne $findingsPair[1] -and $attempt -lt $maxAttempts) {
        $attempt++
        LogMsg "Running ESTIGRun (attempt $attempt)..."
        ESTIGRun
        $findingsPair = Get-LastTwoFindings
    }

    if ($null -ne $findingsPair -and $findingsPair[0] -eq $findingsPair[1]) {
        LogMsg "Results are verified: $($findingsPair[1]) Open\NR findings."
    } elseif ($null -ne $findingsPair) {
        LogMsg "WARNING: Did not get stable results after $maxAttempts attempts. Last two: $($findingsPair[0]), $($findingsPair[1])"
    } else {
        LogMsg "WARNING: Could not obtain two findings entries for comparison."
    }
} else {
    LogMsg "'VerifyFindings' is disabled, skipping findings verification."
}

#######################################################
# STEP 4: Move All Data to Share
#######################################################
LogMsg "--------STEP 4--------"
# ======= DEFINE PATHS =======
$CKLDir             = Join-Path -Path $Share "Checklists"
$HostCKLDir         = Join-Path -Path $CKLDir "$hostname\Checklist"
$LocalPath          = "$LocalESTIGOperational\$hostname"
$LocalCKLPath       = Join-Path $LocalPath "Checklist"

# ======= ENSURE SHARED DIRECTORIES EXIST =======
if (-not (Test-Path -Path $HostCKLDir)) {
    New-Item -ItemType Directory -Path $HostCKLDir -Force | Out-Null
}

# ======= CHECK FOR LOCAL CHECKLISTS =======
$LocalCKLCount = (Get-ChildItem -Path $LocalCKLPath -Filter "*.cklb" -ErrorAction SilentlyContinue).Count

if ($LocalCKLCount -gt 0) {

    # ----- CLEAN & UPDATE SHARED CKL DIRECTORY -----
    if (-not (Test-Path -Path $HostCKLDir)) {
        New-Item -ItemType Directory -Path $HostCKLDir -Force | Out-Null
    } else {
        Remove-Item -Path "$HostCKLDir\*" -Force -ErrorAction SilentlyContinue
    }

    Move-Item -Path "$LocalCKLPath\*" -Destination $HostCKLDir -Force
    LogMsg "Moved $LocalCKLCount Checklist(s) to share"

} else {
    LogMsg "No local checklists found for $hostname"
}

# ======= FINAL TIMING AND CLEANUP =======
$ScriptEndTime = Get-Date
$Duration = $ScriptEndTime - $ScriptStartTime
$Minutes = [math]::Floor($Duration.TotalSeconds / 60)
$Seconds = [math]::Round($Duration.TotalSeconds % 60)
LogMsg "----------------------"
LogMsg ("Total Script Execution completed in {0}m, {1}s" -f $Minutes, $Seconds)

# PHASE 2: STIGManPrep
#######################################################
# STEP 5: Populate 'show tec' Logs & Run Evaluate-STIG for Cisco Devices
#######################################################

if ($hostname -eq $STIGManPrepHost) {
LogSum "--------STEP 5--------"
LogSum "$hostname is the designated STIGManPrep host."
if ($EnableCisco -eq 1){
    # ========== INITIAL SETUP ==========
    $CiscoStartTime = Get-Date

    LogSum "Beginning Cisco checklist preparation."

    # Cisco static info
    $plinkPath = "$LocalESTIGOperational\Tools\plink.exe"
    $port      = 22
    $command   = 'show tec'
    $CKLDir    = Join-Path -Path $Share "Checklists"

    # Ensure plink exists
    if (-not (Test-Path -Path $plinkPath)) {
        if (Test-Path -Path $PlinkSharePath) {
            #LogSum "Plink.exe not found locally. Copying from share..."
            Copy-Item -Path $PlinkSharePath -Destination $plinkPath -Force

            # Unblock the copied file
            try {
                Unblock-File -Path $plinkPath
                #LogSum "Unblocked plink.exe after copying."
            } catch {
                LogSum "WARNING: Failed to unblock plink.exe: $_"
            }
        } else {
            LogSum "ERROR: Plink.exe not found at expected share path: $PlinkSharePath"
            throw "Missing required file: plink.exe"
        }
    }

    # ========== CREATE AND SCHEDULE TASKS FOR EACH DEVICE ==========
    foreach ($device in $CiscoDevices) {
        $batDir       = Join-Path "$LocalESTIGOperational\Tools" $device.hostname
        $outputFile   = Join-Path $batDir 'showtec.txt'
        $doneFile     = Join-Path $batDir 'done.txt'
        $batFilePath  = Join-Path $batDir 'show-tec.bat'
        $taskName     = "ShowTec_$($device.hostname)"
    
        # Ensure batch directory exists
        if (-not (Test-Path $batDir)) {
            New-Item -ItemType Directory -Path $batDir -Force | Out-Null
        } else {
            # Clean up old files just in case previous run failed unexpectedly
            Remove-Item -Path $outputFile, $doneFile -Force -ErrorAction SilentlyContinue
        }

        $CiscoLogFile = Join-Path $ESTIGLogs "$($device.hostname)-ESTIG-Log.txt"
        Remove-Item -Path $CiscoLogFile -Force -ErrorAction SilentlyContinue

    # Write batch script with plink and done.txt marker
    $batContent = @"
@echo off
"$plinkPath" -batch -ssh $Username@$($device.IP) -P $port -pw $Password -hostkey "$($device.HostKey)" "$command" > "$outputFile"
echo done > "$doneFile"
"@
    Set-Content -Path $batFilePath -Value $batContent -Encoding ASCII

    # Register scheduled task (in the future, triggered on demand)
    $TaskStartTime = (Get-Date).AddMinutes(60).ToString('HH:mm')
    $schtasksCmd = @"
schtasks.exe /Create /TN $taskName /TR `"$batFilePath`" /SC ONCE /ST $TaskStartTime /RL HIGHEST /RU $Username /RP $Password /F
"@
        try {
            Invoke-Expression $schtasksCmd | Out-Null
        } catch {
            LogSum "Failed to create scheduled task $taskName : $_"
        }
    }

    # ========== START ALL TASKS ==========
    foreach ($device in $CiscoDevices) {
        $taskName = "ShowTec_$($device.hostname)"
        try {
            schtasks.exe /Run /TN $taskName | Out-Null
           # LogSum "Started scheduled task $taskName"
        } catch {
            LogSum "Failed to start scheduled task $taskName : $_"
        }
    }

    # ========== WAIT FOR COMPLETION WITH TIMEOUT ==========
    $maxWaitSeconds = 900  # 15-minute max per device
    LogSum "Waiting for each device to populate show tec logs..."

    foreach ($device in $CiscoDevices) {
        $doneFile = Join-Path "$LocalESTIGOperational\Tools\$($device.hostname)" "done.txt"
        $elapsed  = 0

        while (-not (Test-Path $doneFile) -and $elapsed -lt $maxWaitSeconds) {
            Start-Sleep -Seconds 15
            $elapsed += 15
            #LogSum "Waiting on $($device.hostname)... [$elapsed seconds elapsed]"
        }

        if (Test-Path $doneFile) {
            #LogSum "$($device.hostname) completed successfully."
        } else {
            LogSum "WARNING: Timeout reached waiting for $($device.hostname). Proceeding without done.txt."
        }
    }

    # ========== CLEANUP TASKS AND BATCH FILES ==========
    foreach ($device in $CiscoDevices) {
        $batDir      = Join-Path "$LocalESTIGOperational\Tools" $device.hostname
        $batFilePath = Join-Path $batDir 'show-tec.bat'
        $taskName    = "ShowTec_$($device.hostname)"
        $outputFile  = Join-Path $batDir 'showtec.txt'

        if (Test-Path $outputFile) {
            LogSum "show tec log file created for $($device.hostname)"
            Remove-Item -Path $batFilePath -Force -ErrorAction SilentlyContinue
        } else {
            LogSum "Warning: No output found for $($device.hostname)"
            Remove-Item -Path $batFilePath -Force -ErrorAction SilentlyContinue
        }

        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            #LogSum "Removed scheduled task: $taskName"
        } catch {
            LogSum "Failed to remove scheduled task $taskName : $_"
        }
    }

    # ========== RUN EVALUATE-STIG AGAINST EACH DEVICE ==========
    $ThrottleLimit = 5
    $VulnTimeout   = 5
    $Output        = "CombinedCKLB"
    $ScriptPath    = "$LocalESTIGOperational\Evaluate-STIG\Evaluate-STIG.ps1"

    foreach ($device in $CiscoDevices) {
        $showTecPath = Join-Path (Join-Path "$LocalESTIGOperational\Tools" $device.hostname) 'showtec.txt'
        $AnswerKey = $($device.hostname)
        if (-not (Test-Path $showTecPath)) {
            LogSum "Skipping $($device.hostname): missing showtec.txt"
            continue
        }

        LogSum "Running Evaluate-STIG for $($device.hostname)..."
        & $ScriptPath -ScanType $ScanType -Output $Output -AnswerKey $AnswerKey -AFPath $AFPath -OutputPath $CKLDir -CiscoConfig $showTecPath -ThrottleLimit $ThrottleLimit -VulnTimeout $VulnTimeout -ExcludeSTIG $ExcludeSTIG -Marking $Marking

        $checklistPath = Join-Path -Path $CKLDir -ChildPath "$($device.hostname)\Checklist"
        $cklbFiles = @(Get-ChildItem -Path $checklistPath -Filter *.cklb -File -ErrorAction SilentlyContinue)

        if ($cklbFiles.Count -gt 0) {
            $CiscoLogFile = Join-Path $ESTIGLogs "$($device.hostname)-ESTIG-Log.txt"
            $AnswerKey = $($device.hostname)
            Add-Content -Path $CiscoLogFile "$AnswerKey finished processing"
        }
    }

    # ========== LOG DURATION ==========
    $CiscoEndTime   = Get-Date
    $CiscoDuration  = $CiscoEndTime - $CiscoStartTime
    $Minutes        = [math]::Floor($CiscoDuration.TotalSeconds / 60)
    $Seconds        = [math]::Round($CiscoDuration.TotalSeconds % 60)
    LogSum ("Cisco devices finished processing in {0}m, {1}s" -f $Minutes, $Seconds)
} else {
    LogSum "CISCO Automation Disabled"
}

#######################################################
# STEP 6: Wait for all hosts to report, aggregate checklists
#######################################################
LogSum "--------STEP 6--------"

# ======= INITIALIZE AND CONFIGURE WAIT LOGIC =======
$PrepStartTime  = Get-Date
$TotalWaitTime  = $PrepWaitTime * 60
$CheckInterval  = 60   # seconds between checks
$LogInterval    = 600  # seconds between logs
$Elapsed        = 0
$LogCounter     = 0

if ($CheckInterval -le 0) {
    LogSum "FATAL: CheckInterval must be > 0. Exiting script."
    exit 1
}

if ($CheckInterval -ge $LogInterval -or $LogInterval -le 0) {
    $LogEvery = 1
} else {
    $LogEvery = [int]([math]::Ceiling($LogInterval / $CheckInterval))
}

# ======= DISCOVER HOST FOLDERS AND LOGS UP FRONT =======
$AllHostFolders = Get-ChildItem -Path $CKLDir -Directory | Where-Object { !$_.Name.StartsWith('_') } | Select-Object -ExpandProperty Name
$Today = (Get-Date).Date
$TodaysLogs = Get-ChildItem -Path $ESTIGLogs -File | Where-Object { $_.LastWriteTime.Date -eq $Today }
$LiveHosts = $TodaysLogs | ForEach-Object {
    if ($_.Name -match "^(.*)-ESTIG-Log\.txt$") { $Matches[1] }
} | Where-Object { $_ } | Sort-Object -Unique

$CiscoHostnames = $CiscoDevices | ForEach-Object { $_.hostname }

$WaitHosts = $AllHostFolders | Where-Object { 
    ($LiveHosts -contains $_) -and
    ($CiscoHostnames -notcontains $_)
} | Sort-Object

Add-Content -Path $SumLogFile @"
Detected host folders: $($AllHostFolders.Count)
Detected hosts reporting today: $($LiveHosts.Count)
Hosts that will be waited on: $($WaitHosts.Count)
"@

# ======= MAIN WAIT LOOP =======
$StillMissing = @()
while ($Elapsed -lt $TotalWaitTime) {
    $StillMissing = @()
    foreach ($entry in $WaitHosts) {
        $checklistPath = Join-Path -Path $CKLDir -ChildPath "$entry\Checklist"
        if (-not (Test-Path $checklistPath)) {
            $StillMissing += $entry
            continue
        }
        $cklbFiles = @(Get-ChildItem -Path $checklistPath -Filter *.cklb -File -ErrorAction SilentlyContinue)
        if ($cklbFiles.Count -eq 0) {
            $StillMissing += $entry
        }
    }
    $ReportedHosts = $WaitHosts | Where-Object { $StillMissing -notcontains $_ }
    $MissingHosts  = $StillMissing

    if ($MissingHosts.Count -eq 0) {
        break
    }

    if (($LogCounter % $LogEvery) -eq 0) {
        $MinutesLeft = [math]::Max([math]::Floor(($TotalWaitTime - $Elapsed) / 60), 0)
        LogSum "$($ReportedHosts.Count)/$($WaitHosts.Count) hosts have reported. [$MinutesLeft minutes remaining]"
        # De-duplicate before logging, if you want interim missing logs
        # Add-Content -Path $SumLogFile -Value "$($MissingHosts | Sort-Object -Unique -join "`n")"
    }
    Start-Sleep -Seconds $CheckInterval
    $Elapsed    += $CheckInterval
    $LogCounter++
}

# After wait loop, before populating $FinalMissingHosts
$CiscoMissingChecklists = @()
foreach ($ciscoHost in $CiscoHostnames) {
    $checklistPath = Join-Path -Path $CKLDir -ChildPath "$ciscoHost\Checklist"
    $cklbFiles = @(Get-ChildItem -Path $checklistPath -Filter *.cklb -File -ErrorAction SilentlyContinue)
    if ($cklbFiles.Count -eq 0) {
        $CiscoMissingChecklists += $ciscoHost
    }
}

# ======= FINAL TALLY AND SUMMARY LOGGING =======
# Combine your "wait" missing hosts with Cisco hosts missing checklists
$FinalMissingHosts = $MissingHosts + $CiscoMissingChecklists | Sort-Object -Unique
$ReportedHosts     = $WaitHosts | Where-Object { $FinalMissingHosts -notcontains $_ }

if ($Elapsed -ge $TotalWaitTime -and $FinalMissingHosts.Count -gt 0) {
    LogSum "Timeout reached after $($TotalWaitTime/60)m. The following hosts did NOT report: $($FinalMissingHosts -join ', ')"
}

if ($FinalMissingHosts.Count -eq 0) {
    LogSum "All $($WaitHosts.Count) hosts have reported in before timeout."
} else {
    LogSum "$($ReportedHosts.Count)/$($WaitHosts.Count) hosts have reported. Hosts that did not report: $($FinalMissingHosts -join ', ')"
}

# ======= REPORT HOST FOLDERS WITH NO LOGS TODAY =======
$NonReportHosts = $AllHostFolders | Where-Object { $LiveHosts -notcontains $_ } | Sort-Object
if ($NonReportHosts.Count -gt 0) {
    LogSum "WARNING: $($NonReportHosts.Count) host folders exist but did NOT report logs today. These were NOT waited on:"
    LogSum "-----NON REPORTING HOSTS-----"
    Add-Content -Path $SumLogFile -Value ($NonReportHosts -join "`n")
    LogSum "-----------------------------"
}

# ======= COPY CHECKLISTS TO STIG-MANAGER DIR =======
$MovedCKLCount   = 0
$STIGManPrepDir  = Join-Path $CKLDir "_STIG-Manager"

# --- Archive setup ---
$ArchiveDate     = Get-Date -Format 'yyyyMMdd'
$DatedArchiveDir = Join-Path $CKLDir "_Archive\$ArchiveDate"
$ArchiveZipPath  = Join-Path $CKLDir "_Archive\$ArchiveDate.zip"

if (-not (Test-Path $DatedArchiveDir)) {
    New-Item -Path $DatedArchiveDir -ItemType Directory -Force | Out-Null
} else {
    LogSum "Clearing existing archive for today: $DatedArchiveDir"
    Remove-Item -Path (Join-Path $DatedArchiveDir '*') -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Keep only 90 most recent archive zips ---
$ArchiveParentDir = Join-Path $CKLDir "_Archive"
$archiveZips      = Get-ChildItem -Path $ArchiveParentDir -Filter *.zip | Sort-Object Name -Descending

if ($archiveZips.Count -gt $ArchiveAge) {
    $zipsToRemove = $archiveZips | Select-Object -Skip $ArchiveAge
    foreach ($zip in $zipsToRemove) {
        Remove-Item -Path $zip.FullName -Force -ErrorAction SilentlyContinue
        LogSum "Deleted old archive zip: $($zip.FullName)"
    }
}

If (Test-Path $DatedArchiveDir) {
    Move-Item -Path $STIGManPrepDir\* -Destination $DatedArchiveDir
    LogSum "Archived checklists in _STIG-Manager Directory to $DatedArchiveDir"
    
    # Zip the populated archive folder
    Compress-Archive -Path "$DatedArchiveDir\*" -DestinationPath $ArchiveZipPath -Force
    LogSum "Zipped archive to $ArchiveZipPath"
    
    # Remove the unzipped directory to save space (optional but recommended)
    Remove-Item -Path $DatedArchiveDir -Recurse -Force -ErrorAction SilentlyContinue
    LogSum "Removed unzipped archive directory: $DatedArchiveDir"
}

$ManualDir = Join-Path $CKLDir "_Manual"

If (Test-Path -Path $ManualDir) {
    $cklbFiles     = Get-ChildItem -Path $ManualDir -Filter *.cklb -File -ErrorAction SilentlyContinue
    foreach ($file in $cklbFiles) {
        Copy-Item -Path $file.FullName -Destination $STIGManPrepDir -Force -ErrorAction SilentlyContinue
        $MovedCKLCount++
    }
}

foreach ($hostName in $AllHostFolders) {
    $hostFolder    = Join-Path -Path $CKLDir -ChildPath $hostName
    $checklistPath = Join-Path $hostFolder "Checklist"
    $cklbFiles     = Get-ChildItem -Path $checklistPath -Filter *.cklb -File -ErrorAction SilentlyContinue
    foreach ($file in $cklbFiles) {
        Move-Item -Path $file.FullName -Destination $STIGManPrepDir -Force -ErrorAction SilentlyContinue
        $MovedCKLCount++
    }
}

# ======= FINAL SUMMARY =======
LogSum "------SUMMARY------"

if ($FinalMissingHosts.Count -gt 0) {
    LogSum "Hosts that did not report:"
    foreach ($entry in $FinalMissingHosts) {
        LogSum "$entry"
    }
} else {
    LogSum "$($ReportedHosts.Count)/$($WaitHosts.Count) Live hosts Reported!"
    LogSum "$($ReportedHosts.Count)/$($AllHostFolders.count) Reported out of all existing host directories"
}

LogSum "Total host directories scanned: $($AllHostFolders.Count)"
LogSum "Total checklists copied to STIG-Manager directory: $MovedCKLCount"

    ####################################
    # TIMING AND COMPLETION LOGGING
    ####################################

    LogSum "-------------------"
    LogSum "Automate-STIG Execution completed."
    $TotalEndTime = Get-Date
    $Duration = $TotalEndTime - $PrepStartTime
    $Minutes = [math]::Floor($Duration.TotalSeconds / 60)
    $Seconds = [math]::Round($Duration.TotalSeconds % 60)
    LogSum ("Total Phase 2 Execution Time: {0}m, {1}s" -f $Minutes, $Seconds)
}