<#
.SYNOPSIS
    Prepares the lab VM for detection testing (Sysmon, audit policy, Atomic Red Team).

.DESCRIPTION
    Configures the disposable attack-test VM so that Atomic Red Team activity
    produces the telemetry our Sentinel detections rely on.

    Target: Windows Server 2022, Windows PowerShell 5.1 (the VM has no pwsh 7).
    Designed to run unattended as SYSTEM via a managed Run Command: no prompts,
    no pauses. Idempotent: safe to re-run; each step converges to the desired
    state instead of assuming a clean machine.

    Pinned sources (pinned 2026-11-07):
      - Sysmon config : olafhartong/sysmon-modular, release tag
                        'configs-a45dedb13a43', file 'sysmonconfig-15.21.xml',
                        SHA-256 64BEC37BA849C5F2934A55D2A29E7DDFAE46A30D56F7F2908D1F8A454898797E
      - Sysmon binary : https://download.sysinternals.com/files/Sysmon.zip
                        minimum version 15.21, signer 'O=Microsoft Corporation'

    Logs to C:\DacSetup\setup.log (transcript, appended across runs).
    Exit code 0 on success, 1 on any failure.

.NOTES
    Issue: #18 (lab VM setup script)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# PS 5.1 defaults can exclude TLS 1.2, which GitHub and Sysinternals require.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# The PS 5.1 progress bar slows Invoke-WebRequest dramatically and is useless unattended.
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Pinned constants (pinned 2026-11-07)
# ---------------------------------------------------------------------------
$WorkDir = 'C:\DacSetup'
$LogPath = Join-Path $WorkDir 'setup.log'

$SysmonConfigTag    = 'configs-a45dedb13a43'
$SysmonConfigFile   = 'sysmonconfig-15.21.xml'
$SysmonConfigUrl    = "https://github.com/olafhartong/sysmon-modular/releases/download/$SysmonConfigTag/$SysmonConfigFile"
$SysmonConfigSha256 = '64BEC37BA849C5F2934A55D2A29E7DDFAE46A30D56F7F2908D1F8A454898797E'

$SysmonZipUrl      = 'https://download.sysinternals.com/files/Sysmon.zip'
$SysmonMinVersion  = [version]'15.21'
$SysmonSignerOrg   = 'O=Microsoft Corporation'
$SysmonServiceName = 'Sysmon64'

# Advanced audit subcategories to enable for Success (Failure is left untouched).
# Referenced by GUID, not name, because auditpol subcategory names are localized.
# Note: 1102 (audit log cleared) is always logged regardless of policy, and 7045
# (service installed) is written to the System log, so neither needs a subcategory.
$AuditSubcategories = @(
    [pscustomobject]@{ Name = 'Process Creation';           Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}' } # 4688
    [pscustomobject]@{ Name = 'User Account Management';    Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}' } # 4720
    [pscustomobject]@{ Name = 'Security Group Management';  Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}' } # 4732
    [pscustomobject]@{ Name = 'Other Object Access Events'; Guid = '{0CCE9227-69AE-11D9-BED3-505054503030}' } # 4698
    [pscustomobject]@{ Name = 'Logon';                      Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}' } # 4624
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Log {
    param([Parameter(Mandatory)][string]$Message)
    # Write-Host (not Write-Output) so log lines never leak into function return values.
    Write-Host ('[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message)
}

function Assert-Elevated {
    # Installing a driver/service and changing audit policy need admin rights.
    # SYSTEM's token includes the Administrators group, so this covers Run Command too.
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must run elevated (administrator or SYSTEM).'
    }
    Write-Log ("Running elevated as {0}" -f [Security.Principal.WindowsIdentity]::GetCurrent().Name)
}

function Assert-DacSysmonBinary {
    # Sysinternals only publishes a 'latest' Sysmon.zip, so its hash changes with
    # every release and can't be pinned. Instead we require a valid Microsoft
    # Authenticode signature (proves origin/integrity) and a minimum version
    # (proves it understands the 15.21 config schema).
    # -SkipVersionCheck lets the caller tell "untrusted" (throws here) apart from
    # "trusted but too old" (caller compares the returned version itself).
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$SkipVersionCheck
    )

    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        throw "Sysmon binary not found: $Path"
    }

    $sig = Get-AuthenticodeSignature -FilePath $Path
    # Check Status first: SignerCertificate is null for unsigned files.
    if ($sig.Status -ne 'Valid' -or $null -eq $sig.SignerCertificate -or
        $sig.SignerCertificate.Subject -notlike "*$SysmonSignerOrg*") {
        throw "Sysmon signature check failed for $Path. Status: $($sig.Status)."
    }
    Write-Log "Sysmon: signature valid for $Path ($($sig.SignerCertificate.Subject))"

    # Build the version from numeric parts: the FileVersion string format is not
    # guaranteed, and string comparison would rank '15.3' above '15.21'.
    $vi = (Get-Item -Path $Path).VersionInfo
    $version = New-Object Version($vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart)
    Write-Log "Sysmon: $Path is version $version (FileVersion string '$($vi.FileVersion)')"

    if (-not $SkipVersionCheck -and $version -lt $SysmonMinVersion) {
        throw "Sysmon version $version at $Path is below the required minimum $SysmonMinVersion."
    }
    return $version
}

function Get-DacSysmonServiceExe {
    # The service's own PathName is the only reliable source for which binary is
    # actually installed; the freshly downloaded copy may be a different version.
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$SysmonServiceName'"
    if ($null -eq $svc -or [string]::IsNullOrWhiteSpace($svc.PathName)) {
        throw "Could not read the executable path of service '$SysmonServiceName'."
    }

    # PathName may be quoted and may carry arguments: take the quoted part, or
    # everything up to and including the first '.exe'.
    $raw = [Environment]::ExpandEnvironmentVariables($svc.PathName.Trim())
    if ($raw -match '^"([^"]+)"') {
        $exe = $Matches[1]
    }
    elseif ($raw -match '^(.+?\.exe)(\s|$)') {
        $exe = $Matches[1]
    }
    else {
        throw "Unrecognised PathName for service '$SysmonServiceName': $raw"
    }
    return $exe
}

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
function Install-DacSysmon {
    Write-Log 'Sysmon: starting'

    # --- Config: verified by pinned hash ---
    # The config is a static release asset, so an exact hash pin is possible and
    # guarantees we apply exactly the reviewed ruleset (no silent upstream changes).
    $configPath = Join-Path $WorkDir $SysmonConfigFile
    Write-Log "Sysmon: downloading config $SysmonConfigTag/$SysmonConfigFile"
    Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $configPath -UseBasicParsing

    $actualHash = (Get-FileHash -Path $configPath -Algorithm SHA256).Hash
    if ($actualHash -ine $SysmonConfigSha256) {
        # Remove the bad file so a later run can't accidentally use it.
        Remove-Item -Path $configPath -Force -ErrorAction SilentlyContinue
        throw "Sysmon config hash mismatch. Expected $SysmonConfigSha256, got $actualHash."
    }
    Write-Log "Sysmon: config hash verified ($actualHash)"

    # --- Downloaded binary: verified by signature + minimum version ---
    $zipPath    = Join-Path $WorkDir 'Sysmon.zip'
    $extractDir = Join-Path $WorkDir 'Sysmon'
    Write-Log "Sysmon: downloading $SysmonZipUrl"
    Invoke-WebRequest -Uri $SysmonZipUrl -OutFile $zipPath -UseBasicParsing

    # Clear any previous extraction so stale binaries from an older run are never used.
    if (Test-Path -Path $extractDir) {
        Remove-Item -Path $extractDir -Recurse -Force
    }
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    # Verify the download up front even on re-runs: if the installed copy turns
    # out to be too old, this is the binary we will replace it with.
    $downloadedExe = Join-Path $extractDir 'Sysmon64.exe'
    $downloadedVersion = Assert-DacSysmonBinary -Path $downloadedExe

    # --- Install or update (idempotent) ---
    # -accepteula is passed on every call: the EULA flag is stored per user, and an
    # unaccepted EULA would open a dialog and hang an unattended SYSTEM run.
    $needsInstall = $true
    $existing = Get-Service -Name $SysmonServiceName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        $installedExe = Get-DacSysmonServiceExe
        Write-Log "Sysmon: service exists, installed binary is $installedExe"

        # Signature failure throws here on purpose: an untrusted binary registered
        # as Sysmon64 needs a human to look at it, not a silent replacement.
        $installedVersion = Assert-DacSysmonBinary -Path $installedExe -SkipVersionCheck

        if ($installedVersion -ge $SysmonMinVersion) {
            # Use the installed exe for -c so the config is applied by the same
            # version that will parse it, not by the newer download.
            Write-Log "Sysmon: installed version $installedVersion meets minimum, re-applying config"
            & $installedExe -accepteula -c $configPath |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { Write-Log "  sysmon: $_" }
            if ($LASTEXITCODE -ne 0) { throw "$installedExe -c failed with exit code $LASTEXITCODE." }
            $needsInstall = $false
        }
        else {
            # Too old to understand the pinned config schema: replace it. Uninstall
            # with the installed exe so its own driver/service are removed cleanly.
            Write-Log "Sysmon: installed version $installedVersion is below minimum $SysmonMinVersion, uninstalling"
            & $installedExe -u force |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { Write-Log "  sysmon: $_" }
            if ($LASTEXITCODE -ne 0) { throw "$installedExe -u force failed with exit code $LASTEXITCODE." }
        }
    }

    if ($needsInstall) {
        Write-Log "Sysmon: installing version $downloadedVersion from $downloadedExe"
        & $downloadedExe -accepteula -i $configPath |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { Write-Log "  sysmon: $_" }
        if ($LASTEXITCODE -ne 0) { throw "$downloadedExe -i failed with exit code $LASTEXITCODE." }
    }

    # --- Confirm it is actually running ---
    # A zero exit code doesn't prove events are flowing; the service must be up.
    # Allow a short grace period because a fresh install can still be starting.
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $svc = Get-Service -Name $SysmonServiceName -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq 'Running') { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)

    if ($null -eq $svc -or $svc.Status -ne 'Running') {
        $state = 'missing'
        if ($null -ne $svc) { $state = [string]$svc.Status }
        throw "Sysmon service '$SysmonServiceName' is not running (state: $state)."
    }
    # Re-check the binary the running service points at, so the log (and the exit
    # code) reflect what is actually running, whichever path was taken above.
    $runningExe = Get-DacSysmonServiceExe
    $runningVersion = Assert-DacSysmonBinary -Path $runningExe
    Write-Log "Sysmon: service '$SysmonServiceName' is Running ($runningExe, version $runningVersion)"
}

function Set-DacRegistryDword {
    # Idempotent DWORD setter: only writes when the value or its type differs,
    # so the log shows exactly what a given run changed.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value
    )

    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
        Write-Log "Registry: created key $Path"
    }

    # RegistryKey.GetValue returns $null for a missing value instead of throwing,
    # which Get-ItemProperty would do under -ErrorAction Stop.
    $key = Get-Item -Path $Path
    $current = $key.GetValue($Name, $null)
    $isDword = $false
    if ($null -ne $current) {
        $isDword = $key.GetValueKind($Name) -eq [Microsoft.Win32.RegistryValueKind]::DWord
    }

    if ($isDword -and $current -eq $Value) {
        Write-Log "Registry: $Path\$Name already $Value"
    }
    else {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
        Write-Log "Registry: $Path\$Name set to $Value (was '$current')"
    }
}

function Set-DacAuditPolicy {
    Write-Log 'Audit policy: starting'

    # Without this, 4688 records only the image path; detections on encoded or
    # suspicious arguments need the full command line.
    Set-DacRegistryDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1

    # Force subcategory (advanced) settings to override legacy category settings,
    # otherwise a category-level policy can silently undo the auditpol changes below.
    Set-DacRegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'SCENoApplyLegacyAuditPolicy' -Value 1

    # auditpol /set is itself idempotent, so we always apply and then verify.
    foreach ($sub in $AuditSubcategories) {
        & auditpol.exe /set "/subcategory:$($sub.Guid)" /success:enable |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { Write-Log "  auditpol: $_" }
        if ($LASTEXITCODE -ne 0) { throw "auditpol /set for '$($sub.Name)' $($sub.Guid) failed with exit code $LASTEXITCODE." }
    }

    # Verify by reading the effective policy back: a zero exit code from /set
    # doesn't prove the setting stuck (e.g. a GPO could override it).
    foreach ($sub in $AuditSubcategories) {
        $raw = & auditpol.exe /get "/subcategory:$($sub.Guid)" /r
        if ($LASTEXITCODE -ne 0) { throw "auditpol /get for '$($sub.Name)' $($sub.Guid) failed with exit code $LASTEXITCODE." }

        $row = @($raw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ConvertFrom-Csv) | Select-Object -First 1
        if ($null -eq $row -or $null -eq $row.PSObject.Properties['Inclusion Setting']) {
            throw "Could not parse auditpol output for '$($sub.Name)' $($sub.Guid)."
        }

        $setting = $row.'Inclusion Setting'
        Write-Log "Audit policy: $($sub.Name) = $setting"
        if ($setting -notlike '*Success*') {
            throw "Audit subcategory '$($sub.Name)' $($sub.Guid) is '$setting', expected Success."
        }
    }

    Write-Log 'Audit policy: done'
}

function Install-DacAtomicRedTeam {
    Write-Log 'TODO: Atomic Red Team (#18, session 2)'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$exitCode = 0
$transcriptStarted = $false
try {
    if (-not (Test-Path -Path $WorkDir)) {
        New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
    }
    Start-Transcript -Path $LogPath -Append | Out-Null
    $transcriptStarted = $true

    Write-Log '=== DAC lab setup: start ==='
    Assert-Elevated

    Install-DacSysmon
    Set-DacAuditPolicy
    Install-DacAtomicRedTeam

    Write-Log '=== DAC lab setup: success ==='
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Log "ERROR at: $($_.ScriptStackTrace)"
    Write-Log '=== DAC lab setup: FAILED ==='
    $exitCode = 1
}
finally {
    # Stop the transcript before exiting so the log is flushed and closed.
    if ($transcriptStarted) {
        try { Stop-Transcript | Out-Null } catch { }
    }
}

exit $exitCode
