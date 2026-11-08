<#
.SYNOPSIS
    Prepares the lab VM for detection testing (Sysmon, audit policy, Atomic Red Team).

.DESCRIPTION
    Configures the disposable attack-test VM so that Atomic Red Team activity
    produces the telemetry our Sentinel detections rely on.

    Target: Windows Server 2022, Windows PowerShell 5.1 (the VM has no pwsh 7).
    Runs automatically on deploy, as SYSTEM, via the managed Run Command
    rc-dac-setup in infra/lab/main.bicep; can still be run by hand over RDP
    from an elevated Windows PowerShell 5.1 prompt. Unattended: no prompts,
    no pauses. Idempotent: safe to re-run; each step converges to the desired
    state instead of assuming a clean machine.

    Pinned sources (pinned 2026-11-07):
      - Sysmon config : olafhartong/sysmon-modular, release tag
                        'configs-a45dedb13a43', file 'sysmonconfig-15.21.xml',
                        SHA-256 64BEC37BA849C5F2934A55D2A29E7DDFAE46A30D56F7F2908D1F8A454898797E
      - Sysmon binary : https://download.sysinternals.com/files/Sysmon.zip
                        minimum version 15.21, signer 'O=Microsoft Corporation'
      - Modules       : Invoke-AtomicRedTeam 2.3.0, powershell-yaml 0.4.12
                        (PSGallery, installed for AllUsers)
      - Atomics       : redcanaryco/atomic-red-team commit
                        a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6, archive
                        SHA-256 2392FB6DD4E6ACEA3E9087FC6FFDE0F7C20A32E873AD191366AFC8599FCC9EA2

    Steps:
      1. Sysmon        : install or update, apply the pinned config, confirm running.
      2. Audit policy  : enable the Success subcategories our rules need, verify.
      3. Atomic Red Team:
           - create C:\AtomicRedTeam and add it as a Microsoft Defender folder
             exclusion BEFORE anything is downloaded (atomics contain payloads
             Defender would otherwise quarantine mid-extraction);
           - install the pinned powershell-yaml and Invoke-AtomicRedTeam modules
             for AllUsers (the script runs as SYSTEM, tests run as the lab admin);
           - download the pinned atomics archive, verify its hash, extract only
             the atomics folder to C:\AtomicRedTeam\atomics, and record the
             commit in C:\AtomicRedTeam\atomics.commit;
           - run a read-only smoke test (Invoke-AtomicTest T1136.001
             -ShowDetailsBrief). No atomic test is ever executed by this script.

    Logs to C:\DacSetup\setup.log (transcript, appended across runs).
    Exit code 0 on success, 1 on any failure.

.NOTES
    Issue: #18 (lab VM setup script)

    Detection note: adding the Defender exclusion is itself a detectable
    defense-evasion action (Microsoft Defender event 5007, configuration
    changed; ATT&CK T1562.001 Impair Defenses: Disable or Modify Tools). In this
    lab it is expected, known-good baseline activity produced by every run of
    this script, so expect it in the workspace and don't treat it as a test hit.
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

# Atomic Red Team. Modules are pinned to exact versions; the atomics are pinned to
# a commit and verified by archive hash. GitHub generates commit archives on the
# fly, so the hash was verified stable across two downloads on 2026-11-07.
$ArtModuleName     = 'Invoke-AtomicRedTeam'
$ArtModuleVersion  = '2.3.0'
$YamlModuleName    = 'powershell-yaml'
$YamlModuleVersion = '0.4.12'
$NuGetMinVersion   = [version]'2.8.5.201'

$AtomicsCommit    = 'a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6'
$AtomicsZipUrl    = "https://github.com/redcanaryco/atomic-red-team/archive/$AtomicsCommit.zip"
$AtomicsZipSha256 = '2392FB6DD4E6ACEA3E9087FC6FFDE0F7C20A32E873AD191366AFC8599FCC9EA2'

$ArtRoot           = 'C:\AtomicRedTeam'
$AtomicsDir        = Join-Path $ArtRoot 'atomics'
$AtomicsMarkerPath = Join-Path $ArtRoot 'atomics.commit'
$ArtSmokeTestId    = 'T1136.001'

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
            # Sysmon writes UTF-16, so its "blank" lines arrive as \0 characters:
            # strip them before filtering (same for the two calls below).
            & $installedExe -accepteula -c $configPath |
                ForEach-Object { $_ -replace "`0", '' } |
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
                ForEach-Object { $_ -replace "`0", '' } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { Write-Log "  sysmon: $_" }
            if ($LASTEXITCODE -ne 0) { throw "$installedExe -u force failed with exit code $LASTEXITCODE." }
        }
    }

    if ($needsInstall) {
        Write-Log "Sysmon: installing version $downloadedVersion from $downloadedExe"
        & $downloadedExe -accepteula -i $configPath |
            ForEach-Object { $_ -replace "`0", '' } |
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

function Test-DacDefenderExclusion {
    # True if $Path is in Defender's ExclusionPath list. Trailing backslashes are
    # ignored so 'C:\X' and 'C:\X\' compare equal; -contains is case-insensitive.
    param([Parameter(Mandatory)][string]$Path)

    $wanted = $Path.TrimEnd('\')
    # ExclusionPath is $null when no exclusions exist; Where-Object drops it.
    $current = @((Get-MpPreference).ExclusionPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.TrimEnd('\') })
    return ($current -contains $wanted)
}

function Add-DacDefenderExclusion {
    # Adds a Defender folder exclusion and proves it took effect.
    # This is itself a detectable action (Defender event 5007, ATT&CK T1562.001);
    # in this lab it is known-good baseline activity (see .NOTES).
    param([Parameter(Mandatory)][string]$Path)

    if ($null -eq (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Log "Defender: Get-MpPreference not available, Defender not present; no exclusion needed for $Path"
        return
    }

    if (Test-DacDefenderExclusion -Path $Path) {
        Write-Log "Defender: $Path already excluded"
    }
    else {
        Add-MpPreference -ExclusionPath $Path
        Write-Log "Defender: exclusion added for $Path"
    }

    # Read back: Add-MpPreference can succeed silently while tamper protection or
    # a managed policy keeps the change from applying.
    if (-not (Test-DacDefenderExclusion -Path $Path)) {
        throw "Defender exclusion for $Path is missing after Add-MpPreference (blocked by tamper protection or policy?)."
    }
}

function Install-DacNuGetProvider {
    # PowerShellGet needs the NuGet provider to reach PSGallery; if it is missing,
    # Install-Module prompts to bootstrap it, which would hang an unattended run.
    # -ListAvailable only lists installed providers and never triggers that prompt.
    $nuget = @(Get-PackageProvider -ListAvailable | Where-Object {
        $_.Name -eq 'NuGet' -and [version]([string]$_.Version) -ge $NuGetMinVersion
    })
    if ($nuget.Count -gt 0) {
        Write-Log "NuGet: package provider $($nuget[0].Version) already installed"
        return
    }

    Write-Log "NuGet: installing package provider >= $NuGetMinVersion"
    Install-PackageProvider -Name NuGet -MinimumVersion $NuGetMinVersion -Force | Out-Null
    Write-Log 'NuGet: package provider installed'
}

function Install-DacPinnedModule {
    # Installs an exact module version for AllUsers. AllUsers matters: this
    # script runs as SYSTEM, but the module is used interactively by the lab admin.
    # -Force skips the "untrusted repository" prompt for this one call without
    # changing PSGallery's InstallationPolicy.
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Version
    )

    # Only count a copy under the AllUsers module root: a CurrentUser copy for
    # SYSTEM would be invisible to the lab admin.
    $allUsersRoot = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
    $findPinned = {
        @(Get-Module -ListAvailable -Name $Name | Where-Object {
            $_.Version -eq [version]$Version -and
            $_.ModuleBase.StartsWith($allUsersRoot, [StringComparison]::OrdinalIgnoreCase)
        })
    }

    # Wrap at the call site: invoking the scriptblock unrolls its @() result, so
    # zero matches arrive as $null and .Count would throw under StrictMode.
    if (@(& $findPinned).Count -gt 0) {
        Write-Log "Modules: $Name $Version already installed"
        return
    }

    Install-DacNuGetProvider
    Write-Log "Modules: installing $Name $Version (AllUsers)"
    Install-Module -Name $Name -RequiredVersion $Version -Scope AllUsers -Repository PSGallery -Force

    if (@(& $findPinned).Count -eq 0) {
        throw "Module $Name $Version not found under $allUsersRoot after Install-Module."
    }
    Write-Log "Modules: $Name $Version installed"
}

function Install-DacAtomicsFolder {
    Write-Log "Atomics: target commit $AtomicsCommit"
    $shortCommit = $AtomicsCommit.Substring(0, 7)

    $installedCommit = ''
    if (Test-Path -LiteralPath $AtomicsMarkerPath -PathType Leaf) {
        # [string] cast: Get-Content -Raw returns $null for an empty file.
        $installedCommit = ([string](Get-Content -LiteralPath $AtomicsMarkerPath -Raw)).Trim()
    }

    if ($installedCommit -ieq $AtomicsCommit -and (Test-Path -LiteralPath $AtomicsDir -PathType Container)) {
        Write-Log "Atomics: already at $shortCommit"
    }
    else {
        # Download inside the excluded folder so Defender doesn't scan the archive.
        $zipPath = Join-Path $ArtRoot "atomic-red-team-$AtomicsCommit.zip"
        Write-Log "Atomics: downloading $AtomicsZipUrl"
        Invoke-WebRequest -Uri $AtomicsZipUrl -OutFile $zipPath -UseBasicParsing

        $actualHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash
        if ($actualHash -ine $AtomicsZipSha256) {
            Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
            throw "Atomics archive hash mismatch. Expected $AtomicsZipSha256, got $actualHash."
        }
        Write-Log "Atomics: archive hash verified ($actualHash)"

        # Drop the marker before touching the folder: if the old marker survived an
        # interrupted extraction, a later run could see a matching commit and skip
        # over a half-extracted folder.
        if (Test-Path -LiteralPath $AtomicsMarkerPath) {
            Remove-Item -LiteralPath $AtomicsMarkerPath -Force
        }
        if (Test-Path -LiteralPath $AtomicsDir) {
            Write-Log "Atomics: removing existing $AtomicsDir"
            Remove-Item -LiteralPath $AtomicsDir -Recurse -Force
        }
        New-Item -Path $AtomicsDir -ItemType Directory -Force | Out-Null

        # ZipFile instead of Expand-Archive: we only want the atomics/ subtree,
        # flattened into $AtomicsDir, and it is much faster on PS 5.1.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $prefix   = "atomic-red-team-$AtomicsCommit/atomics/"
        $rootFull = [IO.Path]::GetFullPath($AtomicsDir).TrimEnd('\') + '\'
        $fileCount = 0
        $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            foreach ($entry in $archive.Entries) {
                $entryName = $entry.FullName.Replace('\', '/')
                if (-not $entryName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { continue }

                $relative = $entryName.Substring($prefix.Length)
                # Directory entries end in '/' (and have an empty Name); directories
                # are created on demand from file paths instead.
                if ($relative.Length -eq 0 -or $relative.EndsWith('/')) { continue }

                $dest = [IO.Path]::GetFullPath([IO.Path]::Combine($AtomicsDir, $relative.Replace('/', '\')))
                # Zip-slip guard: never write outside $AtomicsDir, even from a pinned archive.
                if (-not $dest.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Atomics archive entry escapes the target folder: $($entry.FullName)"
                }

                [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dest)) | Out-Null
                [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
                $fileCount++
            }
        }
        finally {
            $archive.Dispose()
        }
        Write-Log "Atomics: extracted $fileCount files to $AtomicsDir"

        Remove-Item -LiteralPath $zipPath -Force

        # Marker last, so any failure above makes the next run retry from scratch.
        Set-Content -LiteralPath $AtomicsMarkerPath -Value $AtomicsCommit -Encoding Ascii -NoNewline
        Write-Log "Atomics: now at $shortCommit (marker $AtomicsMarkerPath)"
    }

    # Sanity check on both paths: cheap, and catches a folder damaged since the last run.
    $smokeYaml = Join-Path $AtomicsDir "$ArtSmokeTestId\$ArtSmokeTestId.yaml"
    if (-not (Test-Path -LiteralPath $smokeYaml -PathType Leaf)) {
        throw "Atomics sanity check failed: $smokeYaml is missing."
    }
    $techniqueCount = @(Get-ChildItem -LiteralPath $AtomicsDir -Directory |
        Where-Object { $_.Name -match '^T\d{4}' }).Count
    Write-Log "Atomics: $techniqueCount technique folders present"
}

function Install-DacAtomicRedTeam {
    Write-Log 'Atomic Red Team: starting'

    # The exclusion must exist before anything is downloaded, or Defender will
    # quarantine atomics payloads mid-extraction and leave a partial folder.
    if (-not (Test-Path -LiteralPath $ArtRoot)) {
        New-Item -Path $ArtRoot -ItemType Directory -Force | Out-Null
        Write-Log "Atomic Red Team: created $ArtRoot"
    }
    Add-DacDefenderExclusion -Path $ArtRoot

    # powershell-yaml first: Invoke-AtomicRedTeam needs it to parse the atomics.
    Install-DacPinnedModule -Name $YamlModuleName -Version $YamlModuleVersion
    Install-DacPinnedModule -Name $ArtModuleName -Version $ArtModuleVersion

    $loaded = @(Import-Module -Name $ArtModuleName -RequiredVersion $ArtModuleVersion -PassThru) |
        Where-Object { $_.Name -eq $ArtModuleName } |
        Select-Object -First 1
    if ($null -eq $loaded) {
        throw "Import-Module $ArtModuleName $ArtModuleVersion returned no module."
    }
    Write-Log "Atomic Red Team: loaded $($loaded.Name) $($loaded.Version) from $($loaded.ModuleBase)"

    Install-DacAtomicsFolder

    # Read-only smoke test: -ShowDetailsBrief only lists the tests, it never runs
    # one. Out-Host sends the output to the console, and so to the transcript.
    Write-Log "Atomic Red Team: smoke test (read-only) Invoke-AtomicTest $ArtSmokeTestId -ShowDetailsBrief"
    Invoke-AtomicTest $ArtSmokeTestId -ShowDetailsBrief -PathToAtomicsFolder $AtomicsDir | Out-Host

    Write-Log 'Atomic Red Team: done'
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
