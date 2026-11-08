#Requires -Version 7.2
<#
.SYNOPSIS
    Shared constants and helpers for lab-up.ps1 and lab-down.ps1.

.DESCRIPTION
    Dot-source this file; do not run it directly. Loading it only defines constants
    and functions: it makes no az calls, network calls, or file writes, so the Pester
    tests can dot-source it safely.

    Every az call goes through Invoke-DacAz. Output that needs filtering is read with
    -o json | ConvertFrom-Json and filtered in PowerShell, because az.cmd mangles
    complex JMESPath quoting when called from PowerShell. Only single-property
    --query paths are used.

    Nothing here prints subscription IDs, tenant IDs, full resource IDs, the lab
    public IP, or the admin password.

    StrictMode and ErrorActionPreference are set by the entry scripts, not here, so
    dot-sourcing this file does not change the caller's session settings.
#>

# ---------- Constants ----------
$DacStackName        = 'stack-dac-lab'
$DacLabResourceGroup = 'rg-dac-lab'
$DacCoreResourceGroup = 'rg-dac-core'
$DacVmName           = 'vm-dac-lab'
$DacRunCommandName   = 'rc-dac-setup'
$DacPublicIpName     = 'pip-dac-lab'
$DacCoreWorkspaceName = 'law-dac-core'
$DacCoreDcrName      = 'dcr-dac-windows'
$DacAdminUsername    = 'dacadmin'
$DacPasswordMinLength = 12   # Matches @minLength(12) on adminPassword in infra/lab/main.bicep.

# Resolved now (pure path math), checked only when Get-DacParamFile is called.
$DacParamFilePath = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..' 'infra' 'lab' 'main.bicepparam'))

function Get-DacParamFile {
    <#
    .SYNOPSIS
        Returns the full path to infra/lab/main.bicepparam, or throws if it is missing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not (Test-Path -LiteralPath $DacParamFilePath -PathType Leaf)) {
        throw "Lab parameter file not found at '$DacParamFilePath'. Run this script from a full clone of the repo (scripts/ and infra/lab/ side by side)."
    }
    return $DacParamFilePath
}

function Invoke-DacAz {
    <#
    .SYNOPSIS
        Runs one az command from an argument array and returns its stdout.

    .DESCRIPTION
        Always appends --only-show-errors. Throws if az exits non-zero; the error
        names the az command (e.g. 'az stack group create') but never its arguments,
        so parameter values never land in an error message. stderr is not captured
        and goes straight to the console.

    .EXAMPLE
        Invoke-DacAz -Arguments @('group', 'exists', '--name', 'rg-dac-lab')
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string[]] $Arguments
    )

    # The command name is the leading words before the first option, e.g. 'stack group create'.
    $commandWords = @(foreach ($a in $Arguments) { if ($a.StartsWith('-')) { break }; $a })
    $commandName = 'az ' + ($commandWords -join ' ')

    # Make sure PowerShell itself never throws on a non-zero exit (PS 7.3+ setting),
    # so the error below is the one the caller sees.
    $PSNativeCommandUseErrorActionPreference = $false

    $azArgs = @($Arguments) + '--only-show-errors'
    $output = & az @azArgs
    if ($LASTEXITCODE -ne 0) {
        throw "$commandName failed with exit code $LASTEXITCODE. See the az error above."
    }
    return (@($output) -join [Environment]::NewLine)
}

function Test-DacIPv4 {
    <#
    .SYNOPSIS
        True if the value is exactly a dotted-quad IPv4 address (four octets, 0-255).

    .DESCRIPTION
        Pure function. No CIDR suffix, whitespace, leading zeros, or extra text allowed.

    .EXAMPLE
        Test-DacIPv4 -Value '203.0.113.10'   # True
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Value
    )

    if ([string]::IsNullOrEmpty($Value)) { return $false }
    # [0-9] rather than \d (which matches non-ASCII digits); \A and \z rather than ^ and $
    # (which would accept a trailing newline).
    $octet = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
    return [bool]($Value -cmatch "\A$octet\.$octet\.$octet\.$octet\z")
}

function Get-DacPublicIp {
    <#
    .SYNOPSIS
        Returns this machine's public IPv4 address from api.ipify.org.

    .DESCRIPTION
        The value is validated with Test-DacIPv4 and returned, never printed.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try {
        $response = Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 15
    }
    catch {
        throw "Could not look up your public IP from api.ipify.org ($($_.Exception.Message)). Pass it with -AllowedIp instead."
    }

    $ip = ([string]$response).Trim()
    if (-not (Test-DacIPv4 -Value $ip)) {
        throw 'api.ipify.org did not return a valid IPv4 address. Pass your IP with -AllowedIp instead.'
    }
    return $ip
}

function ConvertTo-DacResourceLabel {
    <#
    .SYNOPSIS
        Shortens a full resource ID to the part after its last '/providers/'.

    .DESCRIPTION
        Pure function. The result never contains the subscription ID or resource group.
        Throws (without echoing the ID) if the ID has no '/providers/' segment.

    .EXAMPLE
        ConvertTo-DacResourceLabel -ResourceId '/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/rg-dac-lab/providers/Microsoft.Compute/virtualMachines/vm-dac-lab'
        # Microsoft.Compute/virtualMachines/vm-dac-lab
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string] $ResourceId
    )

    process {
        $marker = '/providers/'
        $index = $ResourceId.LastIndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase)
        if ($index -lt 0) {
            throw "Not a provider resource ID (no '/providers/' segment); refusing to print it."
        }
        $ResourceId.Substring($index + $marker.Length)
    }
}

function Test-DacIdInResourceGroup {
    <#
    .SYNOPSIS
        True if a resource ID contains '/resourceGroups/<ResourceGroupName>/' (case-insensitive).

    .EXAMPLE
        Test-DacIdInResourceGroup -ResourceId $id -ResourceGroupName 'rg-dac-lab'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $ResourceId,

        [Parameter(Mandatory)]
        [string] $ResourceGroupName
    )

    $needle = "/resourceGroups/$ResourceGroupName/"
    return $ResourceId.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Get-DacJsonProperty {
    <#
    .SYNOPSIS
        Reads a property from a ConvertFrom-Json object, or $null if it is absent.
        StrictMode throws on missing properties; this keeps optional fields safe.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [string] $Name
    )

    if ($null -eq $InputObject) { return $null }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Set-DacDeployEnv {
    <#
    .SYNOPSIS
        Sets DAC_ALLOWED_IP and DAC_ADMIN_PASSWORD for the az call and returns their
        previous values, for Restore-DacDeployEnv.

    .DESCRIPTION
        main.bicepparam reads both values with readEnvironmentVariable. The previous
        values are captured before anything is set. A variable that was unset is saved
        as $null. Uses [Environment] directly (process scope), so $WhatIfPreference
        has no effect.

    .EXAMPLE
        $saved = Set-DacDeployEnv -AllowedIp $ip -AdminPassword $password
        try { <az call> } finally { Restore-DacDeployEnv -SavedState $saved }
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $AllowedIp,
        [Parameter(Mandatory)] [string] $AdminPassword
    )

    $saved = [ordered]@{}
    foreach ($name in 'DAC_ALLOWED_IP', 'DAC_ADMIN_PASSWORD') {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name)
    }
    [Environment]::SetEnvironmentVariable('DAC_ALLOWED_IP', $AllowedIp)
    [Environment]::SetEnvironmentVariable('DAC_ADMIN_PASSWORD', $AdminPassword)
    return $saved
}

function Restore-DacDeployEnv {
    <#
    .SYNOPSIS
        Restores the variables saved by Set-DacDeployEnv, removing any that were unset.

    .DESCRIPTION
        PowerShell turns $null into '' when it passes $null to a [string] parameter of a
        .NET method, and SetEnvironmentVariable(name, '') leaves the variable set to an
        empty string instead of removing it. So a previously unset variable is
        restored with [NullString]::Value, which reaches .NET as a real null and
        removes the variable. Not affected by $WhatIfPreference.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $SavedState
    )

    foreach ($name in @($SavedState.Keys)) {
        $previous = $SavedState[$name]
        if ($null -eq $previous) {
            [Environment]::SetEnvironmentVariable($name, [NullString]::Value)
        }
        else {
            [Environment]::SetEnvironmentVariable($name, [string]$previous)
        }
    }
}

function Assert-DacContext {
    <#
    .SYNOPSIS
        Throws unless az is signed in to this project's subscription.

    .DESCRIPTION
        Checks: the az account is signed in and 'Enabled'; rg-dac-core exists and is
        tagged project=dac; rg-dac-lab exists. That proves the right subscription
        without hardcoding a subscription name or ID. Nothing identifying is printed.
    #>
    [CmdletBinding()]
    param()

    try {
        $state = Invoke-DacAz -Arguments @('account', 'show', '--query', 'state', '-o', 'tsv')
    }
    catch {
        throw 'Azure CLI is not signed in (az account show failed). Run az login, then try again.'
    }
    if ($state.Trim() -ne 'Enabled') {
        throw "The current az subscription is not Enabled (state: '$($state.Trim())'). Pick the project subscription with az account set, or run az login."
    }

    $coreExists = Invoke-DacAz -Arguments @('group', 'exists', '--name', $DacCoreResourceGroup)
    if ($coreExists.Trim() -ne 'true') {
        throw "Resource group $DacCoreResourceGroup not found in the current subscription. Switch to the project subscription (az account set) or deploy the core layer first."
    }

    $coreGroup = Invoke-DacAz -Arguments @('group', 'show', '--name', $DacCoreResourceGroup, '-o', 'json') | ConvertFrom-Json
    $projectTag = Get-DacJsonProperty -InputObject (Get-DacJsonProperty -InputObject $coreGroup -Name 'tags') -Name 'project'
    if ($projectTag -ne 'dac') {
        throw "Resource group $DacCoreResourceGroup exists but is not tagged project=dac, so this may be the wrong subscription. Check az account show, or add the tag if this is the project subscription."
    }

    $labExists = Invoke-DacAz -Arguments @('group', 'exists', '--name', $DacLabResourceGroup)
    if ($labExists.Trim() -ne 'true') {
        throw "Resource group $DacLabResourceGroup not found. Create it once (in the same region as $DacCoreResourceGroup) before running the lab scripts."
    }
}

function Format-DacElapsed {
    <#
    .SYNOPSIS
        Formats a TimeSpan as mm:ss (minutes keep counting past 59).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [TimeSpan] $Elapsed)

    '{0:00}:{1:00}' -f [math]::Floor($Elapsed.TotalMinutes), $Elapsed.Seconds
}
