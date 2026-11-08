#Requires -Version 7.2

<#
.SYNOPSIS
    Deploys (or updates) the lab layer as the deployment stack stack-dac-lab.

.DESCRIPTION
    Checks that az is signed in to this project's subscription, works out the RDP
    allowed IP and the VM admin password, then runs az stack group create against
    infra/lab/main.bicepparam in rg-dac-lab. The stack uses --action-on-unmanage
    deleteAll, so lab-down.ps1 can remove everything it created in one step.

    main.bicepparam reads DAC_ALLOWED_IP and DAC_ADMIN_PASSWORD from the environment.
    This script sets both only for the az call and restores their previous values
    afterwards (removing them if they were not set), even if the deployment fails.
    Neither value is written to a file or printed, except the IP in the final summary
    so you can RDP in.

    After the stack succeeds, the VM is started if it is not running (unless -NoStart),
    and a summary shows elapsed time, VM power state, the setup Run Command result,
    and the RDP target.

    With -WhatIf, runs az deployment group what-if instead and changes nothing.

.PARAMETER AllowedIp
    Public IPv4 address allowed to RDP to the VM. Defaults to this machine's public
    IP from api.ipify.org.

.PARAMETER NoStart
    Do not start the VM if it is not running after the deployment.

.EXAMPLE
    ./scripts/lab-up.ps1
    Deploys the lab, allowing RDP from this machine's public IP. Prompts for the admin
    password unless DAC_ADMIN_PASSWORD is already set.

.EXAMPLE
    ./scripts/lab-up.ps1 -WhatIf
    Shows what the deployment would change, without changing anything.

.EXAMPLE
    ./scripts/lab-up.ps1 -AllowedIp 203.0.113.10 -NoStart
    Deploys with an explicit allowed IP and leaves the VM stopped if it is not running.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $AllowedIp,

    [switch] $NoStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'lab-common.ps1')

$paramFile = Get-DacParamFile
Assert-DacContext
Write-Host "Azure context OK: $DacCoreResourceGroup (project=dac) and $DacLabResourceGroup found."

# ---------- Allowed IP ----------
if ($PSBoundParameters.ContainsKey('AllowedIp')) {
    if (-not (Test-DacIPv4 -Value $AllowedIp)) {
        throw '-AllowedIp must be a plain IPv4 address such as 203.0.113.10 (no CIDR suffix, no spaces).'
    }
    $ip = $AllowedIp
    Write-Host 'Allowed IP: from -AllowedIp.'
}
else {
    $ip = Get-DacPublicIp
    Write-Host 'Allowed IP: this machine''s public IP (api.ipify.org).'
}

# ---------- Admin password ----------
$envPassword = [Environment]::GetEnvironmentVariable('DAC_ADMIN_PASSWORD')
if (-not [string]::IsNullOrEmpty($envPassword)) {
    $password = $envPassword
    Write-Host 'Admin password: from DAC_ADMIN_PASSWORD.'
}
else {
    $password = Read-Host -Prompt "Admin password for $DacAdminUsername (min $DacPasswordMinLength chars)" -MaskInput
}
if ($password.Length -lt $DacPasswordMinLength) {
    throw "Admin password must be at least $DacPasswordMinLength characters (the Bicep minLength)."
}

# ---------- Deploy (or what-if) with the env vars set only for the az call ----------
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$savedEnv = Set-DacDeployEnv -AllowedIp $ip -AdminPassword $password
try {
    if ($WhatIfPreference) {
        Write-Host 'Running az deployment group what-if (no changes will be made)...'
        $whatIf = Invoke-DacAz -Arguments @(
            'deployment', 'group', 'what-if',
            '--resource-group', $DacLabResourceGroup,
            '--parameters', $paramFile
        )
        Write-Host $whatIf
        Write-Host ''
        Write-Warning "The what-if 'Scope:' line above contains the subscription ID. Redact it before sharing this output."
        return
    }

    Write-Host "Deploying stack $DacStackName to $DacLabResourceGroup (the setup Run Command can take up to 30 minutes)..."
    $state = Invoke-DacAz -Arguments @(
        'stack', 'group', 'create',
        '--name', $DacStackName,
        '--resource-group', $DacLabResourceGroup,
        '--parameters', $paramFile,
        '--action-on-unmanage', 'deleteAll',
        '--deny-settings-mode', 'none',
        '--description', 'DaC lab layer (scripts/lab-up.ps1)',
        '--yes',
        '--query', 'provisioningState',
        '-o', 'tsv'
    )
    if ($state.Trim() -ine 'succeeded') {
        throw "Stack $DacStackName finished with provisioningState '$($state.Trim())', expected 'succeeded'."
    }
    Write-Host "Stack $DacStackName succeeded."
}
finally {
    # Runs on success, failure, and the what-if return above.
    Restore-DacDeployEnv -SavedState $savedEnv
    $savedEnv = $null
    $password = $null
    $envPassword = $null
}

# ---------- Make sure the VM is running ----------
$vmShowArgs = @(
    'vm', 'show', '-d',
    '--resource-group', $DacLabResourceGroup,
    '--name', $DacVmName,
    '--query', 'powerState',
    '-o', 'tsv'
)
$powerState = (Invoke-DacAz -Arguments $vmShowArgs).Trim()
if ($powerState -ine 'VM running') {
    if ($NoStart) {
        Write-Host "VM is '$powerState'; not starting it (-NoStart)."
    }
    else {
        Write-Host "VM is '$powerState'; starting it..."
        Invoke-DacAz -Arguments @('vm', 'start', '--resource-group', $DacLabResourceGroup, '--name', $DacVmName) | Out-Null
        $powerState = (Invoke-DacAz -Arguments $vmShowArgs).Trim()
        if ($powerState -ine 'VM running') {
            Write-Warning "VM still reports '$powerState' after az vm start."
        }
    }
}

# ---------- Setup Run Command result ----------
$rcState = 'unavailable'
$rcExitCode = 'unavailable'
try {
    $rc = Invoke-DacAz -Arguments @(
        'vm', 'run-command', 'show',
        '--resource-group', $DacLabResourceGroup,
        '--vm-name', $DacVmName,
        '--name', $DacRunCommandName,
        '--instance-view',
        '-o', 'json'
    ) | ConvertFrom-Json
    $instanceView = Get-DacJsonProperty -InputObject $rc -Name 'instanceView'
    $value = Get-DacJsonProperty -InputObject $instanceView -Name 'executionState'
    if ($null -ne $value) { $rcState = [string]$value }
    $value = Get-DacJsonProperty -InputObject $instanceView -Name 'exitCode'
    if ($null -ne $value) { $rcExitCode = [string]$value }
}
catch {
    Write-Warning "Could not read Run Command $DacRunCommandName status: $($_.Exception.Message)"
}

# ---------- RDP target ----------
$publicIp = (Invoke-DacAz -Arguments @(
        'network', 'public-ip', 'show',
        '--resource-group', $DacLabResourceGroup,
        '--name', $DacPublicIpName,
        '--query', 'ipAddress',
        '-o', 'tsv'
    )).Trim()

$stopwatch.Stop()

Write-Host ''
Write-Host '========== Lab up =========='
Write-Host "Total time      : $(Format-DacElapsed -Elapsed $stopwatch.Elapsed)"
Write-Host "VM power state  : $powerState"
Write-Host "Setup run cmd   : $DacRunCommandName executionState=$rcState exitCode=$rcExitCode"
Write-Host "RDP             : .\$DacAdminUsername @ $publicIp"
Write-Host '                  (local console only - don''t paste or commit this)'
