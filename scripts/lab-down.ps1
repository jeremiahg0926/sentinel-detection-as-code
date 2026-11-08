#Requires -Version 7.2

<#
.SYNOPSIS
    Deletes the lab deployment stack stack-dac-lab and every resource it manages.

.DESCRIPTION
    Checks that az is signed in to this project's subscription, then reads the
    resources managed by stack-dac-lab. As a core-safety guard, if any managed
    resource is outside rg-dac-lab the script stops and deletes nothing.

    The managed resources are listed by type and name only (no subscription IDs),
    then you are asked to confirm. The stack is deleted with --action-on-unmanage
    deleteAll, and the script verifies that rg-dac-lab is empty and that the core
    resources (law-dac-core, dcr-dac-windows) are still in rg-dac-core.

    rg-dac-lab itself is kept; an empty resource group costs nothing.

.PARAMETER Force
    Skip the confirmation prompt. An explicit -Confirm still prompts.

.EXAMPLE
    ./scripts/lab-down.ps1
    Lists the lab resources and asks for confirmation before deleting them.

.EXAMPLE
    ./scripts/lab-down.ps1 -WhatIf
    Lists the lab resources that would be deleted, and stops.

.EXAMPLE
    ./scripts/lab-down.ps1 -Force
    Deletes the lab without prompting.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'lab-common.ps1')

if ($Force -and -not $PSBoundParameters.ContainsKey('Confirm')) {
    $ConfirmPreference = 'None'
}

Assert-DacContext
Write-Host "Azure context OK: $DacCoreResourceGroup (project=dac) and $DacLabResourceGroup found."

# ---------- Does the stack exist? ----------
$stacks = @(Invoke-DacAz -Arguments @(
        'stack', 'group', 'list',
        '--resource-group', $DacLabResourceGroup,
        '-o', 'json'
    ) | ConvertFrom-Json)
if (-not ($stacks | Where-Object { (Get-DacJsonProperty -InputObject $_ -Name 'name') -eq $DacStackName })) {
    Write-Host "Stack $DacStackName not found in $DacLabResourceGroup - nothing to delete."
    exit 0
}

# ---------- Managed resources and core-safety guard ----------
$stack = Invoke-DacAz -Arguments @(
    'stack', 'group', 'show',
    '--name', $DacStackName,
    '--resource-group', $DacLabResourceGroup,
    '-o', 'json'
) | ConvertFrom-Json

$resourceIds = @(
    foreach ($r in @(Get-DacJsonProperty -InputObject $stack -Name 'resources')) {
        $id = Get-DacJsonProperty -InputObject $r -Name 'id'
        if ($id) { [string]$id }
    }
)

$outside = @($resourceIds | Where-Object { -not (Test-DacIdInResourceGroup -ResourceId $_ -ResourceGroupName $DacLabResourceGroup) })
if ($outside.Count -gt 0) {
    throw "Core-safety guard: $($outside.Count) resource(s) managed by $DacStackName are outside $DacLabResourceGroup. Deleting nothing. Inspect the stack in the portal before continuing."
}

Write-Host ''
Write-Host "$DacStackName manages $($resourceIds.Count) resource(s) in ${DacLabResourceGroup}:"
foreach ($id in $resourceIds) {
    Write-Host "  - $(ConvertTo-DacResourceLabel -ResourceId $id)"
}
Write-Host ''

$target = "$DacStackName in $DacLabResourceGroup ($($resourceIds.Count) managed resources)"
if (-not $PSCmdlet.ShouldProcess($target, 'Delete deployment stack and all managed resources')) {
    if (-not $WhatIfPreference) { Write-Host 'Cancelled. Nothing was deleted.' }
    return
}

# ---------- Delete ----------
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
Write-Host "Deleting $DacStackName and its resources..."
Invoke-DacAz -Arguments @(
    'stack', 'group', 'delete',
    '--name', $DacStackName,
    '--resource-group', $DacLabResourceGroup,
    '--action-on-unmanage', 'deleteAll',
    '--yes'
) | Out-Null
Write-Host "Stack $DacStackName deleted."

# ---------- Verify ----------
$labLeft = @(Invoke-DacAz -Arguments @('resource', 'list', '--resource-group', $DacLabResourceGroup, '-o', 'json') |
    ConvertFrom-Json | ForEach-Object { Get-DacJsonProperty -InputObject $_ -Name 'name' })
$coreNames = @(Invoke-DacAz -Arguments @('resource', 'list', '--resource-group', $DacCoreResourceGroup, '-o', 'json') |
    ConvertFrom-Json | ForEach-Object { Get-DacJsonProperty -InputObject $_ -Name 'name' })

$stopwatch.Stop()

Write-Host ''
Write-Host '========== Lab down =========='
if ($labLeft.Count -eq 0) {
    Write-Host "Lab RG          : $DacLabResourceGroup is empty"
}
else {
    Write-Warning "$DacLabResourceGroup still has $($labLeft.Count) resource(s): $($labLeft -join ', ')"
}
Write-Host "Core RG         : $DacCoreResourceGroup has $(if ($coreNames.Count) { $coreNames -join ', ' } else { '(nothing)' })"

$missingCore = @($DacCoreWorkspaceName, $DacCoreDcrName | Where-Object { $coreNames -notcontains $_ })
if ($missingCore.Count -gt 0) {
    throw "Core resource(s) missing from ${DacCoreResourceGroup}: $($missingCore -join ', '). Investigate before the next lab-up."
}
Write-Host "Core check      : $DacCoreWorkspaceName and $DacCoreDcrName present"
Write-Host "Total time      : $(Format-DacElapsed -Elapsed $stopwatch.Elapsed)"
Write-Host "Note            : $DacLabResourceGroup itself is kept (empty, free)."
