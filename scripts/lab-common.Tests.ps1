#Requires -Version 7.2
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Pester 5 tests for the pure functions in lab-common.ps1. No az or network calls:
    dot-sourcing lab-common.ps1 only defines constants and functions.
    Test data uses made-up all-zero subscription GUIDs.

    Run: Invoke-Pester ./scripts/lab-common.Tests.ps1 -Output Detailed
#>

BeforeAll {
    Set-StrictMode -Version Latest
    . (Join-Path $PSScriptRoot 'lab-common.ps1')

    $script:Sub = '00000000-0000-0000-0000-000000000000'
    $script:LabVmId = "/subscriptions/$Sub/resourceGroups/rg-dac-lab/providers/Microsoft.Compute/virtualMachines/vm-dac-lab"
    $script:CoreDcrId = "/subscriptions/$Sub/resourceGroups/rg-dac-core/providers/Microsoft.Insights/dataCollectionRules/dcr-dac-windows"
}

Describe 'Test-DacIPv4' {
    It 'accepts a valid address: <_>' -ForEach @('203.0.113.10', '0.0.0.0', '255.255.255.255') {
        Test-DacIPv4 -Value $_ | Should -BeTrue
    }

    It 'rejects an out-of-range octet: <_>' -ForEach @('256.1.1.1', '1.2.3.300', '1.2.3.-1') {
        Test-DacIPv4 -Value $_ | Should -BeFalse
    }

    It 'rejects extra text: <_>' -ForEach @('203.0.113.10/32', ' 203.0.113.10', '203.0.113.10 ', "203.0.113.10`n", 'ip=203.0.113.10', '1.2.3', '1.2.3.4.5') {
        Test-DacIPv4 -Value $_ | Should -BeFalse
    }

    It 'rejects an empty string' {
        Test-DacIPv4 -Value '' | Should -BeFalse
    }

    It 'rejects $null' {
        Test-DacIPv4 -Value $null | Should -BeFalse
    }
}

Describe 'ConvertTo-DacResourceLabel' {
    It 'shortens a VM ID' {
        ConvertTo-DacResourceLabel -ResourceId $LabVmId |
            Should -Be 'Microsoft.Compute/virtualMachines/vm-dac-lab'
    }

    It 'shortens a VM extension ID' {
        ConvertTo-DacResourceLabel -ResourceId "$LabVmId/extensions/AzureMonitorWindowsAgent" |
            Should -Be 'Microsoft.Compute/virtualMachines/vm-dac-lab/extensions/AzureMonitorWindowsAgent'
    }

    It 'uses the last /providers/ segment of a DCR association ID' {
        $id = "$LabVmId/providers/Microsoft.Insights/dataCollectionRuleAssociations/dcra-dac-lab"
        ConvertTo-DacResourceLabel -ResourceId $id |
            Should -Be 'Microsoft.Insights/dataCollectionRuleAssociations/dcra-dac-lab'
    }

    It 'never includes the subscription ID' {
        ConvertTo-DacResourceLabel -ResourceId $LabVmId | Should -Not -Match $Sub
    }

    It 'throws on an ID with no /providers/ segment, without echoing it' {
        $rgId = "/subscriptions/$Sub/resourceGroups/rg-dac-lab"
        { ConvertTo-DacResourceLabel -ResourceId $rgId } | Should -Throw -ExpectedMessage '*refusing to print it*'
        try { ConvertTo-DacResourceLabel -ResourceId $rgId } catch { $_.Exception.Message | Should -Not -Match $Sub }
    }
}

Describe 'Set-DacDeployEnv / Restore-DacDeployEnv' {
    BeforeAll {
        $script:EnvNames = @('DAC_ALLOWED_IP', 'DAC_ADMIN_PASSWORD')
        $script:TestIp = '192.0.2.123'                 # TEST-NET-1, documentation-only range
        $script:TestPassword = 'test-only-not-a-real-password'

        # Removes a variable for real ([NullString] so PowerShell does not pass '').
        function script:Clear-TestEnv { foreach ($n in $EnvNames) { [Environment]::SetEnvironmentVariable($n, [NullString]::Value) } }
    }

    BeforeEach {
        # Keep whatever the developer's session had, so the tests never clobber it.
        $script:SessionEnv = @{}
        foreach ($n in $EnvNames) { $script:SessionEnv[$n] = [Environment]::GetEnvironmentVariable($n) }
        Clear-TestEnv
    }

    AfterEach {
        Clear-TestEnv
        foreach ($n in $EnvNames) {
            if ($null -ne $SessionEnv[$n]) { [Environment]::SetEnvironmentVariable($n, $SessionEnv[$n]) }
        }
    }

    Context 'with $WhatIfPreference = <WhatIf>' -ForEach @(@{ WhatIf = $false }, @{ WhatIf = $true }) {
        It 'sets both variables while deploying' {
            $WhatIfPreference = $WhatIf
            $saved = Set-DacDeployEnv -AllowedIp $TestIp -AdminPassword $TestPassword
            try {
                $env:DAC_ALLOWED_IP | Should -Be $TestIp
                $env:DAC_ADMIN_PASSWORD | Should -Be $TestPassword
            }
            finally { Restore-DacDeployEnv -SavedState $saved }
        }

        It 'unset before -> unset after (removed, not left empty)' {
            $WhatIfPreference = $WhatIf
            $saved = Set-DacDeployEnv -AllowedIp $TestIp -AdminPassword $TestPassword
            Restore-DacDeployEnv -SavedState $saved

            foreach ($n in $EnvNames) {
                Test-Path "Env:$n" | Should -BeFalse -Because "$n was unset before"
                [Environment]::GetEnvironmentVariable($n) | Should -BeNullOrEmpty
            }
        }

        It 'set before -> original value restored' {
            $WhatIfPreference = $WhatIf
            [Environment]::SetEnvironmentVariable('DAC_ALLOWED_IP', '198.51.100.7')
            [Environment]::SetEnvironmentVariable('DAC_ADMIN_PASSWORD', 'test-only-original-value')

            $saved = Set-DacDeployEnv -AllowedIp $TestIp -AdminPassword $TestPassword
            Restore-DacDeployEnv -SavedState $saved

            $env:DAC_ALLOWED_IP | Should -Be '198.51.100.7'
            $env:DAC_ADMIN_PASSWORD | Should -Be 'test-only-original-value'
        }

        It 'restores in finally when the code inside try throws' {
            $WhatIfPreference = $WhatIf
            {
                $saved = Set-DacDeployEnv -AllowedIp $TestIp -AdminPassword $TestPassword
                try { throw 'simulated az failure' }
                finally { Restore-DacDeployEnv -SavedState $saved }
            } | Should -Throw -ExpectedMessage 'simulated az failure'

            foreach ($n in $EnvNames) { Test-Path "Env:$n" | Should -BeFalse }
        }
    }
}

Describe 'Comment-based help on <Script>' -ForEach @(@{ Script = 'lab-up.ps1' }, @{ Script = 'lab-down.ps1' }) {
    BeforeAll {
        # Get-Help reads the file; it does not run the script.
        $script:Help = Get-Help (Join-Path $PSScriptRoot $Script) -Full
    }

    It 'has a non-empty Synopsis (not just the syntax line)' {
        $Help.Synopsis | Should -Not -BeNullOrEmpty
        $Help.Synopsis | Should -Not -Match ([regex]::Escape($Script))
    }

    It 'has at least one example' {
        @($Help.examples.example).Count | Should -BeGreaterOrEqual 1
    }
}

Describe 'Test-DacIdInResourceGroup' {
    It 'is true for a lab resource ID' {
        Test-DacIdInResourceGroup -ResourceId $LabVmId -ResourceGroupName 'rg-dac-lab' | Should -BeTrue
    }

    It 'is false for a core resource ID' {
        Test-DacIdInResourceGroup -ResourceId $CoreDcrId -ResourceGroupName 'rg-dac-lab' | Should -BeFalse
    }

    It 'is case-insensitive' {
        $upper = $LabVmId.Replace('/resourceGroups/rg-dac-lab/', '/RESOURCEGROUPS/RG-DAC-LAB/')
        Test-DacIdInResourceGroup -ResourceId $upper -ResourceGroupName 'rg-dac-lab' | Should -BeTrue
    }

    It 'does not match a resource group whose name only starts with the lab name' {
        $lookalike = $LabVmId.Replace('/rg-dac-lab/', '/rg-dac-lab-old/')
        Test-DacIdInResourceGroup -ResourceId $lookalike -ResourceGroupName 'rg-dac-lab' | Should -BeFalse
    }
}
