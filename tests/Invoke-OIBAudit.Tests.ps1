#Requires -Version 7.0
# Pester tests for Scripts/Invoke-OIBAudit.ps1. They need no tenant and no network.
#   Invoke-Pester tests/Invoke-OIBAudit.Tests.ps1

BeforeAll {
    $script:ToolPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Scripts/Invoke-OIBAudit.ps1'
    . $script:ToolPath          # dot-sourcing loads the functions and skips the main part
    Import-SettingNames

    $script:Windows  = @(Get-BaselinePolicies $RepoRoot @('Windows'))
    $script:Manifest = Get-BaselineManifest $RepoRoot @('Windows')
    $script:Example  = Join-Path $RepoRoot 'Scripts/BestPractices.example.md'

    function Copy-TestPolicy ($Policy, [string]$Name = $Policy.Name, [string]$OibId = $Policy.OibId) {
        $settings = @{}
        foreach ($id in $Policy.Settings.Keys) { $settings[$id] = @($Policy.Settings[$id]) }
        [pscustomobject]@{ Name = $Name; OibId = $OibId; Kind = $Policy.Kind; Platform = ''; Source = 'test'; Settings = $settings }
    }

    function Get-TestPolicy ([string]$Words) {
        Find-BaselinePolicies $Words $script:Windows | Select-Object -First 1
    }

    function Invoke-Tool ([string[]]$Arguments) {
        # Runs the tool as a separate process with no sign-in details, and returns output and exit code.
        $saved = @{}
        foreach ($name in 'OIB_TENANT_ID', 'OIB_CLIENT_ID', 'OIB_CLIENT_SECRET', 'OIB_ACCESS_TOKEN') {
            $saved[$name] = [Environment]::GetEnvironmentVariable($name)
            [Environment]::SetEnvironmentVariable($name, $null)
        }
        try {
            $output = & pwsh -NoProfile -File $script:ToolPath @Arguments 2>&1 | Out-String
            return [pscustomobject]@{ Output = $output; ExitCode = $LASTEXITCODE }
        }
        finally {
            foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
        }
    }
}

Describe 'Reading the baseline' {
    It 'finds every active Windows policy in the manifest' {
        $manifest = Read-JsonFile (Join-Path $RepoRoot 'WINDOWS/PolicyManifest.json')
        $active = @($manifest['policies'] | Where-Object { $_['status'] -eq 'active' })
        $script:Windows.Count | Should -Be $active.Count
    }

    It 'reads the UTF-16 exports and keeps one copy of each macOS policy' {
        $mac = @(Get-BaselinePolicies $RepoRoot @('MacOS'))
        $mac.Count | Should -BeGreaterThan 10
        @($mac | Where-Object { -not $_.Name }).Count | Should -Be 0
        @($mac | Group-Object { Get-StableIdentity $_.Name } | Where-Object Count -gt 1).Count | Should -Be 0
    }

    It 'turns a Settings Catalog policy into setting id and value pairs' {
        $policy = Get-TestPolicy 'Edge Password Management'
        $id = 'user_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~passwordmanager_passwordmanagerenabled'
        $policy.Kind | Should -Be 'SettingsCatalog'
        $policy.Settings[$id] | Should -Be @("${id}_1")
        $policy.OibId | Should -Match '^[0-9A-F-]{36}$'
    }

    It 'has a friendly name for almost every setting the baseline uses' {
        $ids = @($script:Windows | Where-Object Kind -eq 'SettingsCatalog' | ForEach-Object { $_.Settings.Keys } | Sort-Object -Unique)
        $named = @($ids | Where-Object { $script:OibSettingNames.ContainsKey($_) })
        ($named.Count / $ids.Count) | Should -BeGreaterThan 0.95 -Because 'run the tool with -RefreshSettingNames after the baseline gains settings'
    }
}

Describe 'The write gate' {
    It 'refuses <_> requests' -ForEach 'POST', 'PATCH', 'PUT', 'DELETE' {
        { Invoke-OibGraph -Method $_ -Uri 'deviceManagement/configurationPolicies' } | Should -Throw '*READ-ONLY*'
    }

    It 'still refuses a write when the gate variable is forced open, because no write is implemented' {
        $script:OibWriteUnlocked = $true
        try { { Invoke-OibGraph -Method 'POST' -Uri 'deviceManagement/configurationPolicies' } | Should -Throw '*not implemented*' }
        finally { $script:OibWriteUnlocked = $false }
    }

    It 'refuses to save a snapshot inside the repo' {
        $target = [ordered]@{ Info = [ordered]@{}; Collections = [ordered]@{}; Unreadable = @() }
        { Save-Snapshot $target (Join-Path $RepoRoot 'snapshots/x') } | Should -Throw '*inside the repo*'
        Test-Path (Join-Path $RepoRoot 'snapshots') | Should -BeFalse
    }

    It 'Deploy without both halves of the gate exits 2 and reads nothing' {
        (Invoke-Tool @('-Mode', 'Deploy')).ExitCode | Should -Be 2
        $half = Invoke-Tool @('-Mode', 'Deploy', '-AllowWrite')
        $half.ExitCode | Should -Be 2
        $half.Output | Should -Match 'Nothing was read and nothing was changed'
    }

    It 'Deploy refuses a snapshot as its target' {
        (Invoke-Tool @('-Mode', 'Deploy', '-AllowWrite', '-ConfirmTenant', 'contoso.com', '-SnapshotPath', $TestDrive)).ExitCode | Should -Be 2
    }

    It 'DiffOnly with nothing to compare exits 2' {
        (Invoke-Tool @('-Mode', 'DiffOnly')).ExitCode | Should -Be 2
    }
}

Describe 'Comparing policies' {
    BeforeAll {
        $script:A = Get-TestPolicy 'Edge Password Management'
        $script:B = Get-TestPolicy 'Power and Device Lock'
        $script:C = Get-TestPolicy 'BitLocker (OS Disk)'
        $script:Three = @($script:A, $script:B, $script:C)
    }

    It 'reports Same, Different and Missing' {
        $changed = Copy-TestPolicy $script:B
        $id = @($changed.Settings.Keys | Sort-Object)[0]
        $changed.Settings[$id] = @('something-else')

        $result = Compare-PolicySets $script:Three @((Copy-TestPolicy $script:A), $changed) $script:Manifest @()
        $byName = @{}; foreach ($p in $result.policies) { $byName[$p.policy] = $p }

        $byName[$script:A.Name].result | Should -Be 'Same'
        $byName[$script:B.Name].result | Should -Be 'Different'
        @($byName[$script:B.Name].rows).Count | Should -Be 1
        $byName[$script:B.Name].rows[0].settingId | Should -Be $id
        $byName[$script:C.Name].result | Should -Be 'Missing'
    }

    It 'finds a renamed policy by its OIBID, and a prefixed policy by its name' {
        $byId     = Copy-TestPolicy $script:A -Name 'Totally different name'
        $prefixed = Copy-TestPolicy $script:B -Name "TC01 - $($script:B.Name)" -OibId $null
        $result = Compare-PolicySets @($script:A, $script:B) @($byId, $prefixed) $script:Manifest @()
        @($result.policies | Where-Object { $_.result -eq 'Same' }).Count | Should -Be 2
    }

    It 'reports an earlier version as OlderVersion' {
        $older = Copy-TestPolicy $script:B -Name ((Get-StableIdentity $script:B.Name) + ' - v3.6') -OibId '11111111-1111-1111-1111-111111111111'
        $result = Compare-PolicySets @($script:B) @($older) $script:Manifest @()
        $result.policies[0].result | Should -Be 'OlderVersion'
    }

    It 'reports Unknown, not Missing, for a kind of policy that was not read' {
        $result = Compare-PolicySets @($script:A) @() $script:Manifest @('SettingsCatalog')
        $result.policies[0].result | Should -Be 'Unknown'
    }

    It 'tells you when the settings of a missing policy are set by another policy' {
        $other = Copy-TestPolicy $script:A -Name 'Client browser policy' -OibId $null
        $result = Compare-PolicySets @($script:A) @($other) $script:Manifest @()
        $result.policies[0].result | Should -Be 'Missing'
        $result.policies[0].coverage.sameElsewhere | Should -Be $script:A.Settings.Count
        $result.policies[0].coverage.notSet | Should -Be 0
    }

    It 'reads a snapshot folder and gets the same answer as the files it was made from' {
        $folder = Join-Path $TestDrive 'snap'
        New-Item -ItemType Directory -Path $folder | Out-Null
        $raw = @($script:A, $script:B | ForEach-Object { Read-JsonFile $_.Source })
        ConvertTo-Json -InputObject $raw -Depth 100 | Set-Content (Join-Path $folder 'configurationPolicies.json')
        '[]' | Set-Content (Join-Path $folder 'deviceCompliancePolicies.json')

        $target = Read-Snapshot $folder
        $policies = Get-TargetPolicies $target
        $result = Compare-PolicySets $script:Three $policies $script:Manifest (Get-UnreadableKinds $target)

        @($result.policies | Where-Object { $_.result -eq 'Same' }).Count | Should -Be 2
        @($result.policies | Where-Object { $_.result -eq 'Missing' }).Count | Should -Be 1
        (Get-UnreadableKinds $target) | Should -Contain 'DriverUpdate'
    }

    It 'compares the repo with itself and finds no difference' {
        $run = Invoke-Tool @('-Mode', 'DiffOnly', '-CompareRef', 'HEAD', '-Platform', 'Windows365')
        $run.Output | Should -Match '\| Same \|'
        $run.Output | Should -Not -Match '\| (Different|Missing|OlderVersion) \|'
    }
}

Describe 'Best practices rules' {
    It 'reads both tables of the example file' {
        $rules = Read-RulesFile $script:Example
        $rules.policies.Count | Should -Be 5
        $rules.settings.Count | Should -Be 5
        @($rules.policies | ForEach-Object { $_.decision }) | Should -Be @('Skip', 'Skip', 'Keep', 'Change', 'Add')
        $rules.settings[1].level | Should -Be 'Warn'
    }

    It 'understands every row of the example file' {
        $all = @(Get-BaselinePolicies $RepoRoot @('Windows', 'MacOS'))
        $rows = Invoke-BestPractices (Read-RulesFile $script:Example) $all @() $script:Manifest $false @()
        @($rows | Where-Object { $_.result -eq 'NotUnderstood' }).Count | Should -Be 0
        ($rows | Where-Object { $_.rule -like '*password manager*' }).result | Should -Be 'DiffersFromOIB'
    }

    It 'understands every row of the starter file it writes' {
        $path = Join-Path $TestDrive 'starter.md'
        New-RulesFile $path $script:Windows
        $rows = Invoke-BestPractices (Read-RulesFile $path) $script:Windows @() $script:Manifest $false @()
        @($rows | Where-Object { $_.result -eq 'NotUnderstood' }).Count | Should -Be 0
        @($rows | Where-Object { $_.table -eq 'Policies' }).Count | Should -Be $script:Windows.Count
    }

    It 'reports a row it cannot match as NotUnderstood, never as a pass' {
        $path = Join-Path $TestDrive 'bad.md'
        @(
            '## Policies', '| Policy | Decision | Reason |', '| --- | --- | --- |',
            '| No Such Policy Anywhere | Keep | |',
            '| BitLocker (OS Disk) | Maybe | |',
            '## Settings', '| Policy | Setting | Must be | Level | Reason |', '| --- | --- | --- | --- | --- |',
            '| Edge Password Management | A setting that does not exist | On | Fail | |',
            '| Edge Password Management | Enable saving passwords to the password manager (User) | On | Loud | |',
            '| Power and Device Lock | System Sleep Timeout (seconds): | 600 | Fail | |'
        ) | Set-Content $path
        $rows = Invoke-BestPractices (Read-RulesFile $path) $script:Windows @() $script:Manifest $false @()
        @($rows | Where-Object { $_.result -eq 'NotUnderstood' }).Count | Should -Be 5
        ($rows | Where-Object { $_.rule -like '*System Sleep Timeout*' }).found | Should -Match '\(id: '
    }

    It 'accepts "name (id: short id)" when two settings share a name' {
        $policy = Get-TestPolicy 'Power and Device Lock'
        $ids = @($policy.Settings.Keys | Where-Object { (Get-SettingLabel $_) -eq 'System Sleep Timeout (seconds):' })
        $ids.Count | Should -Be 2
        $cell = Get-SettingDisplay $ids[0] @($policy.Settings.Keys)
        Find-SettingIds $cell @($policy) | Should -Be @($ids[0])
    }

    It 'judges a target: pass, fail by level, conflict, and not set' {
        $policy = Get-TestPolicy 'Edge Password Management'
        $id = 'user_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~passwordmanager_passwordmanagerenabled'
        $off = Copy-TestPolicy $policy -Name 'Client Edge policy' -OibId $null
        $off.Settings[$id] = @("${id}_0")

        $path = Join-Path $TestDrive 'target.md'
        @(
            '## Policies', '| Policy | Decision | Reason |', '| --- | --- | --- |',
            '| Edge Password Management | Skip | |',
            '| BitLocker (OS Disk) | Keep | |',
            '## Settings', '| Policy | Setting | Must be | Level | Reason |', '| --- | --- | --- | --- | --- |',
            '| Edge Password Management | Enable saving passwords to the password manager (User) | Off | Fail | |',
            '| Edge Password Management | Enable saving passwords to the password manager (User) | On | Warn | |',
            '| Power and Device Lock | Unattended Sleep Timeout Plugged In | >= 1800 | Fail | |'
        ) | Set-Content $path
        $rows = Invoke-BestPractices (Read-RulesFile $path) $script:Windows @($off) $script:Manifest $true @()

        @($rows | ForEach-Object { $_.result }) | Should -Be @('Pass', 'Fail', 'Pass', 'Warn', 'Fail')
        $rows[4].found | Should -Be 'Not set in any policy.'
    }
}

Describe 'Matching a "Must be" value' {
    BeforeAll {
        $script:Id = 'user_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~passwordmanager_passwordmanagerenabled'
    }

    It '<Expected> against <Actual> is <Result>' -ForEach @(
        @{ Expected = 'On';        Actual = '_1';  Result = $true }
        @{ Expected = 'Enabled';   Actual = '_1';  Result = $true }
        @{ Expected = 'Off';       Actual = '_1';  Result = $false }
        @{ Expected = 'Disabled';  Actual = '_0';  Result = $true }
        @{ Expected = 'No';        Actual = '_0';  Result = $true }
    ) {
        Test-Expectation $Expected $script:Id @("$($script:Id)$Actual") | Should -Be $Result
    }

    It 'number <Expected> against <Actual> is <Result>' -ForEach @(
        @{ Expected = '900';        Actual = '900';  Result = $true }
        @{ Expected = '900';        Actual = '1800'; Result = $false }
        @{ Expected = '>= 1800';    Actual = '1800'; Result = $true }
        @{ Expected = '<= 900';     Actual = '1800'; Result = $false }
        @{ Expected = '> 5';        Actual = '6';    Result = $true }
        @{ Expected = '60 minutes'; Actual = '60';   Result = $true }
        @{ Expected = '0';          Actual = '5';    Result = $false }
    ) {
        Test-Expectation $Expected 'some_simple_setting' @($Actual) | Should -Be $Result
    }

    It 'handles "Not set"' {
        Test-Expectation 'Not set' $script:Id @() | Should -BeTrue
        Test-Expectation 'Not set' $script:Id @("$($script:Id)_1") | Should -BeFalse
        Test-Expectation 'On' $script:Id @() | Should -BeFalse
    }
}
