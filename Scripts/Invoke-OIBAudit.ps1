#Requires -Version 7.0
<#
.SYNOPSIS
    Compares an Intune tenant, a saved snapshot, or another baseline version with the OIB policies
    in this repo. Read-only unless Deploy mode is unlocked.

.DESCRIPTION
    ReadOnly mode (default): Reads the Intune policies of a tenant, optionally saves a snapshot, and
                             lists which baseline policies are present, older, or absent.
    DiffOnly mode:           Reports setting-level differences between this baseline and a tenant, a
                             snapshot, or another git ref of the baseline. Changes nothing.
    BestPractices mode:      Checks the baseline (no target) or a tenant/snapshot against the rules in
                             a Markdown file that you write. See Scripts/BestPractices.example.md.
    Deploy mode:             Off by default. Needs -AllowWrite and -ConfirmTenant. This version shows
                             the plan and stops. It does not write to a tenant.

    Every request to Microsoft Graph goes through one function. That function refuses any request
    that is not a GET unless Deploy mode has unlocked writes, and this version never unlocks them.

    Sign-in uses an app registration (client credentials). Nothing is read from or written to this
    repo about your tenant. Set these environment variables, or pass a token:
        OIB_TENANT_ID, OIB_CLIENT_ID, OIB_CLIENT_SECRET    or    OIB_ACCESS_TOKEN
    The app needs DeviceManagementConfiguration.Read.All. Organization.Read.All adds the tenant name.
    DeviceManagementApps.Read.All adds the BYOD app protection policies.

.PARAMETER Mode
    'ReadOnly' (default), 'DiffOnly', 'BestPractices', or 'Deploy'.

.PARAMETER Platform
    'Windows', 'MacOS', 'Windows365', 'BYOD', or 'All' (default).

.PARAMETER TenantId
    Tenant to read. Falls back to OIB_TENANT_ID.

.PARAMETER ClientId
    App registration to sign in with. Falls back to OIB_CLIENT_ID.

.PARAMETER SnapshotPath
    Read the target from a snapshot folder saved earlier instead of from a live tenant.

.PARAMETER SaveSnapshot
    Folder to save what was read from the tenant. Keep it outside this repo.

.PARAMETER CompareRef
    DiffOnly: a git ref (tag, branch, commit) of this repo to compare with, in place of a tenant.

.PARAMETER Rules
    BestPractices: path to your rules file.

.PARAMETER NewRulesFile
    BestPractices: write a starter rules file that lists every baseline policy, then exit.

.PARAMETER ListSettings
    Print the settings of the baseline policies that match this name, as rows you can paste into
    the Settings table of your rules file. Accepts a full name, a * wildcard, or a few words.

.PARAMETER RefreshSettingNames
    Rebuild Scripts/OIBAudit.SettingNames.json (the friendly names of settings) from Graph.

.PARAMETER OutFile
    Write the Markdown report to this file as well as to the screen.

.PARAMETER OutJson
    Write the full result as JSON to this file.

.PARAMETER AllowWrite
    Deploy: first half of the write gate.

.PARAMETER ConfirmTenant
    Deploy: second half of the write gate. Must equal the tenant's default domain or display name.

.EXAMPLE
    # What changed between two baseline versions. No tenant, no sign-in.
    ./Scripts/Invoke-OIBAudit.ps1 -Mode DiffOnly -CompareRef windows-v3.8 -Platform Windows

.EXAMPLE
    # Show the settings of one policy with their friendly names, ready to paste into a rules file.
    ./Scripts/Invoke-OIBAudit.ps1 -ListSettings 'Edge Password Management'

.EXAMPLE
    # Read a tenant, save a snapshot outside the repo, list what is present.
    ./Scripts/Invoke-OIBAudit.ps1 -Mode ReadOnly -SaveSnapshot ~/oib-snapshots/contoso

.EXAMPLE
    # Check a saved snapshot against your own rules.
    ./Scripts/Invoke-OIBAudit.ps1 -Mode BestPractices -Rules ~/my-rules.md -SnapshotPath ~/oib-snapshots/contoso

.NOTES
    Exit codes: 0 = no differences and no failed rules. 1 = differences found, or a rule failed or
    was not understood. 2 = refused (bad arguments or the write gate). 3 = Deploy stopped before writing.
#>
[CmdletBinding()]
param(
    [ValidateSet('ReadOnly', 'DiffOnly', 'BestPractices', 'Deploy')]
    [string]$Mode = 'ReadOnly',

    [ValidateSet('Windows', 'MacOS', 'Windows365', 'BYOD', 'All')]
    [string]$Platform = 'All',

    [string]$TenantId,
    [string]$ClientId,
    [string]$SnapshotPath,
    [string]$SaveSnapshot,
    [string]$CompareRef,
    [string]$Rules,
    [string]$NewRulesFile,
    [string]$ListSettings,
    [switch]$RefreshSettingNames,
    [string]$OutFile,
    [string]$OutJson,
    [switch]$AllowWrite,
    [string]$ConfirmTenant
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$RepoRoot         = Split-Path -Parent $PSScriptRoot
$ToolVersion      = '0.1.0'
$GraphRoot        = 'https://graph.microsoft.com/beta'
$OibIdRegex       = [regex]'OIBID:([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})'
$VersionSuffix    = [regex]'\s+-\s+v(\d+(?:\.\d+){1,2})$'
$SettingNamesPath = Join-Path $PSScriptRoot 'OIBAudit.SettingNames.json'

$PlatformFolders = [ordered]@{
    Windows    = 'WINDOWS'
    MacOS      = 'MACOS'
    Windows365 = 'WINDOWS365'
    BYOD       = 'BYOD'
}

# Graph collection that holds each kind of policy. Snapshot file names use the same words.
$KindCollections = [ordered]@{
    SettingsCatalog     = @('deviceManagement/configurationPolicies')
    Compliance          = @('deviceManagement/deviceCompliancePolicies')
    DeviceConfiguration = @('deviceManagement/deviceConfigurations')
    DriverUpdate        = @('deviceManagement/windowsDriverUpdateProfiles')
    AppProtection       = @('deviceAppManagement/iosManagedAppProtections', 'deviceAppManagement/androidManagedAppProtections')
}

# Properties that describe the object, not what it configures. Left out of comparisons.
$MetadataProperties = @(
    'id', 'createdDateTime', 'lastModifiedDateTime', 'version', 'displayName', 'name', 'description',
    'roleScopeTagIds', 'supportsScopeTags', 'assignments', 'scheduledActionsForRule', 'apps',
    'deployedAppCount', 'isAssigned', 'inventorySyncStatus', 'deviceReporting', 'newUpdates',
    'deviceManagementApplicabilityRuleOsEdition', 'deviceManagementApplicabilityRuleOsVersion',
    'deviceManagementApplicabilityRuleDeviceMode', 'validOperatingSystemBuildRanges'
)

$TrueWords  = @('on', 'enabled', 'enable', 'true', 'yes', '1')
$FalseWords = @('off', 'disabled', 'disable', 'false', 'no', '0')

# Write gate. Nothing in this version sets it to $true.
$script:OibWriteUnlocked = $false
$script:OibRequestCount  = @{}
$script:OibAccessToken   = $null
$script:OibSettingNames  = @{}

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
function Get-StableIdentity ([string]$PolicyName) {
    return $VersionSuffix.Replace($PolicyName, '').Trim()
}

function Get-PolicyVersion ([string]$PolicyName) {
    $m = $VersionSuffix.Match($PolicyName)
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Get-OibIdFromDescription ([string]$Description) {
    if ([string]::IsNullOrEmpty($Description)) { return $null }
    $m = $OibIdRegex.Match($Description)
    if ($m.Success) { return $m.Groups[1].Value.ToUpperInvariant() }
    return $null
}

function Get-NormalText ([string]$Text) {
    if ($null -eq $Text) { return '' }
    return ([regex]::Replace($Text.ToLowerInvariant(), '[^a-z0-9]', ''))
}

function Read-JsonFile ([string]$Path) {
    # Get-Content -Raw detects the UTF-16 and UTF-8 byte order marks that the exports use.
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -Depth 100 -NoEnumerate)
}

function ConvertTo-CanonicalValue ($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value.ToString().ToLowerInvariant() }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [System.Collections.IList]) {
        if ($Value -is [System.Collections.IList] -and $Value.Count -eq 0) { return $null }
        return ($Value | ConvertTo-Json -Depth 30 -Compress)
    }
    return [string]$Value
}

# ---------------------------------------------------------------------------
# Policy model. Every policy, from a file, a tenant, or a snapshot, becomes:
#   Name, OibId, Kind, Platform, Source, Settings (id -> sorted string[])
# ---------------------------------------------------------------------------
function Get-PolicyKind ([System.Collections.IDictionary]$Raw) {
    $type    = [string]$Raw['@odata.type']
    $context = [string]$Raw['@odata.context']
    if ($Raw.Contains('settings') -or $type -like '*deviceManagementConfigurationPolicy' -or $context -like '*configurationPolicies*') { return 'SettingsCatalog' }
    if ($type -like '*CompliancePolicy') { return 'Compliance' }
    if ($type -like '*windowsDriverUpdateProfile') { return 'DriverUpdate' }
    if ($type -like '*ManagedAppProtection') { return 'AppProtection' }
    return 'DeviceConfiguration'
}

function Add-SettingValue ([hashtable]$Map, [string]$Id, [string]$Value) {
    if ([string]::IsNullOrEmpty($Id)) { return }
    if (-not $Map.ContainsKey($Id)) { $Map[$Id] = [System.Collections.Generic.List[string]]::new() }
    if ($null -ne $Value -and -not $Map[$Id].Contains($Value)) { $Map[$Id].Add($Value) }
}

function Expand-SettingInstance ($Instance, [hashtable]$Map) {
    # Walks one Settings Catalog setting and its children. Records every leaf value under its
    # settingDefinitionId. A setting that appears in several group instances collects all its values.
    if ($null -eq $Instance) { return }
    $id   = [string]$Instance['settingDefinitionId']
    $type = [string]$Instance['@odata.type']

    if ($type -like '*ChoiceSettingCollectionInstance') {
        foreach ($cv in @($Instance['choiceSettingCollectionValue'])) {
            if ($null -eq $cv) { continue }
            Add-SettingValue $Map $id ([string]$cv['value'])
            foreach ($child in @($cv['children'])) { Expand-SettingInstance $child $Map }
        }
    }
    elseif ($type -like '*ChoiceSettingInstance') {
        $cv = $Instance['choiceSettingValue']
        if ($null -ne $cv) {
            Add-SettingValue $Map $id ([string]$cv['value'])
            foreach ($child in @($cv['children'])) { Expand-SettingInstance $child $Map }
        }
    }
    elseif ($type -like '*SimpleSettingCollectionInstance') {
        foreach ($sv in @($Instance['simpleSettingCollectionValue'])) {
            if ($null -ne $sv) { Add-SettingValue $Map $id (ConvertTo-CanonicalValue $sv['value']) }
        }
    }
    elseif ($type -like '*SimpleSettingInstance') {
        $sv = $Instance['simpleSettingValue']
        if ($null -ne $sv) { Add-SettingValue $Map $id (ConvertTo-CanonicalValue $sv['value']) }
    }
    elseif ($type -like '*GroupSettingCollectionInstance') {
        foreach ($group in @($Instance['groupSettingCollectionValue'])) {
            if ($null -eq $group) { continue }
            foreach ($child in @($group['children'])) { Expand-SettingInstance $child $Map }
        }
    }
    elseif ($type -like '*GroupSettingInstance') {
        $group = $Instance['groupSettingValue']
        if ($null -ne $group) { foreach ($child in @($group['children'])) { Expand-SettingInstance $child $Map } }
    }
    else {
        Add-SettingValue $Map $id "(setting type not recognized: $type)"
    }
}

function ConvertTo-OibPolicy ([System.Collections.IDictionary]$Raw, [string]$PlatformName, [string]$Source, [string]$KindHint) {
    # Items in a tenant collection often carry no @odata.type, so the collection decides the kind.
    $kind = if ($KindHint) { $KindHint } else { Get-PolicyKind $Raw }
    $name = if ($Raw.Contains('name') -and $Raw['name']) { [string]$Raw['name'] } else { [string]$Raw['displayName'] }
    $map  = @{}

    if ($kind -eq 'SettingsCatalog') {
        foreach ($setting in @($Raw['settings'])) {
            if ($null -ne $setting) { Expand-SettingInstance $setting['settingInstance'] $map }
        }
    }
    else {
        foreach ($key in @($Raw.Keys)) {
            if ($key -like '*@odata*' -or $MetadataProperties -contains $key) { continue }
            $value = ConvertTo-CanonicalValue $Raw[$key]
            if ($null -ne $value) { Add-SettingValue $map $key $value }
        }
    }

    $settings = @{}
    foreach ($id in $map.Keys) { $settings[$id] = @($map[$id] | Sort-Object) }

    return [pscustomobject]@{
        Name     = $name
        OibId    = Get-OibIdFromDescription ([string]$Raw['description'])
        Kind     = $kind
        Platform = $PlatformName
        Source   = $Source
        Settings = $settings
    }
}

# ---------------------------------------------------------------------------
# Baseline (the files in this repo, or in another checkout of it)
# ---------------------------------------------------------------------------
function Get-BaselinePolicies ([string]$Root, [string[]]$Platforms) {
    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($platformName in $Platforms) {
        $folder = Join-Path $Root $PlatformFolders[$platformName]
        if (-not (Test-Path $folder)) { continue }

        $candidates = foreach ($file in Get-ChildItem -Path $folder -Recurse -Filter '*.json' -File) {
            if ($file.Name -eq 'PolicyManifest.json') { continue }
            $policy = ConvertTo-OibPolicy (Read-JsonFile $file.FullName) $platformName $file.FullName
            if ([string]::IsNullOrEmpty($policy.Name)) { continue }
            $policy
        }

        # MACOS and WINDOWS365 ship each policy twice (IntuneManagement and NativeImport).
        # Keep one per policy: the higher version, and NativeImport when the versions are equal.
        foreach ($group in ($candidates | Group-Object { Get-StableIdentity $_.Name })) {
            $best = $group.Group | Sort-Object `
                @{ Expression = { $v = Get-PolicyVersion $_.Name; if ($v) { [version]$v } else { [version]'0.0' } }; Descending = $true },
                @{ Expression = { $_.Source -like '*NativeImport*' }; Descending = $true } | Select-Object -First 1
            $result.Add($best)
        }
    }
    return @($result | Sort-Object Platform, Name)
}

function Get-BaselineManifest ([string]$Root, [string[]]$Platforms) {
    # oibId (upper case) -> manifest entry. Only platforms that have a PolicyManifest.json.
    $index = @{ ById = @{}; PreviousToCurrent = @{}; Versions = @{} }
    foreach ($platformName in $Platforms) {
        $path = Join-Path (Join-Path $Root $PlatformFolders[$platformName]) 'PolicyManifest.json'
        if (-not (Test-Path $path)) { continue }
        $manifest = Read-JsonFile $path
        $index.Versions[$platformName] = [string]$manifest['oibVersion']
        foreach ($entry in @($manifest['policies'])) {
            $id = ([string]$entry['oibId']).ToUpperInvariant()
            $index.ById[$id] = $entry
            foreach ($previous in @($entry['previousVersions'])) {
                if ($null -ne $previous) { $index.PreviousToCurrent[([string]$previous['oibId']).ToUpperInvariant()] = $id }
            }
        }
    }
    return $index
}

# ---------------------------------------------------------------------------
# Microsoft Graph. One function sends every request. GET only.
# ---------------------------------------------------------------------------
function Get-OibAccessToken {
    if ($script:OibAccessToken) { return $script:OibAccessToken }
    if ($env:OIB_ACCESS_TOKEN) { $script:OibAccessToken = $env:OIB_ACCESS_TOKEN; return $script:OibAccessToken }

    $tenant = if ($TenantId) { $TenantId } else { $env:OIB_TENANT_ID }
    $client = if ($ClientId) { $ClientId } else { $env:OIB_CLIENT_ID }
    if (-not $tenant -or -not $client -or -not $env:OIB_CLIENT_SECRET) {
        throw 'No sign-in details. Set OIB_TENANT_ID, OIB_CLIENT_ID and OIB_CLIENT_SECRET, or set OIB_ACCESS_TOKEN, or use -SnapshotPath.'
    }
    # The token request is a POST to the sign-in service, not to the tenant's data. It changes nothing.
    $body = @{
        grant_type    = 'client_credentials'
        client_id     = $client
        client_secret = $env:OIB_CLIENT_SECRET
        scope         = 'https://graph.microsoft.com/.default'
    }
    $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Body $body
    $script:OibAccessToken = $response.access_token
    return $script:OibAccessToken
}

function Invoke-OibGraph {
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Uri
    )
    $Method = $Method.ToUpperInvariant()
    if ($Method -ne 'GET') {
        if (-not $script:OibWriteUnlocked) {
            throw "READ-ONLY: refused $Method $Uri. This tool does not change a tenant."
        }
        throw "Writes are not implemented in version $ToolVersion. Refused $Method $Uri."
    }

    if ($Uri -notmatch '^https://') { $Uri = "$GraphRoot/$Uri" }
    $headers = @{ Authorization = "Bearer $(Get-OibAccessToken)" }
    $script:OibRequestCount[$Method] = 1 + [int]$script:OibRequestCount[$Method]

    for ($attempt = 1; ; $attempt++) {
        try {
            return (Invoke-WebRequest -Method Get -Uri $Uri -Headers $headers -SkipHttpErrorCheck:$false).Content |
                ConvertFrom-Json -AsHashtable -Depth 100 -NoEnumerate
        }
        catch {
            $status = $null
            if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -in 429, 503, 504 -and $attempt -lt 5) {
                Start-Sleep -Seconds ([math]::Min(30, 2 * $attempt))
                continue
            }
            throw
        }
    }
}

function Get-OibGraphCollection ([string]$Uri) {
    $items = [System.Collections.Generic.List[object]]::new()
    $next  = $Uri
    while ($next) {
        $page = Invoke-OibGraph -Uri $next
        foreach ($item in @($page['value'])) { if ($null -ne $item) { $items.Add($item) } }
        $next = if ($page.Contains('@odata.nextLink')) { [string]$page['@odata.nextLink'] } else { $null }
    }
    return , $items.ToArray()
}

function Get-ErrorStatus ($ErrorRecord) {
    if ($ErrorRecord.Exception.PSObject.Properties['Response'] -and $ErrorRecord.Exception.Response) {
        return [int]$ErrorRecord.Exception.Response.StatusCode
    }
    return 0
}

# ---------------------------------------------------------------------------
# Target: a live tenant, a snapshot folder, or another git ref of the baseline.
# A target is: Label, Type, Info, Collections (collection name -> raw objects), Unreadable (list)
# ---------------------------------------------------------------------------
function Read-TenantLive {
    $target = [ordered]@{ Type = 'Tenant'; Label = 'the tenant'; Info = [ordered]@{}; Collections = [ordered]@{}; Unreadable = [System.Collections.Generic.List[object]]::new() }

    try {
        $orgs = Get-OibGraphCollection 'organization?$select=id,displayName,verifiedDomains'
        $org = $orgs | Select-Object -First 1
        $default = $org['verifiedDomains'] | Where-Object { $_['isDefault'] } | Select-Object -First 1
        $target.Info['tenantId']      = [string]$org['id']
        $target.Info['displayName']   = ([string]$org['displayName']).Trim()
        $target.Info['defaultDomain'] = if ($default) { [string]$default['name'] } else { '' }
        $target.Label = '{0} ({1})' -f $target.Info['displayName'], $target.Info['defaultDomain']
    }
    catch {
        $target.Unreadable.Add([ordered]@{ collection = 'organization'; reason = "Tenant name not read (HTTP $(Get-ErrorStatus $_)). Organization.Read.All is not granted." })
    }
    $target.Info['capturedAt'] = (Get-Date).ToUniversalTime().ToString('o')

    foreach ($kind in $KindCollections.Keys) {
        foreach ($collection in $KindCollections[$kind]) {
            $leaf = Split-Path $collection -Leaf
            try {
                $items = Get-OibGraphCollection $collection
                if ($kind -eq 'SettingsCatalog') {
                    foreach ($item in $items) {
                        $item['settings'] = Get-OibGraphCollection "deviceManagement/configurationPolicies('$($item['id'])')/settings"
                    }
                }
                $target.Collections[$leaf] = $items
            }
            catch {
                $status = Get-ErrorStatus $_
                $reason = if ($status -in 401, 403) { "Permission is missing (HTTP $status)." } else { "Read failed (HTTP $status): $($_.Exception.Message)" }
                $target.Unreadable.Add([ordered]@{ collection = $leaf; reason = $reason })
            }
        }
    }
    return $target
}

function Save-Snapshot ($Target, [string]$Folder) {
    $resolvedRepo = (Resolve-Path $RepoRoot).Path
    $full = [System.IO.Path]::GetFullPath($Folder)
    if ($full.StartsWith($resolvedRepo, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refused to save a snapshot inside the repo ($full). Tenant data must stay outside it. Choose another folder."
    }
    New-Item -ItemType Directory -Path $full -Force | Out-Null
    $meta = [ordered]@{ tool = 'Invoke-OIBAudit'; version = $ToolVersion; info = $Target.Info; unreadable = @($Target.Unreadable) }
    $meta | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $full 'tenant.json') -Encoding utf8
    foreach ($leaf in $Target.Collections.Keys) {
        ConvertTo-Json -InputObject @($Target.Collections[$leaf]) -Depth 100 | Set-Content -LiteralPath (Join-Path $full "$leaf.json") -Encoding utf8
    }
    return $full
}

function Read-Snapshot ([string]$Folder) {
    if (-not (Test-Path $Folder)) { throw "Snapshot folder not found: $Folder" }
    $target = [ordered]@{ Type = 'Snapshot'; Label = "snapshot $Folder"; Info = [ordered]@{}; Collections = [ordered]@{}; Unreadable = [System.Collections.Generic.List[object]]::new() }
    $metaPath = Join-Path $Folder 'tenant.json'
    if (Test-Path $metaPath) {
        $meta = Read-JsonFile $metaPath
        if ($meta['info']) { foreach ($key in $meta['info'].Keys) { $target.Info[$key] = $meta['info'][$key] } }
        foreach ($entry in @($meta['unreadable'])) { if ($null -ne $entry) { $target.Unreadable.Add($entry) } }
        if ($target.Info['displayName']) {
            $taken = $target.Info['capturedAt']
            if ($taken -is [datetime]) { $taken = $taken.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC' }
            $target.Label = 'snapshot of {0} ({1}), taken {2}' -f ([string]$target.Info['displayName']).Trim(), $target.Info['defaultDomain'], $taken
        }
    }
    foreach ($kind in $KindCollections.Keys) {
        foreach ($collection in $KindCollections[$kind]) {
            $leaf = Split-Path $collection -Leaf
            $path = Join-Path $Folder "$leaf.json"
            if (Test-Path $path) {
                $target.Collections[$leaf] = @(Read-JsonFile $path)
            }
            elseif (-not @($target.Unreadable | Where-Object { $_['collection'] -eq $leaf })) {
                $target.Unreadable.Add([ordered]@{ collection = $leaf; reason = 'Not in the snapshot.' })
            }
        }
    }
    return $target
}

function Get-TargetPolicies ($Target) {
    $policies = [System.Collections.Generic.List[object]]::new()
    foreach ($leaf in $Target.Collections.Keys) {
        $kind = $KindCollections.Keys | Where-Object { @($KindCollections[$_] | ForEach-Object { Split-Path $_ -Leaf }) -contains $leaf } | Select-Object -First 1
        foreach ($raw in @($Target.Collections[$leaf])) {
            if ($null -eq $raw) { continue }
            $policies.Add((ConvertTo-OibPolicy $raw '' $leaf $kind))
        }
    }
    return , $policies.ToArray()
}

function Get-UnreadableKinds ($Target) {
    $kinds = @()
    foreach ($kind in $KindCollections.Keys) {
        foreach ($collection in $KindCollections[$kind]) {
            $leaf = Split-Path $collection -Leaf
            if (@($Target.Unreadable | Where-Object { $_['collection'] -eq $leaf })) { $kinds += $kind }
        }
    }
    return @($kinds | Select-Object -Unique)
}

function Export-GitRef ([string]$Ref) {
    # Copies the policy folders of another git ref into a temporary folder.
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("oib-audit-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temp | Out-Null
    $archive = Join-Path $temp 'ref.tar'
    $folders = @($PlatformFolders.Values | Where-Object { git -C $RepoRoot ls-tree --name-only $Ref -- $_ 2>$null })
    if (-not $folders) { throw "Git ref '$Ref' was not found, or it has no policy folders." }
    git -C $RepoRoot archive --format=tar "--output=$archive" $Ref -- @folders
    if ($LASTEXITCODE -ne 0) { throw "git archive failed for ref '$Ref'." }
    tar -xf $archive -C $temp
    Remove-Item -LiteralPath $archive
    return $temp
}

# ---------------------------------------------------------------------------
# Friendly names for settings and their options
# ---------------------------------------------------------------------------
function Import-SettingNames {
    $script:OibSettingNames = @{}
    if (Test-Path $SettingNamesPath) {
        $data = Read-JsonFile $SettingNamesPath
        foreach ($id in $data.Keys) { $script:OibSettingNames[$id] = $data[$id] }
    }
}

function Get-ShortKey ([string]$Id) {
    if ($Id -match '~([^~]+)$') { return $Matches[1] }
    if ($Id -match 'policy_config_(.+)$') { return $Matches[1] }
    return $Id
}

function Get-SettingLabel ([string]$Id) {
    $entry = $script:OibSettingNames[$Id]
    if ($entry -and $entry['name']) { return [string]$entry['name'] }
    return (Get-ShortKey $Id)
}

function Get-SettingDisplay ([string]$Id, [string[]]$ScopeIds) {
    # Two settings in one policy can share a friendly name (battery and plugged-in, for example).
    # Then the name alone does not say which one is meant, so the short id is added.
    $label = Get-SettingLabel $Id
    $twins = @($ScopeIds | Where-Object { $_ -ne $Id -and (Get-SettingLabel $_) -eq $label })
    if ($twins) { return "$label (id: $(Get-ShortKey $Id))" }
    return $label
}

function Get-ValueSuffix ([string]$Id, [string]$Value) {
    if ($Value.StartsWith("${Id}_", [System.StringComparison]::OrdinalIgnoreCase)) { return $Value.Substring($Id.Length + 1) }
    return $Value
}

function Get-ValueLabel ([string]$Id, [string]$Value) {
    $entry = $script:OibSettingNames[$Id]
    if ($entry -and $entry['options'] -and $entry['options'][$Value]) { return [string]$entry['options'][$Value] }
    return (Get-ValueSuffix $Id $Value)
}

function Format-Values ([string]$Id, [string[]]$Values) {
    if (-not $Values -or $Values.Count -eq 0) { return '(not set)' }
    return (@($Values | ForEach-Object { Get-ValueLabel $Id $_ }) -join ', ')
}

function Update-SettingNames ([object[]]$Policies) {
    # One GET for each setting id that the baseline uses. Setting definitions are the same in every tenant.
    $names = [ordered]@{}
    $ids = @($Policies | Where-Object Kind -eq 'SettingsCatalog' | ForEach-Object { $_.Settings.Keys } | Sort-Object -Unique)
    $done = 0
    foreach ($id in $ids) {
        $done++
        if ($done % 100 -eq 0) { Write-Host "  setting names: $done of $($ids.Count)" }
        try {
            $definition = Invoke-OibGraph -Uri ("deviceManagement/configurationSettings('{0}')" -f [uri]::EscapeDataString($id))
        }
        catch { continue }
        $entry = [ordered]@{ name = [string]$definition['displayName'] }
        if ($definition.Contains('options') -and $definition['options']) {
            $options = [ordered]@{}
            foreach ($option in @($definition['options'])) { $options[[string]$option['itemId']] = [string]$option['displayName'] }
            $entry['options'] = $options
        }
        $names[$id] = $entry
    }
    $names | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $SettingNamesPath -Encoding utf8
    return $names.Count
}

# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------
function Find-TargetPolicy ($BaselinePolicy, [object[]]$TargetPolicies, $Manifest) {
    # Returns @{ Policy; How } or $null. Order: OIBID, exact name, earlier version, name inside a longer name.
    $sameKind = @($TargetPolicies | Where-Object Kind -eq $BaselinePolicy.Kind)

    if ($BaselinePolicy.OibId) {
        $hit = $sameKind | Where-Object { $_.OibId -eq $BaselinePolicy.OibId } | Select-Object -First 1
        if ($hit) { return @{ Policy = $hit; How = 'Current' } }
    }
    $hit = $sameKind | Where-Object { $_.Name -eq $BaselinePolicy.Name } | Select-Object -First 1
    if ($hit) { return @{ Policy = $hit; How = 'Current' } }

    if ($BaselinePolicy.OibId) {
        $hit = $sameKind | Where-Object { $_.OibId -and $Manifest.PreviousToCurrent[$_.OibId] -eq $BaselinePolicy.OibId } | Select-Object -First 1
        if ($hit) { return @{ Policy = $hit; How = 'Older' } }
    }
    $identity = Get-StableIdentity $BaselinePolicy.Name
    $hit = $sameKind | Where-Object { (Get-StableIdentity $_.Name) -eq $identity } | Select-Object -First 1
    if ($hit) { return @{ Policy = $hit; How = 'Older' } }

    # A customer prefix or suffix around the baseline name, for example "TC01 - Win - OIB - ...".
    $hit = $sameKind | Where-Object { $_.Name -like "*$([WildcardPattern]::Escape($BaselinePolicy.Name))*" } | Select-Object -First 1
    if ($hit) { return @{ Policy = $hit; How = 'Current' } }
    $hit = $sameKind | Where-Object { (Get-StableIdentity $_.Name) -like "*$([WildcardPattern]::Escape($identity))" } | Select-Object -First 1
    if ($hit) { return @{ Policy = $hit; How = 'Older' } }

    return $null
}

function Compare-PolicySettings ($BaselinePolicy, $TargetPolicy) {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($id in ($BaselinePolicy.Settings.Keys | Sort-Object)) {
        $want = @($BaselinePolicy.Settings[$id])
        if (-not $TargetPolicy.Settings.ContainsKey($id)) {
            $rows.Add([ordered]@{ settingId = $id; baseline = $want; target = @(); result = 'NotSet'; where = $TargetPolicy.Name })
            continue
        }
        $have = @($TargetPolicy.Settings[$id])
        if (($want -join "`n") -ne ($have -join "`n")) {
            $rows.Add([ordered]@{ settingId = $id; baseline = $want; target = $have; result = 'Different'; where = $TargetPolicy.Name })
        }
    }
    # Settings that only the target has. Only meaningful for Settings Catalog: other policy kinds
    # return every property, so a target-only property there is noise.
    if ($BaselinePolicy.Kind -eq 'SettingsCatalog') {
        foreach ($id in ($TargetPolicy.Settings.Keys | Sort-Object)) {
            if (-not $BaselinePolicy.Settings.ContainsKey($id)) {
                $rows.Add([ordered]@{ settingId = $id; baseline = @(); target = @($TargetPolicy.Settings[$id]); result = 'OnlyInTarget'; where = $TargetPolicy.Name })
            }
        }
    }
    return , $rows.ToArray()
}

function Get-SettingIndex ([object[]]$TargetPolicies) {
    # settingDefinitionId -> list of @{ policy; vals } across every Settings Catalog policy in the target.
    $index = @{}
    foreach ($policy in @($TargetPolicies | Where-Object Kind -eq 'SettingsCatalog')) {
        foreach ($id in $policy.Settings.Keys) {
            if (-not $index.ContainsKey($id)) { $index[$id] = [System.Collections.Generic.List[object]]::new() }
            $index[$id].Add(@{ policy = $policy.Name; vals = @($policy.Settings[$id]) })
        }
    }
    return $index
}

function Compare-PolicySets ([object[]]$BaselinePolicies, [object[]]$TargetPolicies, $Manifest, [string[]]$UnreadableKinds) {
    $settingIndex = Get-SettingIndex $TargetPolicies
    $matchedNames = [System.Collections.Generic.HashSet[string]]::new()
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($policy in $BaselinePolicies) {
        $entry = [ordered]@{
            policy = $policy.Name; platform = $policy.Platform; kind = $policy.Kind; oibId = $policy.OibId
            result = ''; targetPolicy = $null; note = ''; settingCount = $policy.Settings.Count
            rows = @(); coverage = $null
        }

        if ($UnreadableKinds -contains $policy.Kind) {
            $entry.result = 'Unknown'
            $entry.note   = 'This kind of policy was not read from the target.'
            $results.Add($entry); continue
        }

        $found = Find-TargetPolicy $policy $TargetPolicies $Manifest
        if ($found) {
            [void]$matchedNames.Add($found.Policy.Name)
            $entry.targetPolicy = $found.Policy.Name
            $entry.rows = Compare-PolicySettings $policy $found.Policy
            if ($found.How -eq 'Older') {
                $entry.result = 'OlderVersion'
                $entry.note   = "Target has '$($found.Policy.Name)'."
            }
            else {
                $entry.result = if ($entry.rows.Count) { 'Different' } else { 'Same' }
            }
        }
        else {
            $entry.result = 'Missing'
            if ($policy.Kind -eq 'SettingsCatalog') {
                # The policy is absent. Are its settings configured by some other policy in the target?
                $same = 0; $different = 0; $notSet = 0
                $rows = [System.Collections.Generic.List[object]]::new()
                foreach ($id in ($policy.Settings.Keys | Sort-Object)) {
                    $want = @($policy.Settings[$id])
                    if (-not $settingIndex.ContainsKey($id)) { $notSet++; continue }
                    $hits = @($settingIndex[$id])
                    $equal = @($hits | Where-Object { ($_.vals -join "`n") -eq ($want -join "`n") })
                    if ($equal.Count -eq $hits.Count) { $same++; continue }
                    $different++
                    $other = $hits | Where-Object { ($_.vals -join "`n") -ne ($want -join "`n") } | Select-Object -First 1
                    $rows.Add([ordered]@{ settingId = $id; baseline = $want; target = @($other.vals); result = 'ElsewhereDifferent'; where = $other.policy })
                }
                $entry.coverage = [ordered]@{ sameElsewhere = $same; differentElsewhere = $different; notSet = $notSet }
                $entry.rows = $rows.ToArray()
            }
        }
        $results.Add($entry)
    }

    # Policies in the target that carry an OIB mark but match nothing in this baseline version.
    $extra = [System.Collections.Generic.List[object]]::new()
    foreach ($policy in $TargetPolicies) {
        if ($matchedNames.Contains($policy.Name)) { continue }
        $isOib = $policy.OibId -or $policy.Name -match '\bOIB\b'
        if (-not $isOib) { continue }
        $note = 'Not in this baseline version.'
        if ($policy.OibId -and $Manifest.ById.ContainsKey($policy.OibId)) {
            $manifestEntry = $Manifest.ById[$policy.OibId]
            if ([string]$manifestEntry['status'] -ne 'active') {
                $by = @($manifestEntry['supersededBy'] | ForEach-Object { if ($Manifest.ById.ContainsKey(([string]$_).ToUpperInvariant())) { [string]$Manifest.ById[([string]$_).ToUpperInvariant()]['name'] } })
                $note = "Marked '$($manifestEntry['status'])' in the baseline manifest." + $(if ($by) { " Replaced by: $($by -join '; ')." } else { '' })
            }
        }
        $extra.Add([ordered]@{ policy = $policy.Name; kind = $policy.Kind; oibId = $policy.OibId; note = $note })
    }

    return [ordered]@{ policies = $results.ToArray(); extra = $extra.ToArray(); otherPolicyCount = @($TargetPolicies).Count - $matchedNames.Count - $extra.Count }
}

# ---------------------------------------------------------------------------
# Best practices: a Markdown file with two tables
# ---------------------------------------------------------------------------
function Read-MarkdownTables ([string]$Path) {
    # Returns section title -> list of rows (ordered dictionaries keyed by the header cells).
    $tables  = [ordered]@{}
    $section = ''
    $header  = $null
    $lineNo  = 0
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $lineNo++
        $text = $line.Trim()
        if ($text -match '^#+\s*(.+?)\s*$') { $section = $Matches[1]; $header = $null; continue }
        if (-not $text.StartsWith('|')) { $header = $null; continue }

        $cells = @($text.Trim('|') -split '(?<!\\)\|' | ForEach-Object { $_.Trim().Replace('\|', '|') })
        if ($null -eq $header) { $header = $cells; continue }
        if (($cells -join '') -match '^[\s:\-]*$') { continue }   # the |---|---| line

        $row = [ordered]@{ '#line' = $lineNo }
        for ($i = 0; $i -lt $header.Count; $i++) {
            $row[$header[$i]] = if ($i -lt $cells.Count) { $cells[$i].Trim('`') } else { '' }
        }
        if (-not $tables.Contains($section)) { $tables[$section] = [System.Collections.Generic.List[object]]::new() }
        $tables[$section].Add($row)
    }
    return $tables
}

function Get-RowCell ($Row, [string[]]$Names) {
    foreach ($key in @($Row.Keys)) {
        if ($Names -contains (Get-NormalText $key)) { return [string]$Row[$key] }
    }
    return ''
}

function Read-RulesFile ([string]$Path) {
    if (-not (Test-Path $Path)) { throw "Rules file not found: $Path" }
    $tables = Read-MarkdownTables $Path
    $rules  = [ordered]@{ policies = [System.Collections.Generic.List[object]]::new(); settings = [System.Collections.Generic.List[object]]::new() }
    foreach ($section in $tables.Keys) {
        $isPolicies = (Get-NormalText $section) -like '*polic*'
        $isSettings = (Get-NormalText $section) -like '*setting*'
        foreach ($row in $tables[$section]) {
            $policyCell = Get-RowCell $row @('policy')
            if ($isSettings) {
                $level = Get-RowCell $row @('level')
                $rules.settings.Add([ordered]@{
                    line = $row['#line']; policy = $policyCell
                    setting = Get-RowCell $row @('setting')
                    mustBe  = Get-RowCell $row @('mustbe', 'value', 'expected')
                    level   = if ($level) { (Get-Culture).TextInfo.ToTitleCase($level.ToLower()) } else { 'Fail' }
                    reason  = Get-RowCell $row @('reason', 'why')
                })
            }
            elseif ($isPolicies) {
                if (-not $policyCell) { continue }
                $decision = Get-RowCell $row @('decision', 'status')
                $rules.policies.Add([ordered]@{
                    line = $row['#line']; policy = $policyCell
                    decision = if ($decision) { (Get-Culture).TextInfo.ToTitleCase($decision.ToLower()) } else { 'Keep' }
                    reason = Get-RowCell $row @('reason', 'why')
                })
            }
        }
    }
    return $rules
}

function Find-BaselinePolicies ([string]$Cell, [object[]]$BaselinePolicies) {
    # Exact name, then name without its version, then a * wildcard, then "every word appears".
    if ([string]::IsNullOrWhiteSpace($Cell) -or $Cell -in 'Any', '*') { return $BaselinePolicies }
    $hits = @($BaselinePolicies | Where-Object { $_.Name -eq $Cell })
    if ($hits) { return $hits }
    $hits = @($BaselinePolicies | Where-Object { (Get-StableIdentity $_.Name) -eq (Get-StableIdentity $Cell) })
    if ($hits) { return $hits }
    if ($Cell.Contains('*')) {
        $hits = @($BaselinePolicies | Where-Object { $_.Name -like $Cell })
        if ($hits) { return $hits }
    }
    $words = @($Cell -split '[^A-Za-z0-9]+' | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    if (-not $words) { return @() }
    return @($BaselinePolicies | Where-Object {
            $nameWords = @($_.Name -split '[^A-Za-z0-9]+' | ForEach-Object { $_.ToLowerInvariant() })
            -not @($words | Where-Object { $nameWords -notcontains $_ })
        })
}

function Find-SettingIds ([string]$Cell, [object[]]$Policies) {
    # Returns the setting ids that the cell names inside the given policies.
    $ids = @($Policies | ForEach-Object { $_.Settings.Keys } | Sort-Object -Unique)
    $hit = @($ids | Where-Object { $_ -eq $Cell })
    if ($hit) { return $hit }

    # "Friendly name (id: short_id)" names one setting exactly.
    if ($Cell -match '\(id:\s*([^)]+)\)\s*$') {
        $key = Get-NormalText $Matches[1]
        return @($ids | Where-Object { (Get-NormalText $_) -eq $key -or (Get-NormalText (Get-ShortKey $_)) -eq $key })
    }

    $wanted = Get-NormalText $Cell
    if (-not $wanted) { return @() }
    $hit = @($ids | Where-Object { (Get-NormalText (Get-SettingLabel $_)) -eq $wanted -or (Get-NormalText (Get-ShortKey $_)) -eq $wanted })
    if ($hit) { return $hit }
    return @($ids | Where-Object { (Get-NormalText (Get-SettingLabel $_)).Contains($wanted) -or (Get-NormalText (Get-ShortKey $_)).Contains($wanted) })
}

function Test-Expectation ([string]$Expected, [string]$Id, [string[]]$Values) {
    $wanted = Get-NormalText $Expected
    if ($wanted -in 'notset', 'notconfigured', 'absent') { return (-not $Values -or $Values.Count -eq 0) }
    if (-not $Values -or $Values.Count -eq 0) { return $false }

    foreach ($value in $Values) {
        $suffix = Get-NormalText (Get-ValueSuffix $Id $value)
        $label  = Get-NormalText (Get-ValueLabel $Id $value)
        $ok = $false

        if ($label -eq $wanted -or $suffix -eq $wanted -or (Get-NormalText $value) -eq $wanted) { $ok = $true }
        elseif ($TrueWords -contains $wanted) { $ok = ($TrueWords -contains $suffix) -or ($TrueWords -contains $label) }
        elseif ($FalseWords -contains $wanted) { $ok = ($FalseWords -contains $suffix) -or ($FalseWords -contains $label) }
        elseif ($Expected.Trim() -match '^(>=|<=|>|<|=)?\s*(-?\d+(?:\.\d+)?)') {
            $operator = if ($Matches[1]) { $Matches[1] } else { '=' }
            $number   = [double]$Matches[2]
            $actual   = 0.0
            $rawTail  = Get-ValueSuffix $Id $value
            if ([double]::TryParse($value, [ref]$actual) -or [double]::TryParse($rawTail, [ref]$actual)) {
                $ok = switch ($operator) {
                    '>=' { $actual -ge $number }
                    '<=' { $actual -le $number }
                    '>'  { $actual -gt $number }
                    '<'  { $actual -lt $number }
                    default { $actual -eq $number }
                }
            }
        }
        if (-not $ok) { return $false }
    }
    return $true
}

function Invoke-BestPractices ($RuleSet, [object[]]$BaselinePolicies, [object[]]$TargetPolicies, $Manifest, [bool]$HasTarget, [string[]]$UnreadableKinds) {
    $rows = [System.Collections.Generic.List[object]]::new()
    $settingIndex = if ($HasTarget) { Get-SettingIndex $TargetPolicies } else { @{} }

    foreach ($rule in $RuleSet.policies) {
        $row = [ordered]@{ line = $rule.line; table = 'Policies'; rule = "$($rule.policy): $($rule.decision)"; expected = $rule.decision; found = ''; result = ''; reason = $rule.reason }
        if ($rule.decision -notin 'Keep', 'Change', 'Skip', 'Add') {
            $row.result = 'NotUnderstood'; $row.found = "Decision '$($rule.decision)' is not one of Keep, Change, Skip, Add."
            $rows.Add($row); continue
        }

        if ($rule.decision -eq 'Add') {
            # A policy of your own that is not part of OIB. It can only be checked against a target.
            if (-not $HasTarget) { $row.result = 'Info'; $row.found = 'Your own policy. Not checked without a target.' }
            else {
                $hit = @($TargetPolicies | Where-Object { $_.Name -like "*$([WildcardPattern]::Escape($rule.policy))*" })
                $row.result = if ($hit) { 'Pass' } else { 'Fail' }
                $row.found  = if ($hit) { "Present: $($hit[0].Name)" } else { 'Not in the target.' }
            }
            $rows.Add($row); continue
        }

        $matches_ = @(Find-BaselinePolicies $rule.policy $BaselinePolicies)
        if (-not $matches_) {
            $row.result = 'NotUnderstood'; $row.found = 'No baseline policy matches this name.'
            $rows.Add($row); continue
        }
        if (-not $HasTarget) {
            $row.result = 'Info'
            $row.found  = "Matches $($matches_.Count) baseline polic$(if ($matches_.Count -eq 1) { 'y' } else { 'ies' })."
            $rows.Add($row); continue
        }

        $present = @(); $absent = @(); $unknown = @()
        foreach ($policy in $matches_) {
            if ($UnreadableKinds -contains $policy.Kind) { $unknown += $policy.Name; continue }
            if (Find-TargetPolicy $policy $TargetPolicies $Manifest) { $present += $policy.Name } else { $absent += $policy.Name }
        }
        if ($rule.decision -eq 'Skip') {
            $row.result = if ($present) { 'Warn' } else { 'Pass' }
            $row.found  = if ($present) { "Deployed, but your rules say Skip: $($present -join '; ')" } else { 'Not deployed.' }
        }
        else {
            $row.result = if ($absent) { 'Fail' } elseif ($unknown) { 'Unknown' } else { 'Pass' }
            $row.found  = if ($absent) { "Missing: $($absent -join '; ')" } elseif ($unknown) { "Could not be read: $($unknown -join '; ')" } else { "Present ($($present.Count))." }
        }
        $rows.Add($row)
    }

    foreach ($rule in $RuleSet.settings) {
        $row = [ordered]@{ line = $rule.line; table = 'Settings'; rule = "$($rule.policy) / $($rule.setting)"; expected = $rule.mustBe; found = ''; result = ''; reason = $rule.reason; level = $rule.level; settingId = $null }
        if ($rule.level -notin 'Fail', 'Warn', 'Info') {
            $row.result = 'NotUnderstood'; $row.found = "Level '$($rule.level)' is not one of Fail, Warn, Info."
            $rows.Add($row); continue
        }
        if (-not $rule.setting -or -not $rule.mustBe) {
            $row.result = 'NotUnderstood'; $row.found = 'The Setting cell or the Must be cell is empty.'
            $rows.Add($row); continue
        }
        $policies = @(Find-BaselinePolicies $rule.policy $BaselinePolicies)
        if (-not $policies) {
            $row.result = 'NotUnderstood'; $row.found = 'No baseline policy matches the Policy cell.'
            $rows.Add($row); continue
        }
        $ids = @(Find-SettingIds $rule.setting $policies)
        if ($ids.Count -eq 0) {
            $row.result = 'NotUnderstood'; $row.found = 'No setting with this name in the matched polic' + $(if ($policies.Count -eq 1) { 'y.' } else { 'ies.' })
            $rows.Add($row); continue
        }
        if ($ids.Count -gt 1) {
            $row.result = 'NotUnderstood'
            $row.found  = "The name matches $($ids.Count) settings. Use one of: " + (@($ids | Select-Object -First 6 | ForEach-Object { Get-SettingDisplay $_ $ids }) -join '; ')
            $rows.Add($row); continue
        }
        $id = $ids[0]
        $row.settingId = $id

        if (-not $HasTarget) {
            # No target: compare the rule with the baseline, so you see where your standard differs from OIB.
            $owner  = $policies | Where-Object { $_.Settings.ContainsKey($id) } | Select-Object -First 1
            $values = @($owner.Settings[$id])
            $row.found  = "OIB sets: $(Format-Values $id $values)"
            $row.result = if (Test-Expectation $rule.mustBe $id $values) { 'SameAsOIB' } else { 'DiffersFromOIB' }
            $rows.Add($row); continue
        }

        $hits = if ($settingIndex.ContainsKey($id)) { @($settingIndex[$id]) } else { @() }
        if (-not $hits) {
            $passes = Test-Expectation $rule.mustBe $id @()
            $row.found  = 'Not set in any policy.'
            $row.result = if ($passes) { 'Pass' } elseif ($UnreadableKinds -contains 'SettingsCatalog') { 'Unknown' } else { $rule.level }
            $rows.Add($row); continue
        }
        $bad = @($hits | Where-Object { -not (Test-Expectation $rule.mustBe $id $_.vals) })
        $row.found  = (@($hits | ForEach-Object { "$(Format-Values $id $_.vals) in '$($_.policy)'" }) -join '; ')
        $row.result = if ($bad) { $rule.level } else { 'Pass' }
        $rows.Add($row)
    }
    return , $rows.ToArray()
}

function New-RulesFile ([string]$Path, [object[]]$BaselinePolicies) {
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('# My best practices')
    $lines.Add('')
    $lines.Add('Edit the two tables. Delete the rows you do not care about. Keep this file outside the public repo.')
    $lines.Add('')
    $lines.Add('Decision: Keep (must be deployed), Change (deployed, with the setting rows below), Skip (must not be deployed), Add (a policy of your own).')
    $lines.Add('Level: Fail, Warn, or Info. Must be: On, Off, a number, a comparison such as `>= 14`, the name of an option, or `Not set`.')
    $lines.Add('')
    $lines.Add('## Policies')
    $lines.Add('')
    $lines.Add('| Policy | Decision | Reason |')
    $lines.Add('| --- | --- | --- |')
    foreach ($policy in $BaselinePolicies) { $lines.Add("| $($policy.Name.Replace('|', '\|')) | Keep | |") }
    $lines.Add('')
    $lines.Add('## Settings')
    $lines.Add('')
    $lines.Add('One row for each setting where your standard is firm. The rows below are the current OIB values for the first policy, as a pattern.')
    $lines.Add('')
    $lines.Add('| Policy | Setting | Must be | Level | Reason |')
    $lines.Add('| --- | --- | --- | --- | --- |')
    $sample = $BaselinePolicies | Where-Object { $_.Kind -eq 'SettingsCatalog' -and $_.Settings.Count } | Select-Object -First 1
    if ($sample) {
        foreach ($id in @($sample.Settings.Keys | Sort-Object | Select-Object -First 5)) {
            $lines.Add("| $($sample.Name) | $((Get-SettingDisplay $id @($sample.Settings.Keys)).Replace('|', '\|')) | $((Format-Values $id $sample.Settings[$id]).Replace('|', '\|')) | Warn | |")
        }
    }
    Set-Content -LiteralPath $Path -Value $lines -Encoding utf8
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
function Format-Cell ([string]$Text, [int]$Max = 90) {
    if ($null -eq $Text) { return '' }
    $clean = ($Text -replace '\s+', ' ').Replace('|', '\|')
    if ($clean.Length -gt $Max) { $clean = $clean.Substring(0, $Max - 1) + '…' }
    return $clean
}

function ConvertTo-MarkdownReport ($Report) {
    $md = [System.Collections.Generic.List[string]]::new()
    $targetWord = if ($Report.target.type -eq 'GitRef') { 'Other version' } else { 'Target' }

    $md.Add('# OIB audit report')
    $md.Add('')
    $md.Add("- Mode: $($Report.mode)")
    $md.Add("- Baseline: $($Report.baseline.platforms -join ', ') ($($Report.baseline.policyCount) policies, commit $($Report.baseline.commit))")
    $md.Add("- Compared with: $($Report.target.label)")
    $md.Add("- Generated: $($Report.generatedAt)")
    if ($Report.target.type -eq 'Tenant') {
        $counts = @($Report.requests.Keys | Sort-Object | ForEach-Object { "$($Report.requests[$_]) $_" }) -join ', '
        $md.Add("- Requests sent to the tenant: $counts. Requests that change data: 0.")
    }
    $md.Add('')

    if (@($Report.unreadable).Count) {
        $md.Add('## Could not be read')
        $md.Add('')
        $md.Add('These are unknown, not absent. Policies of these kinds are marked Unknown below.')
        $md.Add('')
        foreach ($item in $Report.unreadable) { $md.Add("- $($item['collection']): $($item['reason'])") }
        $md.Add('')
    }

    if ($Report.comparison) {
        $policies = @($Report.comparison.policies)
        $md.Add('## Summary')
        $md.Add('')
        $md.Add('| Result | Policies |')
        $md.Add('| --- | --- |')
        foreach ($group in ($policies | Group-Object { $_.result } | Sort-Object Name)) { $md.Add("| $($group.Name) | $($group.Count) |") }
        $md.Add('')
        $md.Add('Same: found, every setting equal. Different: found, settings differ. OlderVersion: found under an earlier version. Missing: not found. Unknown: not read.')
        $md.Add('')

        $md.Add('## Policies')
        $md.Add('')
        $md.Add("| Baseline policy | Result | $targetWord | Differences |")
        $md.Add('| --- | --- | --- | --- |')
        foreach ($p in $policies) {
            $detail = ''
            if ($p.result -in 'Different', 'OlderVersion') { $detail = "$(@($p.rows).Count) of $($p.settingCount) settings" }
            elseif ($p.coverage) { $detail = "Settings set by other policies: $($p.coverage.sameElsewhere) same, $($p.coverage.differentElsewhere) different, $($p.coverage.notSet) not set" }
            elseif ($p.note) { $detail = $p.note }
            $md.Add("| $(Format-Cell $p.policy 110) | $($p.result) | $(Format-Cell ([string]$p.targetPolicy) 70) | $(Format-Cell $detail 110) |")
        }
        $md.Add('')

        if ($Report.mode -ne 'ReadOnly') {
            $withRows = @($policies | Where-Object { @($_.rows).Count })
            if ($withRows) {
                $md.Add('## Setting differences')
                $md.Add('')
                foreach ($p in $withRows) {
                    $md.Add("### $($p.policy)")
                    $md.Add('')
                    $md.Add("| Setting | Baseline | $targetWord | Result | Where |")
                    $md.Add('| --- | --- | --- | --- | --- |')
                    foreach ($row in $p.rows) {
                        $md.Add("| $(Format-Cell (Get-SettingLabel $row.settingId) 70) | $(Format-Cell (Format-Values $row.settingId $row.baseline) 50) | $(Format-Cell (Format-Values $row.settingId $row.target) 50) | $($row.result) | $(Format-Cell $row.where 60) |")
                    }
                    $md.Add('')
                }
            }
        }

        if (@($Report.comparison.extra).Count) {
            $md.Add("## OIB policies in the target that this baseline version does not have")
            $md.Add('')
            foreach ($e in $Report.comparison.extra) { $md.Add("- $($e.policy): $($e.note)") }
            $md.Add('')
        }
        if ($Report.target.type -ne 'GitRef') {
            $md.Add("Other policies in the target that are not part of OIB: $($Report.comparison.otherPolicyCount). They are not judged.")
            $md.Add('')
        }
    }

    if ($Report.rules) {
        $md.Add('## Best practices')
        $md.Add('')
        $md.Add("Rules file: $($Report.rulesFile)")
        $md.Add('')
        $md.Add('| Result | Rules |')
        $md.Add('| --- | --- |')
        foreach ($group in (@($Report.rules) | Group-Object { $_.result } | Sort-Object Name)) { $md.Add("| $($group.Name) | $($group.Count) |") }
        $md.Add('')
        $md.Add('| Line | Rule | Must be | Found | Result | Reason |')
        $md.Add('| --- | --- | --- | --- | --- | --- |')
        foreach ($r in $Report.rules) {
            $md.Add("| $($r.line) | $(Format-Cell $r.rule 90) | $(Format-Cell $r.expected 30) | $(Format-Cell $r.found 110) | $($r.result) | $(Format-Cell $r.reason 80) |")
        }
        $md.Add('')
    }

    if ($Report.deploy) {
        $md.Add('## Deploy')
        $md.Add('')
        foreach ($line in $Report.deploy) { $md.Add($line) }
        $md.Add('')
    }
    return ($md -join "`n")
}

# ---------------------------------------------------------------------------
# Main. Dot-source the script to load the functions without running this part.
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -eq '.') { return }

$platforms = if ($Platform -eq 'All') { @($PlatformFolders.Keys) } else { @($Platform) }

# The write gate is checked before anything else, and before any network request.
if ($Mode -eq 'Deploy') {
    if (-not $AllowWrite -or -not $ConfirmTenant) {
        Write-Host 'Deploy is off. It needs both -AllowWrite and -ConfirmTenant <the tenant default domain or name>.'
        Write-Host 'Nothing was read and nothing was changed.'
        exit 2
    }
    if ($SnapshotPath -or $CompareRef) {
        Write-Host 'Deploy needs a live tenant. It cannot run against a snapshot or a git ref. Nothing was changed.'
        exit 2
    }
}
if ($SnapshotPath -and $CompareRef) { Write-Host 'Use -SnapshotPath or -CompareRef, not both.'; exit 2 }
if ($Mode -eq 'BestPractices' -and -not $Rules -and -not $NewRulesFile) { Write-Host 'BestPractices mode needs -Rules <file>, or -NewRulesFile <file> to create a starter.'; exit 2 }

Import-SettingNames
$baseline = @(Get-BaselinePolicies $RepoRoot $platforms)
$manifest = Get-BaselineManifest $RepoRoot $platforms
if (-not $baseline) { Write-Host 'No baseline policies were found.'; exit 2 }

if ($NewRulesFile) {
    New-RulesFile $NewRulesFile $baseline
    Write-Host "Starter rules file written: $NewRulesFile ($($baseline.Count) policies)."
    exit 0
}

if ($ListSettings) {
    $listed = @(Find-BaselinePolicies $ListSettings $baseline)
    if (-not $listed) { Write-Host "No baseline policy matches '$ListSettings'."; exit 2 }
    '| Policy | Setting | Must be | Level | Reason |'
    '| --- | --- | --- | --- | --- |'
    foreach ($policy in $listed) {
        foreach ($id in ($policy.Settings.Keys | Sort-Object)) {
            "| $($policy.Name.Replace('|', '\|')) | $((Get-SettingDisplay $id @($policy.Settings.Keys)).Replace('|', '\|')) | $((Format-Values $id $policy.Settings[$id]).Replace('|', '\|')) | Warn | |"
        }
    }
    exit 0
}

# --- Decide what the baseline is compared with ---
$target = $null
$tempFolder = $null
if ($CompareRef) {
    $tempFolder = Export-GitRef $CompareRef
    $target = [ordered]@{ Type = 'GitRef'; Label = "git ref $CompareRef"; Info = [ordered]@{ ref = $CompareRef }; Collections = [ordered]@{}; Unreadable = [System.Collections.Generic.List[object]]::new() }
}
elseif ($SnapshotPath) {
    $target = Read-Snapshot $SnapshotPath
}
elseif ($Mode -in 'ReadOnly', 'Deploy' -or $TenantId -or $env:OIB_TENANT_ID -or $env:OIB_ACCESS_TOKEN) {
    try { [void](Get-OibAccessToken) }
    catch { Write-Host "Sign-in failed: $($_.Exception.Message)"; exit 2 }
    $target = Read-TenantLive
    if ($SaveSnapshot) { $saved = Save-Snapshot $target $SaveSnapshot; Write-Host "Snapshot saved: $saved" }
}
elseif ($Mode -eq 'DiffOnly') {
    Write-Host 'DiffOnly needs something to compare with: sign-in details, -SnapshotPath, or -CompareRef.'
    exit 2
}

if ($RefreshSettingNames) {
    $count = Update-SettingNames $baseline
    Write-Host "Setting names written: $count ($SettingNamesPath)."
    Import-SettingNames
}

if ($target -and $target.Type -eq 'GitRef') {
    $targetPolicies  = @(Get-BaselinePolicies $tempFolder $platforms)
    $unreadableKinds = @()
    Remove-Item -LiteralPath $tempFolder -Recurse -Force
}
elseif ($target) {
    $targetPolicies  = Get-TargetPolicies $target
    $unreadableKinds = @(Get-UnreadableKinds $target)
}
else {
    $targetPolicies  = @()
    $unreadableKinds = @()
}

$commit = (git -C $RepoRoot rev-parse --short HEAD 2>$null)
$report = [ordered]@{
    tool        = 'Invoke-OIBAudit'
    version     = $ToolVersion
    mode        = $Mode
    generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC'
    baseline    = [ordered]@{ platforms = $platforms; policyCount = $baseline.Count; commit = [string]$commit; oibVersions = $manifest.Versions }
    target      = [ordered]@{ type = if ($target) { $target.Type } else { 'None' }; label = if ($target) { $target.Label } else { 'nothing (the baseline is checked against your rules)' }; info = if ($target) { $target.Info } else { @{} } }
    requests    = $script:OibRequestCount
    unreadable  = @(if ($target) { $target.Unreadable })
    comparison  = $null
    rulesFile   = $null
    rules       = $null
    deploy      = $null
}

if ($target) {
    $report.comparison = Compare-PolicySets $baseline $targetPolicies $manifest $unreadableKinds
}

if ($Mode -eq 'BestPractices') {
    $ruleSet = Read-RulesFile $Rules
    $report.rulesFile = $Rules
    $report.rules = Invoke-BestPractices $ruleSet $baseline $targetPolicies $manifest ([bool]$target) $unreadableKinds
    # In this mode the report is about your rules. The raw baseline comparison is left out.
    $report.comparison = $null
}

$exitCode = 0
if ($Mode -eq 'Deploy') {
    $names = @($target.Info['defaultDomain'], $target.Info['displayName']) | Where-Object { $_ }
    if (-not ($names | Where-Object { $_ -eq $ConfirmTenant })) {
        Write-Host "The tenant that was read is '$($names -join "' / '")'. -ConfirmTenant '$ConfirmTenant' does not equal it. Nothing was changed."
        exit 2
    }
    $missing = @($report.comparison.policies | Where-Object { $_.result -eq 'Missing' })
    $plan = [System.Collections.Generic.List[string]]::new()
    $plan.Add("Both halves of the write gate are satisfied for $($target.Label).")
    $plan.Add("A deployment would create these $($missing.Count) policies, unassigned. It would not edit or delete anything:")
    $plan.Add('')
    foreach ($p in $missing) { $plan.Add("- $($p.policy)") }
    $plan.Add('')
    $plan.Add("Version $ToolVersion stops here. The write step is not implemented. Nothing was changed.")
    $report.deploy = $plan.ToArray()
    $exitCode = 3
}
elseif ($Mode -eq 'BestPractices') {
    if (@($report.rules | Where-Object { $_.result -in 'Fail', 'NotUnderstood' })) { $exitCode = 1 }
}
elseif ($report.comparison) {
    if (@($report.comparison.policies | Where-Object { $_.result -ne 'Same' })) { $exitCode = 1 }
}

$markdown = ConvertTo-MarkdownReport $report
Write-Output $markdown
if ($OutFile) { Set-Content -LiteralPath $OutFile -Value $markdown -Encoding utf8 }
if ($OutJson) { $report | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutJson -Encoding utf8 }
exit $exitCode
