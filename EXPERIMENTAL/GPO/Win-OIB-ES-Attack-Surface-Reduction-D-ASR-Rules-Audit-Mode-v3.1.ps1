<#
.SYNOPSIS
    Creates and configures a Group Policy Object (GPO) based on settings from an Intune JSON policy.
.DESCRIPTION
    This script reads an Intune JSON policy export for 'Win - OIB - ES - Attack Surface Reduction - D - ASR Rules (Audit Mode) - v3.1',
    extracts relevant Attack Surface Reduction (ASR) rules and Controlled Folder Access (CFA) settings, 
    and creates a corresponding GPO with these settings applied as registry values.
    This script is self-contained and uses the provided JSON content directly.
.NOTES
    Source Policy Name: Win - OIB - ES - Attack Surface Reduction - D - ASR Rules (Audit Mode) - v3.1
    Version: 1.1
    Author: AI Agent
#>
param (
    [string]$JsonContentIn
)

# Strict error handling
$ErrorActionPreference = 'Stop'

# Helper function to clean the JSON content (UTF-16 BOM and null characters)
function Clean-JsonContent {
    param ([string]$RawContent)
    $cleaned = $RawContent
    if ($cleaned.StartsWith("ÿþ")) {
        $cleaned = $cleaned.Substring(2)
    }
    $cleaned = $cleaned.Replace([char]0, "")
    return $cleaned
}

# Helper function to map Intune ASR/CFA state string to numeric value
function Get-DefenderRuleStateValue {
    param (
        [string]$StateString, 
        [string]$SettingNameForWarning = "Setting"
    )
    if ([string]::IsNullOrEmpty($StateString)) {
        Write-Warning "$SettingNameForWarning: StateString is null or empty."
        return $null 
    }
    # Examples: 
    # ASR: "..._blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem_audit" -> audit -> 2
    # CFA: "..._enablecontrolledfolderaccess_2" -> 2 -> 2
    # CFA: "..._enablecontrolledfolderaccess_enable" -> enable -> 1
    $statePart = $StateString.Split('_')[-1]
    
    switch ($statePart) {
        "disable"   { return 0 } # Off / Disabled
        "0"         { return 0 }
        "enable"    { return 1 } # On / Block / Enabled
        "block"     { return 1 }
        "1"         { return 1 }
        "audit"     { return 2 } # Audit
        "auditmode" { return 2 } 
        "2"         { return 2 }
        "warn"      { return 6 } # Warn
        "6"         { return 6 }
        default { 
            Write-Warning "$SettingNameForWarning: Unknown state suffix '$statePart' in '$StateString'. Defaulting to 0 (Off/Disabled)."
            return 0 
        }
    }
}

# --- Initialize Counters ---
$expectedIntuneSettings = 0 # Will be set from JSON's root settingCount
$configuredGpoSettings = 0  # Counts successfully configured GPO registry values.

# --- Parse JSON ---
$cleanedJson = Clean-JsonContent -RawContent $JsonContentIn
try {
    $policyObject = $cleanedJson | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Error "Failed to parse JSON content. Error: $($_.Exception.Message)"
    Write-Error "Cleaned JSON content (first 500 chars for debugging): $($cleanedJson.Substring(0, [System.Math]::Min($cleanedJson.Length, 500)))"
    exit 1 
}

# --- Extract GPO Information ---
$gpoName = $policyObject.name # Settings Catalog uses 'name'
$gpoDescription = $policyObject.description
$expectedIntuneSettings = $policyObject.settingCount # Get count from JSON root

if ([string]::IsNullOrEmpty($gpoDescription)) {
    $gpoDescription = "GPO created from Intune policy '$gpoName' (ASR Audit Mode - Automated Script)"
}

Write-Host "Preparing to create GPO: '$gpoName'"
Write-Host "Description: '$gpoDescription'"
Write-Host "Expected settingCount from JSON root: $expectedIntuneSettings"

# --- Main GPO Configuration ---
try {
    Import-Module GroupPolicy -ErrorAction Stop 

    $existingGpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Warning "GPO named '$gpoName' already exists. Script will not create a new one or modify the existing one. Exiting."
        exit 1 
    }

    $gpo = New-Gpo -Name $gpoName -Comment $gpoDescription
    Write-Host "Successfully created GPO: '$($gpo.DisplayName)' (ID: $($gpo.Id))"

    # Define base registry paths
    $asrRulesRegPath = "SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
    $cfaRegPath = "SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"

    # ASR Rule GUID Mappings (from settingDefinitionId suffix to GUID)
    # Suffix is derived by removing "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_"
    $asrRuleGuidMap = @{
        "blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem" = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"
        "blockexecutionofpotentiallyobfuscatedscripts"                       = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"
        "blockwin32apicallsfromofficemacros"                                 = "92E97FA1-2EDF-4476-BD85-E8ED15C39C72"
        "blockofficecommunicationappfromcreatingchildprocesses"              = "26190899-1602-49E8-8B27-EB1D0A1CE869"
        "blockadoberReaderfromcreatingchildprocesses"                        = "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C"
        "blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion" = "01443614-cd74-433a-b99e-2ecdc07bfc25"
        "blockexecutablecontentfromemailclientandwebmail"                    = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"
        "blockofficeapplicationsfromcreatingexecutablecontent"               = "3B576869-A4EC-4529-8536-B80A7769E899"
        "blockofficeapplicationsfrominjectingcodeintootherprocesses"         = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"
        "blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent"  = "D3E037E1-3EB8-44C8-A917-57927947596D"
        "blockpersistencethroughwmieventsubscription"                        = "E6DB77E5-3DF2-4CF1-B95A-636979351E5E"
        "blockuntrustedunsignedprocessesthatrunfromusb"                      = "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4"
        "blockabuseofexploitedvulnerablesigneddrivers"                       = "563D5009-023D-4A71-A963-27CE659C46FA"
        "blockprocescreationsfrompsexecandwmicommands"                       = "D1E72031-091E-47FA-97C8-1F7C349A6A4B"
        "useadvancedprotectionagainstransomware"                             = "C1DB55AB-C21A-4637-BB3F-A12568109D35"
        # Note: The JSON for Audit mode had more rules than the L2 policy. This map is comprehensive.
    }
    
    Write-Host ""
    Write-Host "--- Processing Settings from Intune JSON ---"

    # Process settings from the JSON
    if ($policyObject.settings) {
        foreach ($settingEntry in $policyObject.settings) {
            $definitionId = $settingEntry.settingInstance.settingDefinitionId
            Write-Host "Interpreting top-level Intune settingDefinitionId: $definitionId"

            if ($definitionId -eq "device_vendor_msft_policy_config_defender_attacksurfacereductionrules") {
                # This is the ASR rules group
                # GPO Path: Computer Configuration > Admin Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction > Configure Attack Surface Reduction rules
                Write-Host "Found ASR Rules group. Processing individual rules..."
                if ($settingEntry.settingInstance.groupSettingCollectionValue) {
                    # The first element of groupSettingCollectionValue contains the list of children rules
                    foreach ($childRule in $settingEntry.settingInstance.groupSettingCollectionValue[0].children) {
                        $ruleFullDefId = $childRule.settingDefinitionId
                        $ruleSuffix = $ruleFullDefId.Replace("device_vendor_msft_policy_config_defender_attacksurfacereductionrules_", "")
                        $ruleGuid = $asrRuleGuidMap[$ruleSuffix]
                        
                        if ($ruleGuid) {
                            $ruleStateValueString = $childRule.choiceSettingValue.value
                            $ruleState = Get-DefenderRuleStateValue -StateString $ruleStateValueString -SettingNameForWarning $ruleSuffix
                            
                            if ($ruleState -ne $null) {
                                Write-Host "  - Applying ASR Rule: $ruleSuffix (GUID: $ruleGuid) to State: $ruleState (Registry Path: $asrRulesRegPath)"
                                Set-GPRegistryValue -Name $gpo.DisplayName -Key $asrRulesRegPath -ValueName $ruleGuid -Type DWord -Value $ruleState -ErrorAction Stop
                                $configuredGpoSettings++
                            } else {
                                Write-Warning "  - Could not determine valid state for ASR rule $ruleSuffix (GUID: $ruleGuid) from value '$ruleStateValueString'. Skipping."
                            }
                        } else {
                            Write-Warning "  - ASR Rule with definition suffix '$ruleSuffix' (from ID '$ruleFullDefId') not found in GUID map. Skipping."
                        }
                    }
                } else {
                     Write-Warning "ASR rule group setting '$definitionId' found but has no 'groupSettingCollectionValue' or it's empty. Skipping ASR rules."
                }
            } elseif ($definitionId -eq "device_vendor_msft_policy_config_defender_enablecontrolledfolderaccess") {
                # This is Controlled Folder Access (CFA)
                # GPO Path: Computer Configuration > Admin Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Controlled Folder Access > Configure Controlled folder access
                Write-Host "Found Controlled Folder Access setting."
                if ($settingEntry.settingInstance.choiceSettingValue) {
                    $cfaStateValueString = $settingEntry.settingInstance.choiceSettingValue.value
                    $cfaState = Get-DefenderRuleStateValue -StateString $cfaStateValueString -SettingNameForWarning "EnableControlledFolderAccess"
                    
                    if ($cfaState -ne $null) {
                        Write-Host "  - Applying Controlled Folder Access (CFA) state: $cfaState (Registry Path: $cfaRegPath)"
                        Set-GPRegistryValue -Name $gpo.DisplayName -Key $cfaRegPath -ValueName "EnableControlledFolderAccess" -Type DWord -Value $cfaState -ErrorAction Stop
                        $configuredGpoSettings++
                    } else {
                        Write-Warning "  - Could not determine valid state for CFA from value '$cfaStateValueString'. Skipping."
                    }
                } else {
                     Write-Warning "CFA setting '$definitionId' found but has no 'choiceSettingValue'. Skipping."
                }
            } else {
                Write-Warning "Unknown/unmapped settingDefinitionId '$definitionId' found in settings array. Skipping."
            }
        }
    } else {
        Write-Warning "JSON does not contain a 'settings' array as expected for a Settings Catalog policy."
    }

} catch {
    Write-Error "An error occurred during GPO creation or configuration: $($_.Exception.Message)"
}

# --- Final Verification ---
Write-Host ""
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Configuration Script Summary"
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Name: $gpoName"
Write-Host "Source Intune Policy Name: $($policyObject.name) (Type: Settings Catalog - ASR)"
Write-Host ""
Write-Host "Expected settingCount from JSON root: $expectedIntuneSettings"
Write-Host "Number of Set-GPRegistryValue commands successfully executed: $configuredGpoSettings"
Write-Host ""
Write-Host "Discrepancy Explanation (if any):"
Write-Host "The 'expectedIntuneSettings' from the JSON root counts the number of top-level configuration items in the Intune policy (e.g., one item for the ASR rules group, one for CFA)."
Write-Host "The 'configuredGpoSettings' counts each individual Set-GPRegistryValue command executed. A single Intune 'group' setting (like the ASR rules group) expands into multiple registry values (one per actual ASR rule configured within that group)."
Write-Host "Therefore, if all ASR rules within the group are mapped and applied, '$configuredGpoSettings' can be higher than '$expectedIntuneSettings'."
Write-Host "If '$configuredGpoSettings' is lower than the total number of individual rules/settings defined in the JSON, it may be due to unmapped settingDefinitionIds or issues parsing specific values."
Write-Host "--------------------------------------------------------------------"
Write-Host "Script finished."
# Example of how to run:
# $jsonFilePath = "WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - ES - Attack Surface Reduction - D - ASR Rules (Audit Mode) - v3.1.json"
# $fileContent = Get-Content -Path $jsonFilePath -Raw | Out-String
# # Ensure $fileContent is correctly passed as a single string if running manually, e.g. using $(Get-Content ... -Raw)
# .\Win-OIB-ES-Attack-Surface-Reduction-D-ASR-Rules-Audit-Mode-v3.1.ps1 -JsonContentIn $fileContent
