# Script to create GPO from Intune Settings Catalog JSON (ASR Rules L2 & CFA)

#Requires -Modules GroupPolicy

param (
    [string]$JsonContentIn
)

# Helper function to clean the JSON content
function Clean-JsonContent {
    param ([string]$RawContent)
    $cleaned = $RawContent
    if ($cleaned.StartsWith("ÿþ")) {
        $cleaned = $cleaned.Substring(2)
    }
    $cleaned = $cleaned.Replace([char]0, "")
    return $cleaned
}

# Helper function to map Intune ASR state string to numeric value
function Get-AsrRuleStateValue {
    param ([string]$StateString)
    # Example: device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem_audit
    # Expected suffixes: _disable (0), _enable (1), _audit (2), _warn (6), _block (1)
    $statePart = $StateString.Split('_')[-1]
    switch ($statePart) {
        "disable" { return 0 } # Off
        "enable"  { return 1 } # Block (Intune often uses "enable" for block state for ASR rules)
        "block"   { return 1 } # Block
        "audit"   { return 2 } # Audit
        "warn"    { return 6 } # Warn
        default   { 
            Write-Warning "Unknown ASR state string part: $statePart from full string $StateString. Defaulting to 0 (Off)."
            return 0 
        }
    }
}

# Helper function to map Intune CFA state string to numeric value
function Get-CfaStateValue {
    param ([string]$StateString)
    # Example: device_vendor_msft_policy_config_defender_enablecontrolledfolderaccess_2 (Audit Mode)
    # Suffixes: _0 (Disabled), _1 (Enabled/Block), _2 (Audit)
    # Or "device_vendor_msft_policy_config_defender_enablecontrolledfolderaccess_enable"
    $statePart = $StateString.Split('_')[-1]
    switch ($statePart) {
        "0"         { return 0 } # Disabled
        "disable"   { return 0 } 
        "1"         { return 1 } # Enabled (Block Mode)
        "enable"    { return 1 }
        "block"     { return 1 }
        "2"         { return 2 } # Audit Mode
        "audit"     { return 2 } 
        "auditmode" { return 2 }
        default {
            Write-Warning "Unknown CFA state string part: $statePart from full string $StateString. Defaulting to 0 (Disabled)."
            return 0
        }
    }
}

# Initialize
$setGPRegistryValueCommandsExecuted = 0
$interpretedSettingsInPayload = 0 # Based on the "settings" array entries

# Clean and Parse JSON
$cleanedJson = Clean-JsonContent -RawContent $JsonContentIn
try {
    $policyObject = $cleanedJson | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Error "Failed to parse JSON content. Error: $($_.Exception.Message)"
    Write-Error "Cleaned JSON content (first 500 chars): $($cleanedJson.Substring(0, [System.Math]::Min($cleanedJson.Length, 500)))"
    exit 1
}

# Extract GPO Name, Description, and expected settingCount from root
$gpoName = $policyObject.name # Settings Catalog uses 'name'
$gpoDescription = $policyObject.description # Use the description from JSON
$expectedSettingCount = $policyObject.settingCount # From the root of JSON

if ([string]::IsNullOrEmpty($gpoDescription)) {
    # Fallback if description is empty, though this JSON has a description
    $gpoDescription = "GPO created from Intune Settings Catalog policy '$gpoName' (ASR Rules L2 - Automated Script)"
}

Write-Host "Preparing to create GPO: '$gpoName'"
Write-Host "Description: '$gpoDescription'" # Will include the warning from the JSON
Write-Host "Expected settingCount from JSON root: $expectedSettingCount"

# Create New GPO
try {
    Import-Module GroupPolicy -ErrorAction Stop
    $existingGpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Warning "GPO named '$gpoName' already exists. Script will not create a new one or modify the existing one. Exiting."
        exit 1
    } else {
        $gpo = New-Gpo -Name $gpoName -Comment $gpoDescription -ErrorAction Stop
        Write-Host "Successfully created GPO: '$($gpo.DisplayName)' (ID: $($gpo.Id))"
    }
} catch {
    Write-Error "Failed to create GPO '$gpoName'. Error: $($_.Exception.Message)"
    exit 1
}

# --- Registry Settings Mapping for ASR Rules ---
$asrRulesRegPath = "SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$cfaRegPath = "SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"

# ASR Rule GUID Mappings (from settingDefinitionId suffix to GUID)
$asrRuleGuidMap = @{
    "blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem" = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"
    "blockexecutionofpotentiallyobfuscatedscripts" = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"
    "blockwin32apicallsfromofficemacros" = "92E97FA1-2EDF-4476-BD85-E8ED15C39C72"
    "blockofficecommunicationappfromcreatingchildprocesses" = "26190899-1602-49E8-8B27-EB1D0A1CE869"
    "blockadoberReaderfromcreatingchildprocesses" = "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" # Note: JSON uses "blockadoberReader..."
    "blockexecutablerunningunlessitemeetscriteria" = "01443614-cd74-433a-b99e-2ecdc07bfc25" # Suffix in JSON: blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion
    "blockexecutablecontentfromemailclientandwebmail" = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"
    "blockofficeapplicationsfromcreatingexecutablecontent" = "3B576869-A4EC-4529-8536-B80A7769E899"
    "blockofficeapplicationsfrominjectingcodeintootherprocesses" = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"
    "blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent" = "D3E037E1-3EB8-44C8-A917-57927947596D"
    "blockpersistencethroughwmieventsubscription" = "E6DB77E5-3DF2-4CF1-B95A-636979351E5E"
    "blockuntrustedunsignedprocessesthatrunfromusb" = "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4"
    "blockabuseofexploitedvulnerablesigneddrivers" = "563D5009-023D-4A71-A963-27CE659C46FA"
    "blockprocescreationsfrompsexecandwmicommands" = "D1E72031-091E-47FA-97C8-1F7C349A6A4B"
    "useadvancedprotectionagainstransomware" = "C1DB55AB-C21A-4637-BB3F-A12568109D35" # Suffix: useadvancedprotectionagainstransomware
}

# Process settings from the JSON
if ($policyObject.settings) {
    foreach ($settingEntry in $policyObject.settings) {
        $interpretedSettingsInPayload++ # Counts each top-level entry in the "settings" array
        $definitionId = $settingEntry.settingInstance.settingDefinitionId
        
        if ($definitionId -eq "device_vendor_msft_policy_config_defender_attacksurfacereductionrules") {
            if ($settingEntry.settingInstance.groupSettingCollectionValue) {
                foreach ($asrRuleInstance in $settingEntry.settingInstance.groupSettingCollectionValue) {
                    foreach($childRule in $asrRuleInstance.children){
                        $ruleFullDefId = $childRule.settingDefinitionId
                        # Extract the meaningful part of the rule ID, e.g., "blockexecutionofpotentiallyobfuscatedscripts"
                        $ruleSuffix = $ruleFullDefId.Replace("device_vendor_msft_policy_config_defender_attacksurfacereductionrules_", "")
                        $ruleGuid = $asrRuleGuidMap[$ruleSuffix]
                        
                        if ($ruleGuid) {
                            $ruleStateValueString = $childRule.choiceSettingValue.value
                            $ruleState = Get-AsrRuleStateValue -StateString $ruleStateValueString
                            
                            try {
                                Write-Host "Applying ASR Rule: $ruleSuffix (GUID: $ruleGuid) to State: $ruleState"
                                Set-GPRegistryValue -Name $gpoName -Key $asrRulesRegPath -ValueName $ruleGuid -Type DWord -Value $ruleState -ErrorAction Stop
                                $setGPRegistryValueCommandsExecuted++
                            } catch {
                                Write-Warning "Failed to set registry value for ASR rule $ruleGuid ($ruleSuffix): $($_.Exception.Message)"
                            }
                        } else {
                            Write-Warning "ASR Rule with definition suffix '$ruleSuffix' (from ID '$ruleFullDefId') not found in GUID map. Skipping."
                        }
                    }
                }
            } else {
                 Write-Warning "ASR rule group setting '$definitionId' found but has no 'groupSettingCollectionValue'. Skipping."
            }
        } elseif ($definitionId -eq "device_vendor_msft_policy_config_defender_enablecontrolledfolderaccess") {
            if ($settingEntry.settingInstance.choiceSettingValue) {
                $cfaStateValueString = $settingEntry.settingInstance.choiceSettingValue.value
                $cfaState = Get-CfaStateValue -StateString $cfaStateValueString
                
                try {
                    Write-Host "Applying Controlled Folder Access (CFA) state: $cfaState"
                    Set-GPRegistryValue -Name $gpoName -Key $cfaRegPath -ValueName "EnableControlledFolderAccess" -Type DWord -Value $cfaState -ErrorAction Stop
                    $setGPRegistryValueCommandsExecuted++
                } catch {
                    Write-Warning "Failed to set registry value for Controlled Folder Access: $($_.Exception.Message)"
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

# --- Summary ---
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Configuration Summary for '$gpoName'"
Write-Host "--------------------------------------------------------------------"
Write-Host "Source JSON: Settings Catalog (ASR Rules L2 & CFA)"
Write-Host "GPO Name: $gpoName"
Write-Host ""
Write-Host "Expected settingCount from JSON root: $expectedSettingCount"
Write-Host "Number of top-level setting entries interpreted from JSON 'settings' array: $interpretedSettingsInPayload"
Write-Host "Total Set-GPRegistryValue commands successfully executed: $setGPRegistryValueCommandsExecuted"
Write-Host ""
Write-Host "Discrepancy Explanation (if any):"
Write-Host "The 'expectedSettingCount' from the JSON root refers to the number of top-level setting configurations."
Write-Host "The 'Set-GPRegistryValue commands executed' can be higher if a single JSON setting entry (like the ASR rules group) expands into multiple registry values (one per ASR rule configured)."
Write-Host "If commands executed is lower than interpreted settings or the sum of all sub-settings, it may be due to unmapped/unknown settingDefinitionIds or missing values within the JSON structure."
Write-Host "--------------------------------------------------------------------"
Write-Host "Script finished."
# Example of how to run:
# $jsonFilePath = "path\to\Win - OIB - ES - Attack Surface Reduction - D - ASR Rules (L2) - v3.3.json"
# $fileContent = Get-Content -Path $jsonFilePath -Raw
# .\ThisScriptFileName.ps1 -JsonContentIn $fileContent
