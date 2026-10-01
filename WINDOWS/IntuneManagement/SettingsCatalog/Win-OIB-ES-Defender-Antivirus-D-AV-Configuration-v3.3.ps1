# Script to create GPO from Intune Settings Catalog JSON (Defender AV Configuration)

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

# Helper function to parse simple choice/boolean setting values (e.g., _0, _1, _enabled, _disabled)
function Parse-SimpleChoiceValue {
    param (
        [string]$ValueString, # e.g., "device_vendor_msft_policy_config_defender_allowarchivescanning_1"
        [string]$SettingNameForWarning = "Setting"
    )
    if ([string]::IsNullOrEmpty($ValueString)) {
        Write-Warning "$SettingNameForWarning: ValueString is null or empty."
        return $null 
    }
    $parts = $ValueString.Split('_')
    $lastPart = $parts[-1]

    switch ($lastPart) {
        "0"       { return 0 }
        "disabled"{ return 0 }
        "1"       { return 1 }
        "enabled" { return 1 }
        # Add other common mappings if needed
        default {
            # Try to convert to integer if it's purely numeric (e.g., for SpynetReporting, CloudBlockLevel)
            if ($lastPart -match "^\d+$") {
                return [int]$lastPart
            }
            Write-Warning "$SettingNameForWarning: Unknown choice value suffix '$lastPart' in '$ValueString'. Returning null."
            return $null
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
$gpoName = $policyObject.name 
$gpoDescription = $policyObject.description
$expectedSettingCount = $policyObject.settingCount

if ([string]::IsNullOrEmpty($gpoDescription)) {
    $gpoDescription = "GPO created from Intune Settings Catalog policy '$gpoName' (Defender AV Config - Automated Script)"
}

Write-Host "Preparing to create GPO: '$gpoName'"
Write-Host "Description: '$gpoDescription'"
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

# --- Registry Settings Mapping for Defender Antivirus ---
$defenderKeyBase = "SOFTWARE\Policies\Microsoft\Windows Defender"

# Process settings from the JSON
if ($policyObject.settings) {
    foreach ($settingEntry in $policyObject.settings) {
        $interpretedSettingsInPayload++
        $definitionId = $settingEntry.settingInstance.settingDefinitionId
        $regKey = $null
        $regValueName = $null
        $regValue = $null
        $regType = "DWord" # Most Defender settings are DWORD

        # Determine value based on instance type
        $instanceValue = $null
        if ($settingEntry.settingInstance.'@odata.type' -eq "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance") {
            $instanceValue = $settingEntry.settingInstance.choiceSettingValue.value
        } elseif ($settingEntry.settingInstance.'@odata.type' -eq "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance") {
            $instanceValue = $settingEntry.settingInstance.simpleSettingValue.value # This could be int, bool, or string
        } else {
            Write-Warning "Setting '$definitionId' has an unhandled instance type: $($settingEntry.settingInstance.'@odata.type'). Skipping."
            continue
        }

        # Switch on Definition ID to map to registry values
        switch -Wildcard ($definitionId) {
            "*defender_allowarchivescanning" {
                $regKey = "$defenderKeyBase\Scan"
                $regValueName = "DisableArchiveScanning"
                $parsedVal = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
                if ($parsedVal -eq 1) { $regValue = 0 } elseif($parsedVal -eq 0) { $regValue = 1 } # Inverse logic
            }
            "*defender_allowbehaviormonitoring" {
                $regKey = "$defenderKeyBase\Real-Time Protection"
                $regValueName = "DisableBehaviorMonitoring"
                $parsedVal = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
                if ($parsedVal -eq 1) { $regValue = 0 } elseif($parsedVal -eq 0) { $regValue = 1 } # Inverse logic
            }
            "*defender_allowcloudprotection" {
                $regKey = "$defenderKeyBase\Spynet"
                $regValueName = "SpynetReporting" # MAPS
                $parsedVal = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
                # 1 = Basic, 2 = Advanced. Intune's "Allow" typically means Advanced.
                if ($parsedVal -eq 1) { $regValue = 2 } elseif($parsedVal -eq 0) { $regValue = 0 } 
            }
            "*defender_allowemailscanning" {
                $regKey = "$defenderKeyBase\Scan"
                $regValueName = "DisableEmailScanning"
                $parsedVal = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
                if ($parsedVal -eq 1) { $regValue = 0 } elseif($parsedVal -eq 0) { $regValue = 1 } # Inverse logic
            }
            "*defender_allowfullscanremovabledrivescanning" {
                $regKey = "$defenderKeyBase\Scan"
                $regValueName = "DisableRemovableDriveScanning"
                $parsedVal = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
                if ($parsedVal -eq 1) { $regValue = 0 } elseif($parsedVal -eq 0) { $regValue = 1 } # Inverse logic
            }
            "*defender_allowioavprotection" { # Scan all downloaded files and attachments
                $regKey = "$defenderKeyBase\Real-Time Protection"
                $regValueName = "DisableIOAVProtection"
                $parsedVal = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
                if ($parsedVal -eq 1) { $regValue = 0 } elseif($parsedVal -eq 0) { $regValue = 1 } # Inverse logic
            }
            "*defender_allowrealtimemonitoring" {
                $regKey = "$defenderKeyBase\Real-Time Protection"
                $regValueName = "DisableRealtimeMonitoring"
                $parsedVal = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
                if ($parsedVal -eq 1) { $regValue = 0 } elseif($parsedVal -eq 0) { $regValue = 1 } # Inverse logic
            }
            "*defender_allowscanningnetworkfiles" {
                $regKey = "$defenderKeyBase\Scan"
                $regValueName = "DisableScanningNetworkFiles"
                $parsedVal = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
                if ($parsedVal -eq 1) { $regValue = 0 } elseif($parsedVal -eq 0) { $regValue = 1 } # Inverse logic
            }
            "*defender_allowscriptscanning" {
                $regKey = "$defenderKeyBase\Scan" # Note: Different from ASR script scanning. This is for AMSI.
                $regValueName = "DisableScriptScanning" 
                $parsedVal = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
                if ($parsedVal -eq 1) { $regValue = 0 } elseif($parsedVal -eq 0) { $regValue = 1 } # Inverse logic
            }
            "*defender_allowuseruiaccess" {
                $regKey = "$defenderKeyBase"
                $regValueName = "DisableUserUIAccess"
                $parsedVal = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
                if ($parsedVal -eq 1) { $regValue = 0 } elseif($parsedVal -eq 0) { $regValue = 1 } # Inverse logic
            }
            "*defender_avgcpuloadfactor" {
                $regKey = "$defenderKeyBase\Scan"
                $regValueName = "AvgCPULoadFactor"
                $regValue = [int]$instanceValue # Directly use the integer value
            }
            "*defender_checkforsignaturesbeforerunningscan" {
                $regKey = "$defenderKeyBase\Scan"
                $regValueName = "CheckForSignaturesBeforeRunningScan"
                $regValue = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
            }
            "*defender_cloudblocklevel" {
                $regKey = "$defenderKeyBase\Spynet"
                $regValueName = "CloudBlockLevel"
                # Values: 1 (Default), 2 (Moderate), 4 (High), 6 (High+), 8 (Zero Tolerance)
                # Intune suffixes: _0 (Default), _1 (Moderate), _2 (High), _3 (High+), _4 (Zero Tolerance)
                $statePart = $instanceValue.Split('_')[-1]
                $map = @{ "0"=1; "1"=2; "2"=4; "3"=6; "4"=8 }
                if ($map.ContainsKey($statePart)) { $regValue = $map[$statePart] }
                else { Write-Warning "Unknown CloudBlockLevel state '$statePart'. Skipping."; $regValue = $null }
            }
            "*defender_cloudextendedtimeout" {
                $regKey = "$defenderKeyBase\Spynet"
                $regValueName = "CloudExtendedTimeout"
                $regValue = [int]$instanceValue # Value in seconds
            }
            "*defender_disablecatchupfullscan" {
                $regKey = "$defenderKeyBase\Scan"
                $regValueName = "DisableCatchupFullScan"
                $regValue = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId # 1 for true (disable), 0 for false (enable)
            }
            "*defender_disablecatchupquickscan" {
                $regKey = "$defenderKeyBase\Scan"
                $regValueName = "DisableCatchupQuickScan"
                $regValue = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId # 1 for true (disable), 0 for false (enable)
            }
            "*defender_enablelowcpupriority" {
                $regKey = "$defenderKeyBase\Scan"
                $regValueName = "EnableLowCPUPriority"
                $regValue = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId # 1 for true (enable)
            }
             "*defender_meteredconnectionupdates" {
                $regKey = "$defenderKeyBase\Signature Updates"
                $regValueName = "MeteredConnectionUpdates" # Allow updates over metered connections
                $regValue = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId # 1 for true (allow)
            }
            "*defender_puaprotection" {
                $regKey = "$defenderKeyBase\MpEngine"
                $regValueName = "MpEnablePus" # Potentially Unwanted Application Protection
                # Suffixes: _0 (Off), _1 (On/Block), _2 (Audit)
                $regValue = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
            }
            "*defender_realtimescandirection" {
                $regKey = "$defenderKeyBase\Real-Time Protection"
                $regValueName = "RealTimeScanDirection"
                # Suffixes: _0 (Both), _1 (Incoming), _2 (Outgoing)
                $regValue = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
            }
            "*defender_schedulequickscantime" {
                $regKey = "$defenderKeyBase\Scan"
                $regValueName = "ScheduleQuickScanTime"
                $regValue = [int]$instanceValue # Minutes from midnight
            }
            "*defender_schedulescantime" { # Daily scan time
                $regKey = "$defenderKeyBase\Scan"
                $regValueName = "ScheduleScanTime"
                $regValue = [int]$instanceValue # Minutes from midnight
            }
            "*defender_scanscheduleday" {
                $regKey = "$defenderKeyBase\Scan"
                $regValueName = "ScheduleDay"
                # Suffixes: _0 (Everyday), _1-7 (Day of week), _8 (Never)
                $regValue = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
            }
            "*defender_signatureupdateinterval" {
                $regKey = "$defenderKeyBase\Signature Updates"
                $regValueName = "SignatureUpdateInterval"
                $regValue = [int]$instanceValue # Hours
            }
            "*defender_submitsamplesconsent" {
                $regKey = "$defenderKeyBase\Spynet"
                $regValueName = "SubmitSamplesConsent"
                # Suffixes: _0 (Always Prompt), _1 (Send Safe), _2 (Never), _3 (Send All)
                $regValue = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId
            }
            "*defender_configuration_disablelocaladminmerge" {
                 $regKey = "$defenderKeyBase"
                 $regValueName = "DisableLocalAdminMerge"
                 $regValue = Parse-SimpleChoiceValue -ValueString $instanceValue -SettingNameForWarning $definitionId # 1 to disable merge (GPO wins)
            }
            # Settings for exclusions (Paths, Processes, Extensions) are more complex.
            # They usually involve creating multiple registry values (one per exclusion) under a specific key,
            # or a REG_MULTI_SZ. Set-GPRegistryValue is not ideal for these dynamic list-based settings.
            # Example: device_vendor_msft_policy_config_defender_excludedpaths (and similar for processes/extensions)
            "*defender_excludedpaths" { Write-Warning "Setting '$definitionId' (Path Exclusions) is complex and not directly translated by this script using Set-GPRegistryValue. Manual GPO configuration for exclusions is recommended."; $regValue = $null }
            "*defender_excludedprocesses" { Write-Warning "Setting '$definitionId' (Process Exclusions) is complex and not directly translated by this script using Set-GPRegistryValue. Manual GPO configuration for exclusions is recommended."; $regValue = $null }
            "*defender_excludedextensions" { Write-Warning "Setting '$definitionId' (Extension Exclusions) is complex and not directly translated by this script using Set-GPRegistryValue. Manual GPO configuration for exclusions is recommended."; $regValue = $null }
            
            default {
                Write-Warning "Unmapped settingDefinitionId '$definitionId' with value '$instanceValue'. Skipping."
                $regValue = $null # Ensure it's skipped
            }
        }

        if ($regKey -and $regValueName -and $regValue -ne $null) {
            try {
                Write-Host "Applying: $regKey\[$regValueName] = $regValue (Type: $regType)"
                Set-GPRegistryValue -Name $gpoName -Key $regKey -ValueName $regValueName -Type $regType -Value $regValue -ErrorAction Stop
                $setGPRegistryValueCommandsExecuted++
            } catch {
                Write-Warning "Failed to set registry value for $definitionId ($regKey\[$regValueName]): $($_.Exception.Message)"
            }
        } elseif ($regKey -and $regValueName -and $regValue -eq $null -and $definitionId -notmatch "excludedpaths|excludedprocesses|excludedextensions") { # Only show this warning if not an exclusion
             Write-Warning "Value for mapped setting $definitionId ($regKey\[$regValueName]) resolved to null or was invalid. Skipping."
        }
    }
} else {
    Write-Warning "JSON does not contain a 'settings' array as expected for a Settings Catalog policy."
}

# --- Summary ---
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Configuration Summary for '$gpoName'"
Write-Host "--------------------------------------------------------------------"
Write-Host "Source JSON: Settings Catalog (Defender AV Configuration)"
Write-Host "GPO Name: $gpoName"
Write-Host ""
Write-Host "Expected settingCount from JSON root: $expectedSettingCount"
Write-Host "Number of top-level setting entries interpreted from JSON 'settings' array: $interpretedSettingsInPayload"
Write-Host "Total Set-GPRegistryValue commands successfully executed: $setGPRegistryValueCommandsExecuted"
Write-Host ""
Write-Host "Discrepancy Explanation (if any):"
Write-Host "The 'expectedSettingCount' from the JSON root should ideally match 'interpretedSettingsInPayload'."
Write-Host "The 'Set-GPRegistryValue commands executed' might be lower than 'interpretedSettingsInPayload' if:"
Write-Host "  1. Some settings in the JSON are not mapped in this script (unmapped settingDefinitionId)."
Write-Host "  2. Some settings (like exclusion lists) are intentionally skipped due to complexity with Set-GPRegistryValue."
Write-Host "  3. A setting's value could not be parsed correctly."
Write-Host "Review any warnings above for details on skipped or unmapped settings."
Write-Host "--------------------------------------------------------------------"
Write-Host "Script finished."
# Example of how to run:
# $jsonFilePath = "path\to\Win - OIB - ES - Defender Antivirus - D - AV Configuration - v3.3.json"
# $fileContent = Get-Content -Path $jsonFilePath -Raw
# .\ThisScriptFileName.ps1 -JsonContentIn $fileContent
