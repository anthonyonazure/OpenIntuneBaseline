<#
.SYNOPSIS
    Creates and configures a Group Policy Object (GPO) based on settings from an Intune JSON policy.
.DESCRIPTION
    This script reads an Intune JSON policy export for 'Win - OIB - WUfB Drivers - Ring 3 - Production - v3.0',
    extracts relevant Driver Update Profile settings, and creates a corresponding GPO.
    It attempts to map these settings to GPO registry values where feasible using Set-GPRegistryValue.
    Intune's Driver Update Profiles offer granular ring-based management (specific approval types,
    driver-only deferrals) that often do not have direct one-to-one GPO registry key equivalents
    manageable by Set-GPRegistryValue for simple 'Policies' key modifications.
    This script will highlight these limitations by primarily setting a baseline for driver inclusion
    and issuing warnings for the Intune-specific behaviors.
    This script is self-contained and uses the provided JSON content directly.
.NOTES
    Source Policy Name: Win - OIB - WUfB Drivers - Ring 3 - Production - v3.0
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

# --- Initialize Counters ---
# $expectedIntuneSettings: Number of Intune settings this script is programmed to interpret from this specific JSON.
# For this Driver Update Profile, we are looking for:
# 1. approvalType
# 2. deploymentDeferralInDays
# (A common GPO setting for driver inclusion will also be applied, but not counted in $expectedIntuneSettings as it's a baseline application)
$expectedIntuneSettings = 2 
$configuredGpoSettings = 0 # Counts successfully configured GPO registry values.

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
$gpoName = $policyObject.displayName
$gpoDescription = $policyObject.description
if ([string]::IsNullOrEmpty($gpoDescription)) {
    $gpoDescription = "GPO created from Intune policy '$gpoName' (Driver Update Profile Ring 3 Production - Automated Script)"
}

Write-Host "Preparing to create GPO: '$gpoName'"
Write-Host "Description: '$gpoDescription'"

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
    
    Write-Host ""
    Write-Host "--- Processing Driver Update Profile Settings from Intune JSON (Ring 3 - Production) ---"
    $regKeyWindowsUpdate = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

    # This JSON type (@odata.type: #microsoft.graph.windowsDriverUpdateProfile) has direct properties like 'approvalType' and 'deploymentDeferralInDays'.
    # It does not use a generic 'settings' array or 'settingDefinitionId' for these core behaviors.
    # There is also no 'settingCount' property in this specific JSON structure for these profile-level settings.

    # Common Prerequisite: Ensure drivers are scanned for by Windows Update for Business.
    # Intune Setting: (Implied) Drivers should be managed.
    # GPO Path: Computer Configuration > Administrative Templates > Windows Components > Windows Update > Do not include drivers with Windows Updates
    # Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ExcludeWUDriversInQualityUpdate (DWORD)
    # Value: 0 to INCLUDE drivers (i.e., policy is Disabled), 1 to EXCLUDE.
    Write-Host "Applying prerequisite GPO Setting: Ensuring drivers are included in WUfB scans."
    Write-Host "GPO Setting Detail: $regKeyWindowsUpdate\ExcludeWUDriversInQualityUpdate = 0"
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $regKeyWindowsUpdate -ValueName "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 0 -ErrorAction Stop
    $configuredGpoSettings++

    # 1. approvalType
    # Intune Setting: approvalType (Value from JSON: $($policyObject.approvalType))
    # GPO Equivalent: No direct GPO registry key for ring-based "automatic" or "manual" approval of *all drivers in a ring*.
    if ($policyObject.PSObject.Properties.Contains('approvalType')) {
        Write-Warning "Interpreted Intune setting: approvalType = '$($policyObject.approvalType)'."
        Write-Warning "GPO Mapping Limitation: Intune's Driver Update Profile 'approvalType' ('$($policyObject.approvalType)') provides granular control. Standard GPOs manage driver inclusion/exclusion broadly. Specific 'automatic' or 'manual' approval for driver rings as in Intune is not directly translatable to a single Set-GPRegistryValue command. The setting 'ExcludeWUDriversInQualityUpdate = 0' (applied by this script) ensures drivers are offered by WU; default WUfB behavior then applies if not overridden by other policies."
    } else {
        Write-Warning "Intune setting 'approvalType' not found in JSON. Expected for this policy type."
    }

    # 2. deploymentDeferralInDays
    # Intune Setting: deploymentDeferralInDays (Value from JSON: $($policyObject.deploymentDeferralInDays))
    # GPO Equivalent: No direct GPO registry key for driver-specific deferral days. WUfB offers deferrals for Quality or Feature updates.
    if ($policyObject.PSObject.Properties.Contains('deploymentDeferralInDays')) {
        Write-Warning "Interpreted Intune setting: deploymentDeferralInDays = '$($policyObject.deploymentDeferralInDays)' days."
        Write-Warning "GPO Mapping Limitation: Intune's 'deploymentDeferralInDays' for drivers (set to '$($policyObject.deploymentDeferralInDays)' days in this Production ring policy) is specific. Standard GPOs allow deferral of broad 'Quality Updates' or 'Feature Updates'. A separate, distinct deferral period solely for drivers via a single 'Set-GPRegistryValue' key is not available. If drivers are part of Quality Updates, the Quality Update deferral policy would apply (this policy is not configured by this script and would need separate GPO management)."
    } else {
        Write-Warning "Intune setting 'deploymentDeferralInDays' not found in JSON. Expected for this policy type."
    }
    
    Write-Host ""
    Write-Host "--- Additional Notes on Driver Update Profile Mapping ---"
    Write-Host "The primary GPO action taken by this script is to ensure drivers are included in Windows Update scans by setting 'ExcludeWUDriversInQualityUpdate' to 0."
    Write-Host "The more granular Intune concepts of driver 'rings', specific 'approvalType' for rings, and driver-only 'deferral periods' do not have direct one-to-one mappings to GPO registry keys modifiable by Set-GPRegistryValue."
    Write-Host "For advanced WUfB configurations, including driver management, consult the full set of GPOs under 'Computer Configuration > Administrative Templates > Windows Components > Windows Update'."

} catch {
    Write-Error "An error occurred during GPO creation or configuration: $($_.Exception.Message)"
}

# --- Final Verification ---
Write-Host ""
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Configuration Script Summary"
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Name: $gpoName"
Write-Host "Source Intune Policy Name: $($policyObject.displayName) (Type: WindowsDriverUpdateProfile)"
Write-Host ""
Write-Host "Expected Intune settings to interpret for this policy type: $expectedIntuneSettings (approvalType, deploymentDeferralInDays)"
Write-Host "Total Set-GPRegistryValue commands successfully executed in this script: $configuredGpoSettings"
Write-Host ""
Write-Host "Discrepancy Explanation:"
Write-Host "The 'expectedIntuneSettings' counts key properties from the Driver Update Profile JSON."
Write-Host "The 'configuredGpoSettings' counts actual Set-GPRegistryValue commands. For Driver Update Profiles:"
Write-Host "  - One command is executed to ensure drivers are included in Windows Updates (`ExcludeWUDriversInQualityUpdate = 0`)."
Write-Host "  - Specific Intune concepts like ring-based 'approvalType' ('$($policyObject.approvalType)') and driver-only 'deploymentDeferralInDays' ('$($policyObject.deploymentDeferralInDays)' days) do not map to distinct Set-GPRegistryValue commands and are handled with warnings."
Write-Host "This script does not use a 'settingCount' field from the JSON root, as this specific Intune object type does not typically include it for these high-level profile settings."
Write-Host "--------------------------------------------------------------------"
Write-Host "Script finished."
# Example of how to run:
# $jsonFilePath = "WINDOWS/IntuneManagement/DriverUpdateProfiles/Win - OIB - WUfB Drivers - Ring 3 - Production - v3.0.json"
# $fileContent = Get-Content -Path $jsonFilePath -Raw | Out-String
# # Ensure $fileContent is correctly passed as a single string if running manually, e.g. using $(Get-Content ... -Raw)
# .\Win-OIB-WUfB-Drivers-Ring-3-Production-v3.0.ps1 -JsonContentIn $fileContent
