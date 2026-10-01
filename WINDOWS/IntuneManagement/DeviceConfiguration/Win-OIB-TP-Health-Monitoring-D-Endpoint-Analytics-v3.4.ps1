<#
.SYNOPSIS
    Creates and configures a Group Policy Object (GPO) based on settings from an Intune JSON policy.
.DESCRIPTION
    This script reads an Intune JSON policy export for 'Win - OIB - TP - Health Monitoring - D - Endpoint Analytics - v3.4',
    extracts relevant Endpoint Analytics / Windows Health Monitoring settings, and creates a corresponding GPO.
    It attempts to map these settings to GPO registry values where feasible using Set-GPRegistryValue.
    This script is self-contained and uses the provided JSON content directly.
    It is designed to interpret specific fields from the known JSON structure of a WindowsHealthMonitoringConfiguration.
.NOTES
    Source Policy Name: Win - OIB - TP - Health Monitoring - D - Endpoint Analytics - v3.4
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
# For this WindowsHealthMonitoringConfiguration, we are looking for:
# 1. allowDeviceHealthMonitoring
# 2. configDeviceHealthMonitoringScope
# 3. configDeviceHealthMonitoringCustomScope (though often null)
$expectedIntuneSettings = 3 
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
    $gpoDescription = "GPO created from Intune policy '$gpoName' (Endpoint Analytics - Automated Script)"
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

    # Define base registry paths
    $dataCollectionRegPath = "SOFTWARE\Policies\Microsoft\Windows\DataCollection"

    # Setting 1: allowDeviceHealthMonitoring
    # Intune Setting: allowDeviceHealthMonitoring (Value from JSON: $($policyObject.allowDeviceHealthMonitoring))
    if ($policyObject.PSObject.Properties.Contains('allowDeviceHealthMonitoring')) {
        if ($policyObject.allowDeviceHealthMonitoring -eq "enabled") {
            # GPO Path: Computer Configuration > Admin Templates > Windows Components > Data Collection and Preview Builds > Allow device health monitoring
            # Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowDeviceHealthMonitoring (DWORD)
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $dataCollectionRegPath -ValueName "AllowDeviceHealthMonitoring" -Type DWord -Value 1 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for allowDeviceHealthMonitoring: $dataCollectionRegPath\AllowDeviceHealthMonitoring = 1"

            # For Endpoint Analytics to function, commercial data pipeline must also be allowed.
            # GPO Path: Computer Configuration > Admin Templates > Windows Components > Data Collection and Preview Builds > Allow commercial data pipeline
            # Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowCommercialDataPipeline (DWORD)
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $dataCollectionRegPath -ValueName "AllowCommercialDataPipeline" -Type DWord -Value 1 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting (related): $dataCollectionRegPath\AllowCommercialDataPipeline = 1"
            
            # Endpoint Analytics requires at least Basic telemetry.
            # GPO Path: Computer Configuration > Admin Templates > Windows Components > Data Collection and Preview Builds > Allow Telemetry
            # Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry (DWORD) 
            # Values: 0 = Off, 1 = Basic/Required, 2 = Enhanced (deprecated), 3 = Full/Optional
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $dataCollectionRegPath -ValueName "AllowTelemetry" -Type DWord -Value 1 -ErrorAction Stop # Set to 1 for Basic
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting (related): $dataCollectionRegPath\AllowTelemetry = 1 (Basic)"
        } else {
            Write-Warning "Intune setting 'allowDeviceHealthMonitoring' is '$($policyObject.allowDeviceHealthMonitoring)'. This script enforces the 'enabled' state. GPO settings not applied to enforce 'disabled'."
        }
    } else {
        Write-Warning "Intune setting 'allowDeviceHealthMonitoring' not found in JSON. Expected for this policy type."
    }

    # Setting 2: configDeviceHealthMonitoringScope
    # Intune Setting: configDeviceHealthMonitoringScope (Value from JSON: $($policyObject.configDeviceHealthMonitoringScope))
    # GPO Equivalent: The specific scopes (e.g., 'bootPerformance', 'windowsUpdates') don't map one-to-one to easily configurable
    # Set-GPRegistryValue keys beyond the general telemetry enablement above.
    if ($policyObject.PSObject.Properties.Contains('configDeviceHealthMonitoringScope')) {
        $scopeValue = $policyObject.configDeviceHealthMonitoringScope
        Write-Warning "Intune setting 'configDeviceHealthMonitoringScope' is '$scopeValue'."
        Write-Warning "The general GPO settings for enabling device health monitoring and telemetry (AllowDeviceHealthMonitoring, AllowCommercialDataPipeline, AllowTelemetry) have been applied."
        Write-Warning "Specific GPO registry keys for granular Intune scopes like '$scopeValue' via Set-GPRegistryValue are limited. The enabled telemetry level and health monitoring should cover data points for Endpoint Analytics. For more fine-grained control, review dedicated GPO settings for Data Collection and Preview Builds which might not be simple registry flags."
    } else {
        Write-Warning "Intune setting 'configDeviceHealthMonitoringScope' not found in JSON."
    }
    
    # Setting 3: configDeviceHealthMonitoringCustomScope
    # Intune Setting: configDeviceHealthMonitoringCustomScope (Value from JSON: $($policyObject.configDeviceHealthMonitoringCustomScope))
    if ($policyObject.PSObject.Properties.Contains('configDeviceHealthMonitoringCustomScope')) {
        if ($null -ne $policyObject.configDeviceHealthMonitoringCustomScope) {
             Write-Warning "Intune setting 'configDeviceHealthMonitoringCustomScope' has a value: '$($policyObject.configDeviceHealthMonitoringCustomScope)'. Custom scopes are not translated by this script."
        } else {
            Write-Host "Intune setting 'configDeviceHealthMonitoringCustomScope' is null. No action taken."
        }
    } else {
        Write-Warning "Intune setting 'configDeviceHealthMonitoringCustomScope' not found in JSON."
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
Write-Host "Source Intune Policy Name: $($policyObject.displayName) (Type: WindowsHealthMonitoringConfiguration)"
Write-Host ""
Write-Host "Expected Intune settings to interpret for this policy type: $expectedIntuneSettings (allowDeviceHealthMonitoring, configDeviceHealthMonitoringScope, configDeviceHealthMonitoringCustomScope)"
Write-Host "Total Set-GPRegistryValue commands successfully executed in this script: $configuredGpoSettings"
Write-Host ""
Write-Host "Discrepancy Explanation (if any):"
Write-Host "The 'expectedIntuneSettings' counts the number of high-level properties this script logic attempts to map from the specific JSON structure."
Write-Host "The 'configuredGpoSettings' counts each individual Set-GPRegistryValue command."
Write-Host "  - If 'allowDeviceHealthMonitoring' from JSON is 'enabled', 3 GPO settings are configured (AllowDeviceHealthMonitoring, AllowCommercialDataPipeline, AllowTelemetry)."
Write-Host "  - 'configDeviceHealthMonitoringScope' and 'configDeviceHealthMonitoringCustomScope' do not directly translate to distinct Set-GPRegistryValue commands beyond the general enablement and result in warnings."
Write-Host "This script does not use a 'settingCount' field from the JSON root, as this specific Device Configuration type does not have one."
Write-Host "--------------------------------------------------------------------"
Write-Host "Script finished."
# Example of how to run:
# $jsonFilePath = "WINDOWS/IntuneManagement/DeviceConfiguration/Win - OIB - TP - Health Monitoring - D - Endpoint Analytics - v3.4.json"
# $fileContent = Get-Content -Path $jsonFilePath -Raw | Out-String
# # Ensure $fileContent is correctly passed as a single string if running manually, e.g. using $(Get-Content ... -Raw)
# .\Win-OIB-TP-Health-Monitoring-D-Endpoint-Analytics-v3.4.ps1 -JsonContentIn $fileContent
