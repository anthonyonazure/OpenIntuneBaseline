<#
.SYNOPSIS
    Creates and configures a Group Policy Object (GPO) based on settings from an Intune JSON policy.
.DESCRIPTION
    This script reads an Intune JSON policy export for 'Win - OIB - Compliance - U - Defender for Endpoint - v3.1',
    extracts relevant settings, and creates a corresponding GPO with those settings applied as registry values.
    It focuses on Defender Antivirus related configurations.
    This script is self-contained and uses the provided JSON content directly.
    It is designed to interpret specific fields from the known JSON structure of a Windows 10 Compliance Policy.
.NOTES
    Source Policy Name: Win - OIB - Compliance - U - Defender for Endpoint - v3.1
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
# For this Defender for Endpoint compliance policy, we are looking for:
# 1. defenderEnabled
# 2. rtpEnabled
# 3. signatureOutOfDate
$expectedIntuneSettings = 3 
$configuredGpoSettings = 0 # Counts successfully configured GPO registry values.

# --- Parse JSON ---
$cleanedJson = Clean-JsonContent -RawContent $JsonContentIn
try {
    $policyObject = $cleanedJson | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Error "Failed to parse JSON content. Error: $($_.Exception.Message)"
    Write-Error "Cleaned JSON content (first 500 chars for debugging): $($cleanedJson.Substring(0, [System.Math]::Min($cleanedJson.Length, 500)))"
    exit 1 # Exit if JSON parsing fails
}

# --- Extract GPO Information ---
$gpoName = $policyObject.displayName
$gpoDescription = $policyObject.description
if ([string]::IsNullOrEmpty($gpoDescription)) {
    $gpoDescription = "Policy description from Intune JSON. GPO created from Intune policy '$gpoName' (Defender for Endpoint Compliance - Automated Script)"
}

Write-Host "Preparing to create GPO: '$gpoName'"
Write-Host "Description: '$gpoDescription'"

# --- Main GPO Configuration ---
try {
    Import-Module GroupPolicy -ErrorAction Stop # Ensures GPO cmdlets are available

    # Check if GPO already exists
    $existingGpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Warning "GPO named '$gpoName' already exists. Script will not create a new one or modify the existing one. Exiting."
        exit 1 # Stop script if GPO exists to prevent unintended changes
    }

    $gpo = New-Gpo -Name $gpoName -Comment $gpoDescription
    Write-Host "Successfully created GPO: '$($gpo.DisplayName)' (ID: $($gpo.Id))"

    # Define base registry paths
    $defenderRegPath = "SOFTWARE\Policies\Microsoft\Windows Defender"
    $rtpRegPath = "$defenderRegPath\Real-Time Protection"
    $signatureRegPath = "$defenderRegPath\Signature Updates"
    $scanRegPath = "$defenderRegPath\Scan"

    # Setting 1: defenderEnabled
    # Intune Setting: defenderEnabled (Value from JSON: $($policyObject.defenderEnabled))
    # GPO Path: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Turn off Microsoft Defender Antivirus
    if ($policyObject.PSObject.Properties.Contains('defenderEnabled')) {
        if ($policyObject.defenderEnabled -eq $true) {
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $defenderRegPath -ValueName "DisableAntiSpyware" -Type DWord -Value 0 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for defenderEnabled: $defenderRegPath\DisableAntiSpyware = 0 (Defender Antivirus Enabled)"
        } else {
            Write-Warning "Intune setting 'defenderEnabled' is '$($policyObject.defenderEnabled)'. This script enforces 'true' states for Defender components. 'DisableAntiSpyware' not set to enforce 'false'."
        }
    } else {
        Write-Warning "Intune setting 'defenderEnabled' not found in JSON. Expected for this policy type."
    }

    # Setting 2: rtpEnabled (Real-Time Protection)
    # Intune Setting: rtpEnabled (Value from JSON: $($policyObject.rtpEnabled))
    if ($policyObject.PSObject.Properties.Contains('rtpEnabled')) {
        if ($policyObject.rtpEnabled -eq $true) {
            # GPO Path: Computer Configuration > ... > Microsoft Defender Antivirus > Real-time Protection > Turn off real-time protection
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $rtpRegPath -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 0 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for rtpEnabled (DisableRealtimeMonitoring): $rtpRegPath\DisableRealtimeMonitoring = 0 (Real-Time Monitoring Enabled)"

            # GPO Path: Computer Configuration > ... > Microsoft Defender Antivirus > Real-time Protection > Turn on behavior monitoring
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $rtpRegPath -ValueName "DisableBehaviorMonitoring" -Type DWord -Value 0 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for rtpEnabled (DisableBehaviorMonitoring): $rtpRegPath\DisableBehaviorMonitoring = 0 (Behavior Monitoring Enabled)"
            
            # GPO Path: Computer Configuration > ... > Microsoft Defender Antivirus > Real-time Protection > Scan all downloaded files and attachments
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $rtpRegPath -ValueName "DisableIOAVProtection" -Type DWord -Value 0 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for rtpEnabled (DisableIOAVProtection): $rtpRegPath\DisableIOAVProtection = 0 (Scan All Downloads Enabled)"

            # GPO Path: Computer Configuration > ... > Microsoft Defender Antivirus > Real-time Protection > Monitor file and program activity on your computer
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $rtpRegPath -ValueName "DisableOnAccessProtection" -Type DWord -Value 0 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for rtpEnabled (DisableOnAccessProtection): $rtpRegPath\DisableOnAccessProtection = 0 (On-Access Protection Enabled)"
        } else {
            Write-Warning "Intune setting 'rtpEnabled' is '$($policyObject.rtpEnabled)'. This script enforces 'true' states for RTP components. GPO settings for Real-Time Protection components not applied to enforce 'false'."
        }
    } else {
        Write-Warning "Intune setting 'rtpEnabled' not found in JSON. Expected for this policy type."
    }

    # Setting 3: signatureOutOfDate (True means signatures must NOT be out of date)
    # Intune Setting: signatureOutOfDate (Value from JSON: $($policyObject.signatureOutOfDate))
    if ($policyObject.PSObject.Properties.Contains('signatureOutOfDate')) {
        if ($policyObject.signatureOutOfDate -eq $true) {
            # GPO Path: Computer Configuration > ... > Microsoft Defender Antivirus > Signature Updates > Specify the interval to check for definition updates
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $signatureRegPath -ValueName "SignatureUpdateInterval" -Type DWord -Value 4 -ErrorAction Stop # Example: 4 hours
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for signatureOutOfDate (SignatureUpdateInterval): $signatureRegPath\SignatureUpdateInterval = 4"

            # GPO Path: Computer Configuration > ... > Microsoft Defender Antivirus > Signature Updates > Define the order of sources for downloading definitions
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $signatureRegPath -ValueName "FallbackOrder" -Type String -Value "MicrosoftUpdateServer|InternalDefinitionUpdateServer|MMPC" -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for signatureOutOfDate (FallbackOrder): $signatureRegPath\FallbackOrder = 'MicrosoftUpdateServer|InternalDefinitionUpdateServer|MMPC'"
            
            # GPO Path: Computer Configuration > ... > Microsoft Defender Antivirus > Scan > Check for new virus and spyware definitions before scanning
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $scanRegPath -ValueName "CheckForSignaturesBeforeRunningScan" -Type DWord -Value 1 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for signatureOutOfDate (CheckForSignaturesBeforeRunningScan): $scanRegPath\CheckForSignaturesBeforeRunningScan = 1"
        } else {
            Write-Warning "Intune setting 'signatureOutOfDate' is '$($policyObject.signatureOutOfDate)'. This script enforces the 'true' state (signatures must be up-to-date). GPO settings for signature updates not applied to reflect 'false'."
        }
    } else {
        Write-Warning "Intune setting 'signatureOutOfDate' not found in JSON. Expected for this policy type."
    }
    
    # Note other settings not directly mapped or enforced by this script
    Write-Host ""
    Write-Host "--- Other Intune Compliance Settings Note ---"
    Write-Host "This script primarily focuses on enforcing Defender AV 'enabled' states based on the specific JSON structure for 'Defender for Endpoint' compliance."
    Write-Host "Other settings in a typical Windows 10 Compliance Policy (e.g., passwordRequired, bitLockerEnabled, secureBootEnabled, deviceThreatProtectionEnabled, etc.) are either:"
    Write-Host "  a) Handled by separate dedicated scripts if their JSON files are provided."
    Write-Host "  b) Not directly translatable to simple Defender AV GPO registry keys for enforcement by *this specific* script's focus."
    Write-Host "  c) Not present or not 'true' in this particular JSON file."
    # Example of listing some other common compliance checks and their values from this JSON:
    $otherComplianceChecks = @("passwordRequired", "bitLockerEnabled", "secureBootEnabled", "codeIntegrityEnabled", "deviceThreatProtectionEnabled", "activeFirewallRequired")
    foreach ($check in $otherComplianceChecks) {
        if ($policyObject.PSObject.Properties.Contains($check)) {
            Write-Host "Intune setting '$check' found with value '$($policyObject.$check)'. This script does not apply GPO settings for this specific compliance check based on the current logic."
        }
    }

} catch {
    Write-Error "An error occurred during GPO creation or configuration: $($_.Exception.Message)"
    # Additional error handling or logging can be added here
}

# --- Final Verification ---
Write-Host ""
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Configuration Script Summary"
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Name: $gpoName"
Write-Host "Source Intune Policy Name: $($policyObject.displayName) (Type: Windows 10 Compliance Policy)"
Write-Host ""
Write-Host "Expected Intune settings to interpret for this policy type: $expectedIntuneSettings (defenderEnabled, rtpEnabled, signatureOutOfDate)"
Write-Host "Total Set-GPRegistryValue commands executed in this script: $configuredGpoSettings"
Write-Host ""
Write-Host "Discrepancy Explanation (if any):"
Write-Host "The 'expectedIntuneSettings' counts the number of high-level settings this script logic attempts to map."
Write-Host "The 'configuredGpoSettings' counts each individual Set-GPRegistryValue command executed."
Write-Host "  - If 'defenderEnabled' from JSON is true, 1 GPO setting is configured."
Write-Host "  - If 'rtpEnabled' from JSON is true, 4 GPO settings are configured (for main RTP and 3 sub-features)."
Write-Host "  - If 'signatureOutOfDate' from JSON is true, 3 GPO settings are configured."
Write-Host "If any of these primary Intune settings were 'false', the corresponding GPO settings would not be applied to enforce 'false', potentially leading to a lower '$configuredGpoSettings' count than the maximum possible (8 if all were true)."
Write-Host "This script does not use a 'settingCount' field from the JSON, as Compliance Policies do not have such a field."
Write-Host "--------------------------------------------------------------------"
Write-Host "Script finished."
# Example of how to run:
# $jsonFilePath = "WINDOWS/IntuneManagement/CompliancePolicies/Win - OIB - Compliance - U - Defender for Endpoint - v3.1.json"
# $fileContent = Get-Content -Path $jsonFilePath -Raw | Out-String 
# # Ensure $fileContent is correctly passed as a single string if running manually, e.g. using $(Get-Content ... -Raw)
# .\Win-OIB-Compliance-U-Defender-for-Endpoint-v3.1.ps1 -JsonContentIn $fileContent
