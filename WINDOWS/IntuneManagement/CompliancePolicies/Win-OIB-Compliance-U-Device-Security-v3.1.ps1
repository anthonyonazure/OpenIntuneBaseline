<#
.SYNOPSIS
    Creates and configures a Group Policy Object (GPO) based on settings from an Intune JSON policy.
.DESCRIPTION
    This script reads an Intune JSON policy export for 'Win - OIB - Compliance - U - Device Security - v3.1',
    extracts relevant Device Security settings, and creates a corresponding GPO.
    It attempts to map these settings to GPO registry values where feasible using Set-GPRegistryValue.
    Many Device Security settings are compliance checks (e.g., OS version, TPM presence, AV status)
    and are not directly enforced via simple 'Policies' registry keys by this script; warnings or comments will be issued for these.
    This script is self-contained and uses the provided JSON content directly.
.NOTES
    Source Policy Name: Win - OIB - Compliance - U - Device Security - v3.1
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
# For this Device Security compliance policy, we are looking for:
# osMinimumVersion, osMaximumVersion, tpmRequired, activeFirewallRequired, 
# antivirusRequired, antiSpywareRequired, deviceThreatProtectionEnabled, deviceThreatProtectionRequiredSecurityLevel
$expectedIntuneSettings = 8 
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
    $gpoDescription = "GPO created from Intune policy '$gpoName' (Device Security Compliance - Automated Script)"
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
    $firewallRegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    $defenderRegPath = "SOFTWARE\Policies\Microsoft\Windows Defender"

    # 1. activeFirewallRequired
    # Intune Setting: activeFirewallRequired (Value from JSON: $($policyObject.activeFirewallRequired))
    # GPO Path: Computer Configuration > Admin Templates > Network > Network Connections > Windows Defender Firewall > Domain Profile > Windows Defender Firewall: Protect all network connections
    if ($policyObject.PSObject.Properties.Contains('activeFirewallRequired')) {
        if ($policyObject.activeFirewallRequired -eq $true) {
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $firewallRegPath -ValueName "EnableFirewall" -Type DWord -Value 1 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for activeFirewallRequired: $firewallRegPath\EnableFirewall = 1 (Domain Profile Firewall Enabled)"
        } else {
            Write-Warning "Intune setting 'activeFirewallRequired' is '$($policyObject.activeFirewallRequired)'. No GPO setting applied to disable firewall enforcement."
        }
    } else { Write-Warning "Intune setting 'activeFirewallRequired' not found in JSON."}

    # 2. antivirusRequired and antiSpywareRequired
    # Intune Settings: antivirusRequired (Value: $($policyObject.antivirusRequired)), antiSpywareRequired (Value: $($policyObject.antiSpywareRequired))
    # GPO Path (Example for Defender): Computer Configuration > Admin Templates > Windows Components > Microsoft Defender Antivirus > Turn off Microsoft Defender Antivirus
    # Note: The JSON indicates defenderEnabled: false. This means the policy requires *an* AV/AS solution, not necessarily Defender.
    # As a best-effort GPO enforcement, this script will enable Windows Defender Antivirus if AV/AS is required.
    if (($policyObject.PSObject.Properties.Contains('antivirusRequired') -and $policyObject.antivirusRequired -eq $true) -or `
        ($policyObject.PSObject.Properties.Contains('antiSpywareRequired') -and $policyObject.antiSpywareRequired -eq $true)) {
        
        Write-Warning "Intune requires generic Antivirus/Antispyware. Enforcing this by enabling Windows Defender Antivirus as a baseline."
        Set-GPRegistryValue -Name $gpo.DisplayName -Key $defenderRegPath -ValueName "DisableAntiSpyware" -Type DWord -Value 0 -ErrorAction Stop # 0 means Defender AV is ON
        $configuredGpoSettings++
        Write-Host "Applied GPO Setting for Antivirus/Antispyware requirement: $defenderRegPath\DisableAntiSpyware = 0 (Ensures Defender AV is On)"
    } else {
        Write-Host "Intune settings 'antivirusRequired' ($($policyObject.antivirusRequired)) and 'antiSpywareRequired' ($($policyObject.antiSpywareRequired)) do not necessitate enabling Defender AV via this script."
    }

    # 3. tpmRequired
    # Intune Setting: tpmRequired (Value from JSON: $($policyObject.tpmRequired))
    # GPO Equivalent: None for direct enablement. It's a hardware/firmware prerequisite.
    if ($policyObject.PSObject.Properties.Contains('tpmRequired')) {
        if ($policyObject.tpmRequired -eq $true) {
            Write-Warning "Intune setting 'tpmRequired' is true. TPM is a hardware/firmware prerequisite and must be enabled and configured in BIOS/UEFI. GPO cannot enforce this directly. It is essential for features like BitLocker."
        } else {
            Write-Host "Intune setting 'tpmRequired' is false. No TPM prerequisite noted as required by this policy."
        }
    } else { Write-Warning "Intune setting 'tpmRequired' not found in JSON."}

    # 4. osMinimumVersion / osMaximumVersion
    # Intune Settings: osMinimumVersion (Value: $($policyObject.osMinimumVersion)), osMaximumVersion (Value: $($policyObject.osMaximumVersion))
    # GPO Equivalent: None. These are compliance checks, not GPO enforcement settings.
    if ($policyObject.PSObject.Properties.Contains('osMinimumVersion')) {
        Write-Warning "Intune setting 'osMinimumVersion' is '$($policyObject.osMinimumVersion)'. This is a compliance check and cannot be enforced via GPO registry settings."
    } else { Write-Warning "Intune setting 'osMinimumVersion' not found in JSON."}
    
    if ($policyObject.PSObject.Properties.Contains('osMaximumVersion')) {
        Write-Warning "Intune setting 'osMaximumVersion' is '$($policyObject.osMaximumVersion)'. This is a compliance check and cannot be enforced via GPO registry settings."
    } else { Write-Warning "Intune setting 'osMaximumVersion' not found in JSON."}

    # 5. deviceThreatProtectionEnabled
    # Intune Setting: deviceThreatProtectionEnabled (Value from JSON: $($policyObject.deviceThreatProtectionEnabled))
    # GPO Equivalent: MDE onboarding is typically done via a script or dedicated GPO settings, not a simple toggle.
    if ($policyObject.PSObject.Properties.Contains('deviceThreatProtectionEnabled')) {
        if ($policyObject.deviceThreatProtectionEnabled -eq $true) {
            Write-Warning "Intune setting 'deviceThreatProtectionEnabled' is true. MDE onboarding via GPO is complex and typically involves more than simple registry values (e.g., onboarding blob). This script will not perform MDE onboarding."
        } else {
            Write-Host "Intune setting 'deviceThreatProtectionEnabled' is false. No MDE onboarding GPO settings applied."
        }
    } else { Write-Warning "Intune setting 'deviceThreatProtectionEnabled' not found in JSON."}
    
    # 6. deviceThreatProtectionRequiredSecurityLevel
    # Intune Setting: deviceThreatProtectionRequiredSecurityLevel (Value from JSON: $($policyObject.deviceThreatProtectionRequiredSecurityLevel))
    # GPO Equivalent: None. This is a compliance check against MDE's reported threat level.
    if ($policyObject.PSObject.Properties.Contains('deviceThreatProtectionRequiredSecurityLevel')) {
        Write-Warning "Intune setting 'deviceThreatProtectionRequiredSecurityLevel' is '$($policyObject.deviceThreatProtectionRequiredSecurityLevel)'. This is a compliance check against MDE's reported device risk score and is not directly enforced via GPO registry settings."
    } else { Write-Warning "Intune setting 'deviceThreatProtectionRequiredSecurityLevel' not found in JSON."}

    # Note other settings not directly mapped or enforced by this script
    Write-Host ""
    Write-Host "--- Other Intune Compliance Settings Note ---"
    Write-Host "This script primarily focuses on Device Security settings like Firewall, AV/AS baseline, and TPM prerequisites."
    Write-Host "Other settings typically found in a Windows 10 Compliance Policy (e.g., passwordRequired, bitLockerEnabled, secureBootEnabled, etc.) are checked:"
    $otherComplianceChecks = @("passwordRequired", "bitLockerEnabled", "secureBootEnabled", "codeIntegrityEnabled", "defenderEnabled", "rtpEnabled", "signatureOutOfDate")
    foreach ($check in $otherComplianceChecks) {
        if ($policyObject.PSObject.Properties.Contains($check)) {
            Write-Host "Intune setting '$check' found with value '$($policyObject.$check)'. This script does not apply GPO settings for this specific compliance check if its value is false or if it's handled by other more specific scripts."
        }
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
Write-Host "Source Intune Policy Name: $($policyObject.displayName) (Type: Windows 10 Compliance Policy - Device Security)"
Write-Host ""
Write-Host "Expected Intune settings to interpret for this policy type: $expectedIntuneSettings"
Write-Host "Total Set-GPRegistryValue commands successfully executed in this script: $configuredGpoSettings"
Write-Host ""
Write-Host "Discrepancy Explanation (if any):"
Write-Host "The 'expectedIntuneSettings' counts the number of high-level settings this script logic attempts to interpret."
Write-Host "The 'configuredGpoSettings' counts each individual Set-GPRegistryValue command executed."
Write-Host "  - If 'activeFirewallRequired' from JSON is true, 1 GPO setting is configured."
Write-Host "  - If 'antivirusRequired' or 'antiSpywareRequired' from JSON is true, 1 GPO setting is configured (to enable Defender AV as baseline)."
Write-Host "  - Settings like 'tpmRequired', OS versions, and MDE threat levels are compliance checks and do not translate to Set-GPRegistryValue commands for enforcement; warnings are issued instead."
Write-Host "  - Settings that are 'false' in the JSON are not enforced by this script."
Write-Host "This script does not use a 'settingCount' field from the JSON, as Compliance Policies do not have such a field."
Write-Host "--------------------------------------------------------------------"
Write-Host "Script finished."
# Example of how to run:
# $jsonFilePath = "WINDOWS/IntuneManagement/CompliancePolicies/Win - OIB - Compliance - U - Device Security - v3.1.json"
# $fileContent = Get-Content -Path $jsonFilePath -Raw | Out-String 
# # Ensure $fileContent is correctly passed as a single string if running manually, e.g. using $(Get-Content ... -Raw)
# .\Win-OIB-Compliance-U-Device-Security-v3.1.ps1 -JsonContentIn $fileContent
