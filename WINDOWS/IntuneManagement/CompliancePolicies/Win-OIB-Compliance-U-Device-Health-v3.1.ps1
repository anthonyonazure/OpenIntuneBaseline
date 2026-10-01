<#
.SYNOPSIS
    Creates and configures a Group Policy Object (GPO) based on settings from an Intune JSON policy.
.DESCRIPTION
    This script reads an Intune JSON policy export for 'Win - OIB - Compliance - U - Device Health - v3.1',
    extracts relevant Device Health settings, and creates a corresponding GPO.
    It attempts to map these settings to GPO registry values where feasible using Set-GPRegistryValue.
    Many Device Health settings are prerequisites (firmware-level) or complex configurations
    not directly translatable to simple 'Policies' registry keys.
    This script is self-contained and uses the provided JSON content directly.
.NOTES
    Source Policy Name: Win - OIB - Compliance - U - Device Health - v3.1
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
# For this Device Health compliance policy, we are looking for:
# bitLockerEnabled, secureBootEnabled, codeIntegrityEnabled, memoryIntegrityEnabled, 
# kernelDmaProtectionEnabled, virtualizationBasedSecurityEnabled, firmwareProtectionEnabled,
# earlyLaunchAntiMalwareDriverEnabled, tpmRequired, storageRequireEncryption
$expectedIntuneSettings = 10 
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
    $gpoDescription = "GPO created from Intune policy '$gpoName' (Device Health Compliance - Automated Script)"
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

    $deviceGuardRegPath = "SYSTEM\CurrentControlSet\Control\DeviceGuard"
    $fveRegPath = "SOFTWARE\Policies\Microsoft\FVE"

    # 1. bitLockerEnabled
    # Intune Setting: bitLockerEnabled (Value from JSON: $($policyObject.bitLockerEnabled))
    # GPO Example: Computer Configuration > Admin Templates > Windows Components > BitLocker Drive Encryption > Fixed Data Drives > Deny write access to fixed drives not protected by BitLocker
    if ($policyObject.PSObject.Properties.Contains('bitLockerEnabled')) {
        if ($policyObject.bitLockerEnabled -eq $true) {
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $fveRegPath -ValueName "FDVDenyWriteAccess" -Type DWord -Value 1 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for bitLockerEnabled: $fveRegPath\FDVDenyWriteAccess = 1 (Deny write access to non-BitLocker fixed drives)"
            Write-Warning "Note: This is one example of a BitLocker-related GPO setting. Full BitLocker enforcement is more complex and typically involves multiple GPO settings (OS drive encryption, recovery options, TPM configuration, etc.) which are not all covered by this script."
        } else {
            Write-Warning "Intune setting 'bitLockerEnabled' is '$($policyObject.bitLockerEnabled)'. No GPO settings for BitLocker enforcement applied."
        }
    } else { Write-Warning "Intune setting 'bitLockerEnabled' not found in JSON."}

    # 2. secureBootEnabled
    # Intune Setting: secureBootEnabled (Value from JSON: $($policyObject.secureBootEnabled))
    # GPO Equivalent: None for direct enablement. It's a firmware setting.
    if ($policyObject.PSObject.Properties.Contains('secureBootEnabled')) {
        if ($policyObject.secureBootEnabled -eq $true) {
            Write-Warning "Intune setting 'secureBootEnabled' is true. Secure Boot is a UEFI firmware setting and must be enabled in BIOS/UEFI. GPO cannot enforce this directly. It serves as a prerequisite for features like VBS/HVCI."
        } else {
            Write-Warning "Intune setting 'secureBootEnabled' is false. For features like VBS/HVCI to be fully effective and secure, Secure Boot should be enabled in the firmware."
        }
    } else { Write-Warning "Intune setting 'secureBootEnabled' not found in JSON."}

    # 3. codeIntegrityEnabled (Hypervisor-Enforced Code Integrity - HVCI)
    # Intune Setting: codeIntegrityEnabled (Value from JSON: $($policyObject.codeIntegrityEnabled))
    # GPO Path: Computer Configuration > Admin Templates > System > Device Guard > Turn On Virtualization Based Security
    if ($policyObject.PSObject.Properties.Contains('codeIntegrityEnabled')) {
        if ($policyObject.codeIntegrityEnabled -eq $true) {
            Write-Host "Intune setting 'codeIntegrityEnabled' is true. Attempting to enforce related VBS and HVCI GPO settings."
            
            # EnableVirtualizationBasedSecurity = 1 (Enable VBS)
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $deviceGuardRegPath -ValueName "EnableVirtualizationBasedSecurity" -Type DWord -Value 1 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for VBS: $deviceGuardRegPath\EnableVirtualizationBasedSecurity = 1"

            # RequirePlatformSecurityFeatures: 1 for Secure Boot (as kernelDmaProtectionEnabled is false)
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $deviceGuardRegPath -ValueName "RequirePlatformSecurityFeatures" -Type DWord -Value 1 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for VBS: $deviceGuardRegPath\RequirePlatformSecurityFeatures = 1 (Requires Secure Boot)"

            # HypervisorEnforcedCodeIntegrity = 1 (Enable HVCI / Memory Integrity)
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $deviceGuardRegPath -ValueName "HypervisorEnforcedCodeIntegrity" -Type DWord -Value 1 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for HVCI: $deviceGuardRegPath\HypervisorEnforcedCodeIntegrity = 1"
            
            # Locked = 1 (Prevent VBS/HVCI from being turned off locally)
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $deviceGuardRegPath -ValueName "Locked" -Type DWord -Value 1 -ErrorAction Stop
            $configuredGpoSettings++
            Write-Host "Applied GPO Setting for VBS: $deviceGuardRegPath\Locked = 1 (Prevent local changes)"
            
            Write-Warning "Note: Full effectiveness of VBS/HVCI requires appropriate hardware, firmware (with Secure Boot enabled), and hypervisor support. The JSON indicated 'virtualizationBasedSecurityEnabled: $($policyObject.virtualizationBasedSecurityEnabled)', but VBS keys were set due to 'codeIntegrityEnabled: true'."
        } else {
            Write-Warning "Intune setting 'codeIntegrityEnabled' is '$($policyObject.codeIntegrityEnabled)'. GPO settings for VBS/HVCI not applied based on this flag."
        }
    } else { Write-Warning "Intune setting 'codeIntegrityEnabled' not found in JSON."}

    # 4. memoryIntegrityEnabled (Often synonymous with HVCI)
    # Intune Setting: memoryIntegrityEnabled (Value from JSON: $($policyObject.memoryIntegrityEnabled))
    if ($policyObject.PSObject.Properties.Contains('memoryIntegrityEnabled')) {
        if ($policyObject.memoryIntegrityEnabled -eq $true -and $policyObject.codeIntegrityEnabled -ne $true) {
            # Only apply if codeIntegrityEnabled didn't already set it (to avoid double-counting or conflicting logic)
            Write-Warning "Intune setting 'memoryIntegrityEnabled' is true, but 'codeIntegrityEnabled' was not. This state is unusual. Consider aligning these. HVCI settings are typically applied if 'codeIntegrityEnabled' is true."
            # If codeIntegrityEnabled was false, but this is true, it's a conflict.
            # This script prioritizes codeIntegrityEnabled for setting HVCI.
        } elseif ($policyObject.memoryIntegrityEnabled -eq $false) {
             Write-Host "Intune setting 'memoryIntegrityEnabled' is false. HVCI is typically enabled via 'codeIntegrityEnabled'."
        }
    } else { Write-Warning "Intune setting 'memoryIntegrityEnabled' not found in JSON."}

    # 5. kernelDmaProtectionEnabled
    # Intune Setting: kernelDmaProtectionEnabled (Value from JSON: $($policyObject.kernelDmaProtectionEnabled))
    if ($policyObject.PSObject.Properties.Contains('kernelDmaProtectionEnabled')) {
        Write-Host "Intune setting 'kernelDmaProtectionEnabled' is '$($policyObject.kernelDmaProtectionEnabled)'. If true, this would typically set 'RequirePlatformSecurityFeatures' to '3' (Secure Boot + DMA). Current script logic sets it based on 'codeIntegrityEnabled' and does not separately enforce the DMA bit if 'kernelDmaProtectionEnabled' is true but 'codeIntegrityEnabled' is false."
    } else { Write-Warning "Intune setting 'kernelDmaProtectionEnabled' not found in JSON."}

    # 6. virtualizationBasedSecurityEnabled
    # Intune Setting: virtualizationBasedSecurityEnabled (Value from JSON: $($policyObject.virtualizationBasedSecurityEnabled))
    if ($policyObject.PSObject.Properties.Contains('virtualizationBasedSecurityEnabled')) {
         Write-Host "Intune setting 'virtualizationBasedSecurityEnabled' is '$($policyObject.virtualizationBasedSecurityEnabled)'. VBS is enabled as a prerequisite if 'codeIntegrityEnabled' is true."
    } else { Write-Warning "Intune setting 'virtualizationBasedSecurityEnabled' not found in JSON."}
    
    # 7. firmwareProtectionEnabled
    # Intune Setting: firmwareProtectionEnabled (Value from JSON: $($policyObject.firmwareProtectionEnabled))
    if ($policyObject.PSObject.Properties.Contains('firmwareProtectionEnabled')) {
        Write-Host "Intune setting 'firmwareProtectionEnabled' is '$($policyObject.firmwareProtectionEnabled)'. This often relates to System Guard Secure Launch or Secured-core PC capabilities, which are not typically managed by simple GPO registry toggles. No GPO setting applied."
    } else { Write-Warning "Intune setting 'firmwareProtectionEnabled' not found in JSON."}

    # 8. earlyLaunchAntiMalwareDriverEnabled (ELAM)
    # Intune Setting: earlyLaunchAntiMalwareDriverEnabled (Value from JSON: $($policyObject.earlyLaunchAntiMalwareDriverEnabled))
    if ($policyObject.PSObject.Properties.Contains('earlyLaunchAntiMalwareDriverEnabled')) {
        Write-Host "Intune setting 'earlyLaunchAntiMalwareDriverEnabled' is '$($policyObject.earlyLaunchAntiMalwareDriverEnabled)'. ELAM driver registration is part of the AV installation process. GPO does not directly toggle this boolean state for compliance. No GPO setting applied."
    } else { Write-Warning "Intune setting 'earlyLaunchAntiMalwareDriverEnabled' not found in JSON."}

    # 9. tpmRequired
    # Intune Setting: tpmRequired (Value from JSON: $($policyObject.tpmRequired))
    if ($policyObject.PSObject.Properties.Contains('tpmRequired')) {
        Write-Host "Intune setting 'tpmRequired' is '$($policyObject.tpmRequired)'. TPM is a hardware/firmware prerequisite for features like BitLocker and VBS. GPO cannot enable the TPM chip itself. This script does not set a GPO setting based on this flag."
    } else { Write-Warning "Intune setting 'tpmRequired' not found in JSON."}
    
    # 10. storageRequireEncryption
    # Intune Setting: storageRequireEncryption (Value from JSON: $($policyObject.storageRequireEncryption))
    if ($policyObject.PSObject.Properties.Contains('storageRequireEncryption')) {
        if ($policyObject.storageRequireEncryption -eq $true -and $policyObject.bitLockerEnabled -ne $true) {
             Write-Warning "Intune setting 'storageRequireEncryption' is true, but 'bitLockerEnabled' is false. Enforcing storage encryption typically relies on BitLocker, which is not being enforced per the 'bitLockerEnabled' flag. No specific GPO setting applied for 'storageRequireEncryption' alone."
        } else {
            Write-Host "Intune setting 'storageRequireEncryption' is '$($policyObject.storageRequireEncryption)'. This is typically met by BitLocker. BitLocker enforcement is handled by the 'bitLockerEnabled' setting logic."
        }
    } else { Write-Warning "Intune setting 'storageRequireEncryption' not found in JSON."}


} catch {
    Write-Error "An error occurred during GPO creation or configuration: $($_.Exception.Message)"
}

# --- Final Verification ---
Write-Host ""
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Configuration Script Summary"
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Name: $gpoName"
Write-Host "Source Intune Policy Name: $($policyObject.displayName) (Type: Windows 10 Compliance Policy - Device Health)"
Write-Host ""
Write-Host "Expected Intune settings to interpret for this policy type: $expectedIntuneSettings"
Write-Host "Total Set-GPRegistryValue commands executed in this script: $configuredGpoSettings"
Write-Host ""
Write-Host "Discrepancy Explanation (if any):"
Write-Host "The 'expectedIntuneSettings' counts the number of high-level Device Health settings this script logic attempts to interpret."
Write-Host "The 'configuredGpoSettings' counts each individual Set-GPRegistryValue command."
Write-Host "  - If 'bitLockerEnabled' from JSON is true, 1 GPO setting is configured (example setting)."
Write-Host "  - If 'codeIntegrityEnabled' from JSON is true, 4 GPO settings are configured (for VBS, HVCI, and lock)."
Write-Host "  - Many Device Health settings (e.g., SecureBoot, TPM, ELAM) are firmware/hardware prerequisites or complex states not directly enforced by simple 'Policies' registry keys via Set-GPRegistryValue; these are noted with warnings."
Write-Host "  - Settings that are 'false' in the JSON are generally not enforced by this script."
Write-Host "This script does not use a 'settingCount' field from the JSON, as Compliance Policies do not have such a field."
Write-Host "--------------------------------------------------------------------"
Write-Host "Script finished."
# Example of how to run:
# $jsonFilePath = "WINDOWS/IntuneManagement/CompliancePolicies/Win - OIB - Compliance - U - Device Health - v3.1.json"
# $fileContent = Get-Content -Path $jsonFilePath -Raw | Out-String
# # Ensure $fileContent is correctly passed as a single string if running manually, e.g. using $(Get-Content ... -Raw)
# .\Win-OIB-Compliance-U-Device-Health-v3.1.ps1 -JsonContentIn $fileContent
