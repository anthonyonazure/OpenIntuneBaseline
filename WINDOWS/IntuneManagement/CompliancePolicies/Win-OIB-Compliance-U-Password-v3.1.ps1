<#
.SYNOPSIS
    Creates and configures a Group Policy Object (GPO) based on settings from an Intune JSON policy.
.DESCRIPTION
    This script reads an Intune JSON policy export for 'Win - OIB - Compliance - U - Password - v3.1',
    extracts relevant Password settings, and creates a corresponding GPO.
    It attempts to map these settings to GPO registry values where feasible using Set-GPRegistryValue.
    Crucially, most traditional password policy settings (length, complexity, history) are NOT directly
    enforced by Set-GPRegistryValue on individual clients via GPO registry keys in 'Software\Policies'.
    They are typically domain-level policies or require local security policy tools like secedit.
    This script will issue warnings for such settings.
    Screen saver related password settings are an exception and will be mapped if present.
    This script is self-contained and uses the provided JSON content directly.
.NOTES
    Source Policy Name: Win - OIB - Compliance - U - Password - v3.1
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
# For this Password compliance policy, we are looking for:
# passwordRequired, passwordBlockSimple, passwordRequiredToUnlockFromIdle, passwordMinutesOfInactivityBeforeLock,
# passwordExpirationDays, passwordMinimumLength, passwordMinimumCharacterSetCount, passwordRequiredType, passwordPreviousPasswordBlockCount
$expectedIntuneSettings = 9
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
    $gpoDescription = "GPO created from Intune policy '$gpoName' (Password Compliance - Automated Script)"
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
    Write-Host "--- Processing Password Settings from Intune JSON ---"

    # 1. passwordRequired
    # Intune Setting: passwordRequired (Value from JSON: $($policyObject.passwordRequired))
    # GPO Equivalent: Typically part of Account Policies (SAM/AD level), not a direct 'Policies' registry key.
    Write-Warning "Intune setting 'passwordRequired: $($policyObject.passwordRequired)'. Standard GPOs enforce this implicitly via password length/complexity, not a direct toggle key modifiable by Set-GPRegistryValue under 'Software\Policies'. This setting is typically managed by domain or local security policy (SAM)."

    # 2. passwordBlockSimple
    # Intune Setting: passwordBlockSimple (Value from JSON: $($policyObject.passwordBlockSimple))
    # GPO Equivalent: 'Password must meet complexity requirements' (SAM/AD level).
    Write-Warning "Intune setting 'passwordBlockSimple: $($policyObject.passwordBlockSimple)'. 'Simple' passwords are usually blocked by enabling password complexity. Standard GPO password complexity is not directly managed via 'Software\Policies' registry keys for Set-GPRegistryValue. This setting is typically managed by domain or local security policy (SAM)."

    # 3. passwordMinimumLength
    # Intune Setting: passwordMinimumLength (Value from JSON: $($policyObject.passwordMinimumLength))
    # GPO Equivalent: 'Minimum password length' (SAM/AD level).
    if ($policyObject.passwordMinimumLength -ne $null -and $policyObject.passwordMinimumLength -gt 0) {
        Write-Warning "Intune setting 'passwordMinimumLength: $($policyObject.passwordMinimumLength)'. Standard GPO minimum password length is not directly managed via 'Software\Policies' registry keys for Set-GPRegistryValue. This setting is typically managed by domain or local security policy (SAM)."
    } else {
        Write-Host "Intune setting 'passwordMinimumLength' is null or zero."
    }

    # 4. passwordRequiredType
    # Intune Setting: passwordRequiredType (Value from JSON: $($policyObject.passwordRequiredType))
    # GPO Equivalent: Part of 'Password must meet complexity requirements' (SAM/AD level). No direct GPO equivalent for "numeric only" via 'Policies' key.
    if (-not [string]::IsNullOrEmpty($policyObject.passwordRequiredType)) {
        Write-Warning "Intune setting 'passwordRequiredType: $($policyObject.passwordRequiredType)'. Standard GPOs define complexity (e.g., requiring uppercase, lowercase, numbers, symbols) rather than a specific type like 'numeric' via 'Software\Policies' registry keys for Set-GPRegistryValue. This setting is typically managed by domain or local security policy (SAM)."
    } else {
        Write-Host "Intune setting 'passwordRequiredType' is null or empty."
    }
    
    # 5. passwordExpirationDays
    # Intune Setting: passwordExpirationDays (Value from JSON: $($policyObject.passwordExpirationDays))
    # GPO Equivalent: 'Maximum password age' (SAM/AD level).
    if ($policyObject.passwordExpirationDays -ne $null) {
        Write-Warning "Intune setting 'passwordExpirationDays: $($policyObject.passwordExpirationDays)'. Standard GPO password expiration is not directly managed via 'Software\Policies' registry keys for Set-GPRegistryValue. This setting is typically managed by domain or local security policy (SAM)."
    } else {
        Write-Host "Intune setting 'passwordExpirationDays' is null."
    }

    # 6. passwordPreviousPasswordBlockCount
    # Intune Setting: passwordPreviousPasswordBlockCount (Value from JSON: $($policyObject.passwordPreviousPasswordBlockCount))
    # GPO Equivalent: 'Enforce password history' (SAM/AD level).
    if ($policyObject.passwordPreviousPasswordBlockCount -ne $null) {
        Write-Warning "Intune setting 'passwordPreviousPasswordBlockCount: $($policyObject.passwordPreviousPasswordBlockCount)'. Standard GPO password history is not directly managed via 'Software\Policies' registry keys for Set-GPRegistryValue. This setting is typically managed by domain or local security policy (SAM)."
    } else {
        Write-Host "Intune setting 'passwordPreviousPasswordBlockCount' is null."
    }
    
    # 7. passwordMinimumCharacterSetCount
    # Intune Setting: passwordMinimumCharacterSetCount (Value from JSON: $($policyObject.passwordMinimumCharacterSetCount))
    # GPO Equivalent: Part of 'Password must meet complexity requirements' (SAM/AD level).
    if ($policyObject.passwordMinimumCharacterSetCount -ne $null) {
        Write-Warning "Intune setting 'passwordMinimumCharacterSetCount: $($policyObject.passwordMinimumCharacterSetCount)'. This relates to password complexity (number of character types like upper, lower, digit, symbol). Standard GPO complexity is not directly managed via 'Software\Policies' registry keys for Set-GPRegistryValue. This setting is typically managed by domain or local security policy (SAM)."
    } else {
        Write-Host "Intune setting 'passwordMinimumCharacterSetCount' is null."
    }

    # 8. passwordMinutesOfInactivityBeforeLock
    # Intune Setting: passwordMinutesOfInactivityBeforeLock (Value from JSON: $($policyObject.passwordMinutesOfInactivityBeforeLock))
    # GPO Path: User Configuration > Admin Templates > Control Panel > Personalization > Screen saver timeout / Password protect the screen saver
    # Registry (HKCU): Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaveTimeOut (REG_SZ, seconds)
    # Registry (HKCU): Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaverIsSecure (REG_SZ, "1")
    if ($policyObject.PSObject.Properties.Contains('passwordMinutesOfInactivityBeforeLock') -and $policyObject.passwordMinutesOfInactivityBeforeLock -ne $null -and $policyObject.passwordMinutesOfInactivityBeforeLock -gt 0) {
        $timeoutSeconds = $policyObject.passwordMinutesOfInactivityBeforeLock * 60
        $regKeyDesktop = "Software\Policies\Microsoft\Windows\Control Panel\Desktop" # HKCU context implies User Configuration for GPO
        
        Set-GPRegistryValue -Name $gpo.DisplayName -Key $regKeyDesktop -ValueName "ScreenSaveTimeOut" -Type String -Value $timeoutSeconds.ToString() -Context User -ErrorAction Stop
        $configuredGpoSettings++
        Write-Host "Applied GPO Setting for passwordMinutesOfInactivityBeforeLock (ScreenSaveTimeOut): $regKeyDesktop\ScreenSaveTimeOut = '$timeoutSeconds' (User Config)"

        # This setting implies that a password is required to unlock.
        Set-GPRegistryValue -Name $gpo.DisplayName -Key $regKeyDesktop -ValueName "ScreenSaverIsSecure" -Type String -Value "1" -Context User -ErrorAction Stop
        $configuredGpoSettings++
        Write-Host "Applied GPO Setting for passwordMinutesOfInactivityBeforeLock (ScreenSaverIsSecure): $regKeyDesktop\ScreenSaverIsSecure = '1' (User Config)"
        Write-Host "Note: This screen saver lock setting is applied due to 'passwordMinutesOfInactivityBeforeLock' being set to '$($policyObject.passwordMinutesOfInactivityBeforeLock)' minutes."
        Write-Host "The Intune setting 'passwordRequiredToUnlockFromIdle' was '$($policyObject.passwordRequiredToUnlockFromIdle)'."
    } else {
        Write-Host "Intune setting 'passwordMinutesOfInactivityBeforeLock' is '$($policyObject.passwordMinutesOfInactivityBeforeLock)' (null, zero, or not positive). No GPO setting applied for screen saver timeout."
    }

    # 9. passwordRequiredToUnlockFromIdle
    # Intune Setting: passwordRequiredToUnlockFromIdle (Value from JSON: $($policyObject.passwordRequiredToUnlockFromIdle))
    # GPO Path: User Configuration > Admin Templates > Control Panel > Personalization > Password protect the screen saver
    # This is usually coupled with ScreenSaveTimeOut. If timeout is not set, this alone might not be effective or easily mapped.
    if ($policyObject.PSObject.Properties.Contains('passwordRequiredToUnlockFromIdle')) {
        if ($policyObject.passwordRequiredToUnlockFromIdle -eq $true -and ($policyObject.passwordMinutesOfInactivityBeforeLock -eq $null -or $policyObject.passwordMinutesOfInactivityBeforeLock -le 0)) {
            # If passwordMinutesOfInactivityBeforeLock was set, ScreenSaverIsSecure is already handled.
            # This condition addresses if passwordRequiredToUnlockFromIdle is true INDEPENDENTLY of a timeout.
            $regKeyDesktop = "Software\Policies\Microsoft\Windows\Control Panel\Desktop"
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $regKeyDesktop -ValueName "ScreenSaverIsSecure" -Type String -Value "1" -Context User -ErrorAction Stop
            $configuredGpoSettings++ # This might be redundant if the above block also set it.
            Write-Warning "Intune setting 'passwordRequiredToUnlockFromIdle' is true. Applied GPO Setting: $regKeyDesktop\ScreenSaverIsSecure = '1' (User Config). This is most effective when a screen saver timeout is also active."
        } elseif ($policyObject.passwordRequiredToUnlockFromIdle -eq $false -and ($policyObject.passwordMinutesOfInactivityBeforeLock -eq $null -or $policyObject.passwordMinutesOfInactivityBeforeLock -le 0)) {
             Write-Host "Intune setting 'passwordRequiredToUnlockFromIdle' is false, and no inactivity timeout is set. No screen saver lock GPO setting applied."
        }
        # If passwordMinutesOfInactivityBeforeLock is set, that block already handles ScreenSaverIsSecure = "1".
    } else { Write-Warning "Intune setting 'passwordRequiredToUnlockFromIdle' not found in JSON."}


    Write-Host ""
    Write-Host "--- Additional Notes on Password Policy Enforcement ---"
    Write-Host "Most core password policy settings (length, complexity, history, expiration) are traditionally managed via specific Group Policy extensions (Account Policies -> Password Policy) that modify security databases (SAM for local accounts, NTDS.DIT for domain accounts) rather than registry keys under 'Software\Policies'."
    Write-Host "The `Set-GPRegistryValue` cmdlet is primarily for Administrative Template settings that write to these 'Policies' keys. Therefore, this script cannot directly enforce many of the listed password compliance settings into a GPO in a way that clients would process them as standard password policies."
    Write-Host "The warnings issued above for each relevant setting reflect this limitation."
    Write-Host "Screen saver settings, which can require a password on resume, are an exception and have been mapped if configured in the JSON."

} catch {
    Write-Error "An error occurred during GPO creation or configuration: $($_.Exception.Message)"
}

# --- Final Verification ---
Write-Host ""
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Configuration Script Summary"
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Name: $gpoName"
Write-Host "Source Intune Policy Name: $($policyObject.displayName) (Type: Windows 10 Compliance Policy - Password)"
Write-Host ""
Write-Host "Expected Intune settings to interpret for this policy type: $expectedIntuneSettings"
Write-Host "Total Set-GPRegistryValue commands successfully executed in this script: $configuredGpoSettings"
Write-Host ""
Write-Host "Discrepancy Explanation:"
Write-Host "The 'expectedIntuneSettings' counts the number of password-related properties this script logic attempts to interpret from the Intune JSON."
Write-Host "The 'configuredGpoSettings' counts individual Set-GPRegistryValue commands executed. For password policies:"
Write-Host "  - Most settings (length, complexity, history, type, expiration) do not map directly to 'Software\Policies' registry keys for GPO enforcement and thus result in warnings, not Set-GPRegistryValue commands."
Write-Host "  - 'passwordMinutesOfInactivityBeforeLock', if configured with a positive value, results in two Set-GPRegistryValue commands (ScreenSaveTimeOut and ScreenSaverIsSecure)."
Write-Host "  - 'passwordRequiredToUnlockFromIdle: true' might result in one command if no inactivity timeout is set."
Write-Host "Therefore, a low number of 'configuredGpoSettings' is expected for this policy type when using only Set-GPRegistryValue."
Write-Host "This script does not use a 'settingCount' field from the JSON, as Compliance Policies do not have such a field."
Write-Host "--------------------------------------------------------------------"
Write-Host "Script finished."
# Example of how to run:
# $jsonFilePath = "WINDOWS/IntuneManagement/CompliancePolicies/Win - OIB - Compliance - U - Password - v3.1.json"
# $fileContent = Get-Content -Path $jsonFilePath -Raw | Out-String 
# # Ensure $fileContent is correctly passed as a single string if running manually, e.g. using $(Get-Content ... -Raw)
# .\Win-OIB-Compliance-U-Password-v3.1.ps1 -JsonContentIn $fileContent
