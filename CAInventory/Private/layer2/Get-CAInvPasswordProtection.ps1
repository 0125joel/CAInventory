function Get-CAInvPasswordProtection {
    <#
    .SYNOPSIS
        Domain 6.3 — Password protection and smart lockout.
    .DESCRIPTION
        Layer 2 collector. Reads the tenant-wide 'Password Rule Settings' (banned password
        check, custom banned password list, smart lockout threshold/duration) via the beta
        directory-settings endpoint (there is no v1.0 counterpart). Microsoft only returns this
        setting as a separate directorySetting object when the tenant has ever explicitly
        changed it; if the object is missing, the Microsoft default values apply
        (banned password check on, lockout threshold 10, lockout duration 60s) — that isn't
        'Not assessed', but it is a value the tenant has never consciously confirmed, hence
        Review required instead of Ready. Microsoft's own smart
        lockout documentation describes the 10/60s defaults as offering "the right mix of security
        and usability" (learn.microsoft.com/entra/identity/authentication/howto-password-smart-lockout,
        verified 12-09-2026); this check treats a weaker configuration as a Gap on that basis.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.3'
    $src    = 'GET /beta/settings (templateId Password Rule Settings)'
    $templateId = '5cf42378-d67d-4f36-ba46-e8b86229381d'

    $resp = Invoke-CAInvGraph -Uri 'settings' -ApiVersion 'beta'
    if ($resp.Failed) {
        $reason = "Could not read directory settings: $($resp.ErrorMessage)"
        New-CAInvRecord -Domain $domain -CheckId 'Auth-16' -ObjectType 'Policy' `
            -Property 'passwordProtection' -Status 'Not assessed' -NotAssessedReason $reason `
            -ApiVersion 'beta' -GraphSource $src | Out-Null
        New-CAInvRecord -Domain $domain -CheckId 'Auth-17' -ObjectType 'Policy' `
            -Property 'smartLockout' -Status 'Not assessed' -NotAssessedReason $reason `
            -ApiVersion 'beta' -GraphSource $src | Out-Null
        return
    }

    $setting = @($resp.Value) | Where-Object { $_.templateId -eq $templateId } | Select-Object -First 1
    $usesDefaults = -not $setting

    $valueMap = @{}
    if ($setting) {
        foreach ($v in @(Get-CAInvProp $setting 'values' @())) {
            $valueMap[(Get-CAInvProp $v 'name')] = Get-CAInvProp $v 'value'
        }
        Write-CAInvRaw -Domain $domain -Endpoint 'passwordRuleSettings' -Data $setting | Out-Null
    }

    $bannedCheck = $true
    if (-not $usesDefaults) {
        $bannedCheckRaw = if ($valueMap.ContainsKey('EnableBannedPasswordCheck')) { $valueMap['EnableBannedPasswordCheck'] } else { 'True' }
        $bannedCheck = [bool]::Parse($bannedCheckRaw)
    }
    New-CAInvRecord -Domain $domain -CheckId 'Auth-16' -ObjectType 'Policy' `
        -Property 'enableBannedPasswordCheck' `
        -ObservedValue "$bannedCheck$(if ($usesDefaults) { ' (Microsoft default value, tenant never explicitly set this)' })" `
        -Status ($(if (-not $bannedCheck) { 'Gap' } elseif ($usesDefaults) { 'Review required' } else { 'Ready' })) `
        -ManualReview:($usesDefaults -and $bannedCheck) -ApiVersion 'beta' -GraphSource $src `
        -Recommendation ($(if (-not $bannedCheck) { 'Turn on banned password check.' } elseif ($usesDefaults) { 'Deliberately confirm that the Microsoft default values suffice, or set up a custom banned password list (e.g. organization name, product names).' } else { $null })) | Out-Null

    $threshold = if ($usesDefaults) { 10 } elseif ($valueMap.ContainsKey('LockoutThreshold')) { [int]$valueMap['LockoutThreshold'] } else { $null }
    $durationS = if ($usesDefaults) { 60 } elseif ($valueMap.ContainsKey('LockoutDurationInSeconds')) { [int]$valueMap['LockoutDurationInSeconds'] } else { $null }

    if ($null -eq $threshold -or $null -eq $durationS) {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-17' -ObjectType 'Policy' `
            -Property 'smartLockout' -Status 'Not assessed' `
            -NotAssessedReason ('The setting object doesn''t contain both LockoutThreshold and LockoutDurationInSeconds; the smart lockout configuration therefore cannot be determined.') `
            -ApiVersion 'beta' -GraphSource $src | Out-Null
    }
    else {
        $lockoutOk = ($threshold -le 10 -and $durationS -ge 60)
        New-CAInvRecord -Domain $domain -CheckId 'Auth-17' -ObjectType 'Policy' `
            -Property 'smartLockout' `
            -ObservedValue "threshold=$threshold; durationSeconds=$durationS$(if ($usesDefaults) { ' (Microsoft default values)' })" `
            -Status ($(if (-not $lockoutOk) { 'Gap' } elseif ($usesDefaults) { 'Review required' } else { 'Ready' })) `
            -ManualReview:($usesDefaults -and $lockoutOk) -ApiVersion 'beta' -GraphSource $src `
            -Recommendation ($(if (-not $lockoutOk) { "Set lockout threshold to at most 10 attempts and lockout duration to at least 60 seconds — Microsoft's own smart lockout defaults." } elseif ($usesDefaults) { 'Deliberately confirm that the Microsoft default values (10 attempts / 60s) suffice.' } else { $null })) | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Password protection/smart lockout assessed (defaults=$usesDefaults)."
}
