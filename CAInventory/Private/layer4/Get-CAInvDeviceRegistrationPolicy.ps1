function Get-CAInvDeviceRegistrationPolicy {
    <#
    .SYNOPSIS
        Domain 6.19 — Device registration and join.
    .DESCRIPTION
        Layer 4 collector. Reads the deviceRegistrationPolicy (v1.0 since 2026-08-20, was beta)
        that determines who may register devices (Entra registered) and join them (Entra joined),
        and whether MFA is required for that. These settings partly determine the attack surface
        for device-based CA controls: an unlimited join without MFA undermines 'require
        compliant/hybrid device'. Fails soft when the endpoint
        is unavailable.

        Device-07 (2026-08-20, verification round): Microsoft's official CA example page for the
        'Register or join devices' user action (includeUserActions contains
        'urn:user:registerdevice') explicitly warns that the legacy tenant-wide
        multiFactorAuthConfiguration toggle must be OFF (notRequired) when that CA policy is
        active, otherwise the CA policy won't be enforced correctly. The previous version of this
        check unconditionally recommended turning the legacy toggle on, which backfires for
        tenants already on the modern CA approach. Now: first look for such an enabled CA policy
        (CAPolicies from layer 0, if available); if found, the CA policy is authoritative and the
        legacy toggle is assessed against it. If there's no such policy, the original legacy
        toggle assessment remains the fallback.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.19'
    $src    = 'GET /policies/deviceRegistrationPolicy'

    $resp = Invoke-CAInvGraphOrNotAssessed -Uri 'policies/deviceRegistrationPolicy' -ApiVersion 'v1.0' `
        -Domain $domain -CheckId 'Device-07' -ObjectType 'Policy' -Property 'deviceRegistrationPolicy' `
        -GraphSource $src -NotAssessedReasonPrefix ('Could not read deviceRegistrationPolicy')
    if ($resp.Failed) { return }

    $pol = @($resp.Value) | Select-Object -First 1
    Write-CAInvRaw -Domain $domain -Endpoint 'deviceRegistrationPolicy' -Data $pol | Out-Null

    $mfaRequired = ((Get-CAInvProp $pol 'multiFactorAuthConfiguration' '') -eq 'required')

    $azureAdJoin = Format-CAInvDeviceRegistrationMembership -Membership (Get-CAInvProp $pol 'azureADJoin.allowedToJoin')
    $azureAdReg  = Format-CAInvDeviceRegistrationMembership -Membership (Get-CAInvProp $pol 'azureADRegistration.allowedToRegister')
    $userLimit   = Get-CAInvProp $pol 'userDeviceQuota'

    $caPolicies = @(Get-CAInvCaPolicy)
    $registerDevicePolicy = $caPolicies | Where-Object {
        $_.state -eq 'enabled' -and (@(Get-CAInvProp $_ 'conditions.applications.includeUserActions' @()) -contains 'urn:user:registerdevice')
    } | Select-Object -First 1

    if ($registerDevicePolicy) {
        $conflict = $mfaRequired
        New-CAInvRecord -Domain $domain -CheckId 'Device-07' -ObjectType 'Policy' `
            -Property 'deviceRegistrationAndJoin' `
            -ObservedValue "CA policy '$(Get-CAInvProp $registerDevicePolicy 'displayName')' enforces 'Register or join devices'; legacy MFA-at-join=$mfaRequired; quotaPerUser=$userLimit" `
            -Status ($(if ($conflict) { 'Review required' } else { 'Ready' })) `
            -ManualReview:$conflict -ApiVersion 'v1.0' -GraphSource $src `
            -Recommendation ($(if ($conflict) {
                "CA policy '$(Get-CAInvProp $registerDevicePolicy 'displayName')' governs device registration MFA, but the legacy tenant-wide toggle is also still on. Microsoft warns this prevents the CA policy from enforcing correctly: turn off the legacy multiFactorAuthConfiguration toggle (notRequired)."
            } else {
                'MFA at device registration/join is enforced via a CA policy (more granular than the tenant-wide toggle) and the legacy toggle is correctly off.'
            })) | Out-Null
    }
    else {
        New-CAInvRecord -Domain $domain -CheckId 'Device-07' -ObjectType 'Policy' `
            -Property 'deviceRegistrationAndJoin' `
            -ObservedValue "join allowed for: $azureAdJoin; registration allowed for: $azureAdReg; MFA-at-join=$mfaRequired; quotaPerUser=$userLimit" `
            -Status ($(if ($mfaRequired) { 'Ready' } else { 'Review required' })) `
            -ManualReview:(-not $mfaRequired) -ApiVersion 'v1.0' -GraphSource $src `
            -Recommendation ($(if ($mfaRequired) {
                'MFA is required at device join; a good basis for device-based CA controls.'
            } else {
                'No MFA is required at device registration/join. Joining a device without MFA undermines "require compliant/hybrid device" controls. Turn on MFA-at-join, or set up a (more granular) CA policy with the "Register or join devices" user action.'
            })) | Out-Null
    }

    if ($null -ne $userLimit) {
        $quotaOk = ([int]$userLimit -le 10)
        New-CAInvRecord -Domain $domain -CheckId 'Device-07' -ObjectType 'Policy' `
            -Property 'userDeviceQuota' -ObservedValue $userLimit `
            -Status ($(if ($quotaOk) { 'Ready' } else { 'Review required' })) `
            -ManualReview:(-not $quotaOk) -ApiVersion 'v1.0' -GraphSource $src `
            -Recommendation ($(if (-not $quotaOk) { "Quota of $userLimit devices per user is unusually high; more than 10 is uncommon and worth a deliberate decision rather than a leftover default." } else { $null })) | Out-Null
    }

    if (-not (Test-CAInvLicensePrecondition -CheckId 'Device-08' -Domain $domain `
            -ObjectType 'Policy' -Property 'enrollmentRestriction' -GraphSource $src `
            -Consequence ('Without Intune, there are no enrollment restrictions to assess.'))) {
        return
    }

    $decResp = Invoke-CAInvGraph -Uri 'deviceManagement/deviceEnrollmentConfigurations' -ApiVersion 'v1.0'
    if ($decResp.Failed) {
        New-CAInvRecord -Domain $domain -CheckId 'Device-08' -ObjectType 'Policy' `
            -Property 'byodEnrollmentRestriction' -Status 'Not assessed' `
            -NotAssessedReason ('Could not read deviceEnrollmentConfigurations: {0}' -f @($decResp.ErrorMessage)) `
            -GraphSource 'GET /deviceManagement/deviceEnrollmentConfigurations' | Out-Null
    }
    else {
        $configs = @($decResp.Value | Where-Object { "$(Get-CAInvProp $_ '@odata.type' '')" -match 'PlatformRestriction' })
        $platformKeys = @('iosRestriction', 'androidRestriction', 'androidForWorkRestriction', 'windowsRestriction', 'macOSRestriction')
        $blockedPlatforms = [System.Collections.Generic.List[string]]::new()
        foreach ($c in $configs) {
            foreach ($k in $platformKeys) {
                $restriction = Get-CAInvProp $c $k
                if ($restriction -and [bool](Get-CAInvProp $restriction 'personalDeviceEnrollmentBlocked' $false)) {
                    [void]$blockedPlatforms.Add(($k -replace 'Restriction$', ''))
                }
            }
        }
        $blockedPlatforms = @($blockedPlatforms | Select-Object -Unique)
        New-CAInvRecord -Domain $domain -CheckId 'Device-08' -ObjectType 'Policy' `
            -Property 'byodEnrollmentRestriction' `
            -ObservedValue "Personal device enrollment blocked for: $(if ($blockedPlatforms.Count) { $blockedPlatforms -join ', ' } else { 'no platform at all' })" `
            -Status ($(if ($blockedPlatforms.Count -gt 0) { 'Ready' } else { 'Review required' })) `
            -ManualReview:($blockedPlatforms.Count -eq 0) `
            -GraphSource 'GET /deviceManagement/deviceEnrollmentConfigurations' `
            -Recommendation ($(if ($blockedPlatforms.Count -eq 0) { 'Consider blocking personal (BYOD) device enrollment, or deliberately confirm that BYOD is allowed and that compliance/CA controls cover that scenario.' } else { $null })) | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Device registration policy read (MFA-at-join=$mfaRequired)."
}

function Format-CAInvDeviceRegistrationMembership {
    <#
    .SYNOPSIS
        Translates a deviceRegistrationMembership object into readable text.
    .DESCRIPTION
        azureADJoinPolicy.allowedToJoin and azureADRegistrationPolicy.allowedToRegister are
        polymorphic membership objects with three possible @odata.type shapes:
        allDeviceRegistrationMembership (everyone), noDeviceRegistrationMembership (nobody), or
        enumeratedDeviceRegistrationMembership (an explicit list of users/groups). Only for
        Get-CAInvDeviceRegistrationPolicy (Device-07).
    .PARAMETER Membership
        The membership object, or $null.
    .OUTPUTS
        String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] $Membership
    )

    if (-not $Membership) { return 'unknown (not in the response)' }

    $type = [string](Get-CAInvProp $Membership '@odata.type' '')
    switch -Wildcard ($type) {
        '*allDeviceRegistrationMembership' { return 'everyone' }
        '*noDeviceRegistrationMembership' { return 'nobody' }
        '*enumeratedDeviceRegistrationMembership' {
            $users = @(Get-CAInvProp $Membership 'users' @())
            $groups = @(Get-CAInvProp $Membership 'groups' @())
            $parts = @()
            if ($users.Count -gt 0) { $parts += "$($users.Count) user(s)" }
            if ($groups.Count -gt 0) { $parts += "$($groups.Count) group(s)" }
            if ($parts.Count -eq 0) { return 'nobody (empty list)' }
            return ($parts -join ', ')
        }
        default { return "unknown ($type)" }
    }
}
