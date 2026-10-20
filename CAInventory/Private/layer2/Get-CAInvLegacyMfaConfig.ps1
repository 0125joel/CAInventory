function Get-CAInvLegacyMfaConfig {
    <#
    .SYNOPSIS
        Domain 6.3 — Security defaults and legacy/per-user MFA.
    .DESCRIPTION
        Layer 2 collector. Reads the identitySecurityDefaultsEnforcementPolicy and records whether
        security defaults are on. Security defaults and Conditional Access mutually exclude each
        other: if the defaults are on, CA policies are not active and every later CA check is
        context-dependent.

        The legacy per-user MFA status HAS been measured since 21-08-2026. Microsoft Graph beta has
        /users/{id}/authentication/requirements for it, with the perUserMfaState property (disabled
        | enabled | enforced), readable with Policy.Read.All. The earlier text "not readable via
        modern Graph" was thereby factually outdated.

        Two constraints that drive the implementation:
          - It's a PER-USER endpoint; there's no /users?$select=perUserMfaState. A tenant of 471
            users thus requires 471 subrequests, bundled via /$batch (Invoke-CAInvGraphBatch, 20
            per call).
          - It's beta. If the measurement fails, Foundation-04 becomes 'Not assessed' with the real
            failure reason and the portal reference as a fallback route; absence of per-user MFA is
            never concluded from a failed measurement.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.3'
    $src    = 'GET /policies/identitySecurityDefaultsEnforcementPolicy'

    $resp = Invoke-CAInvGraphOrNotAssessed -Uri 'policies/identitySecurityDefaultsEnforcementPolicy' -ApiVersion 'v1.0' `
        -Domain $domain -CheckId 'Foundation-03' -ObjectType 'Policy' -Property 'securityDefaults' `
        -GraphSource $src -NotAssessedReasonPrefix ('Could not read identitySecurityDefaultsEnforcementPolicy')
    if (-not $resp.Failed) {
        $pol = $resp.Value | Select-Object -First 1
        $raw = Write-CAInvRaw -Domain $domain -Endpoint 'securityDefaults' -Data $pol
        $enabled = [bool](Get-CAInvProp $pol 'isEnabled' $false)

        New-CAInvRecord -Domain $domain -CheckId 'Foundation-03' -ObjectType 'Policy' `
            -ObjectName 'Security Defaults' -Property 'isEnabled' -ObservedValue $enabled `
            -Status ($(if ($enabled) { 'Gap' } else { 'Ready' })) `
            -GraphSource $src -RawPath $raw `
            -Recommendation ($(if ($enabled) {
                'Security defaults are on: Conditional Access policies are then NOT active. Turn the defaults off and the CA baseline on in a single change, so no window opens where neither enforces. As long as this stands, the CA rollout cannot go live.'
            } else {
                'Security defaults are off; Conditional Access can enforce the baseline.'
            })) | Out-Null
    }

    Get-CAInvPerUserMfaState -Domain $domain

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message 'Security defaults and legacy MFA context recorded.'
}

function Get-CAInvPerUserMfaState {
    <#
    .SYNOPSIS
        Foundation-04 — measures the legacy per-user MFA status of the user population.
    .DESCRIPTION
        Per-user MFA (Enabled/Enforced) clashes with CA-enforced MFA: a user set to both gets
        duplicate prompts, and Microsoft's own migration recommendation is to turn off per-user MFA
        before CA takes over. For a pre-implementation inventory, what matters is thus not only
        THAT per-user MFA exists, but WHICH accounts have it.

        Source: GET /beta/users/{id}/authentication/requirements -> perUserMfaState. Bundled via
        /$batch because no collection variant of this endpoint exists.

        Status determination:
          - No user at all on enabled/enforced -> Ready.
          - Users on enabled/enforced -> Gap. This is a measured fact against an explicit Microsoft
            recommendation, not a judgment call.
          - Population unknown or measurement (partially) failed -> Not assessed with the real
            reason.
    .PARAMETER Layer
        Layer name for the record.
    .PARAMETER Domain
        Domain for the record.
    .OUTPUTS
        None. Writes one record via New-CAInvRecord.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][string]$Domain
    )

    $src = 'GET /beta/users/{id}/authentication/requirements (perUserMfaState)'
    $portalHint = 'Fallback route: Entra portal > Users > Per-user MFA (legacy).'
    $ctx = $script:CAInvContext
    $users = @(Get-CAInvProp $ctx 'Users' @())

    if ($users.Count -eq 0) {
        New-CAInvRecord -Domain $Domain -CheckId 'Foundation-04' -ObjectType 'Tenant' `
            -Property 'perUserMfaState' -Status 'Not assessed' -ApiVersion 'beta' `
            -NotAssessedReason ('User population not available (layer 1/Identity not run in this run). {0}' -f @($portalHint)) `
            -GraphSource $src | Out-Null
        return
    }

    $targets = @($users | Where-Object {
        (Get-CAInvProp $_ 'userType' '') -eq 'Member' -and (Get-CAInvProp $_ 'accountEnabled' $false) -eq $true
    })

    if ($targets.Count -eq 0) {
        New-CAInvRecord -Domain $Domain -CheckId 'Foundation-04' -ObjectType 'Tenant' `
            -Property 'perUserMfaState' -ObservedValue 'No enabled member accounts to check.' `
            -Status 'Ready' -ApiVersion 'beta' -GraphSource $src | Out-Null
        return
    }

    $requests = @(foreach ($u in $targets) {
        [PSCustomObject]@{
            Id  = [string]$u.id
            Url = "users/$([string]$u.id)/authentication/requirements"
            Upn = [string]$u.userPrincipalName
        }
    })

    Write-CAInvLog -Level 'INFO' -Domain $Domain -Message "Foundation-04: requesting per-user MFA status for $($targets.Count) account(s) via `$batch."
    $results = Invoke-CAInvGraphBatch -Request $requests -ApiVersion 'beta'

    $onLegacy = [System.Collections.Generic.List[string]]::new()
    $failed = 0
    $firstError = $null

    foreach ($r in $requests) {
        $res = $results[$r.Id]
        if (-not $res -or -not $res.Ok) {
            $failed++
            if (-not $firstError -and $res) { $firstError = $res.Error }
            continue
        }
        $state = [string](Get-CAInvProp $res.Body 'perUserMfaState' '')

        if ($state -eq 'enabled' -or $state -eq 'enforced') {
            [void]$onLegacy.Add("$($r.Upn) ($state)")
        }
    }

    $rawPath = Write-CAInvRaw -Domain $Domain -Endpoint 'perUserMfaState' -Data @($requests | ForEach-Object {
        $res = $results[$_.Id]
        [PSCustomObject]@{
            userPrincipalName = $_.Upn
            perUserMfaState   = if ($res -and $res.Ok) { [string](Get-CAInvProp $res.Body 'perUserMfaState' '') } else { $null }
            error             = if ($res -and -not $res.Ok) { $res.Error } else { $null }
        }
    })

    if ($failed -eq $targets.Count) {
        New-CAInvRecord -Domain $Domain -CheckId 'Foundation-04' -ObjectType 'Tenant' `
            -Property 'perUserMfaState' -Status 'Not assessed' -ApiVersion 'beta' `
            -NotAssessedReason ('Could not read perUserMfaState for any user: {0}. Requires Policy.Read.All and a beta endpoint. {1}' -f @($firstError, $portalHint)) `
            -GraphSource $src -RawPath $rawPath | Out-Null
        return
    }

    $partialNote = if ($failed -gt 0) { " Note: measurement failed for $failed of the $($targets.Count) account(s) ($firstError), so this count is a lower bound." } else { '' }

    if ($onLegacy.Count -eq 0) {
        New-CAInvRecord -Domain $Domain -CheckId 'Foundation-04' -ObjectType 'Tenant' `
            -Property 'perUserMfaState' `
            -ObservedValue "None of the $($targets.Count - $failed) tested account(s) is on legacy per-user MFA (enabled/enforced).$partialNote" `
            -Status ($(if ($failed -gt 0) { 'Review required' } else { 'Ready' })) `
            -ApiVersion 'beta' `
            -ManualReview:($failed -gt 0) -GraphSource $src -RawPath $rawPath `
            -Recommendation ($(if ($failed -gt 0) { 'Confirm the unmeasured accounts manually. {0}' -f @($portalHint) } else { $null })) | Out-Null
        Write-CAInvLog -Level 'INFO' -Domain $Domain -Message "Foundation-04: no legacy per-user MFA found ($failed measurement(s) failed)."
        return
    }

    $accounts = ($onLegacy | Sort-Object) -join ', '
    New-CAInvRecord -Domain $Domain -CheckId 'Foundation-04' -ObjectType 'Tenant' `
        -Property 'perUserMfaState' `
        -ObservedValue "$($onLegacy.Count) of $($targets.Count - $failed) tested account(s) is on legacy per-user MFA.$partialNote Accounts: $accounts" `
        -Status 'Gap' -ApiVersion 'beta' -GraphSource $src -RawPath $rawPath `
        -Recommendation ('Set per-user MFA on these accounts to Disabled before enforcing MFA via Conditional Access. Per-user MFA and CA MFA side by side produce duplicate prompts and make the rollout''s behavior unpredictable.') | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $Domain -Message "Foundation-04: $($onLegacy.Count) account(s) on legacy per-user MFA ($failed measurement(s) failed)."
}
