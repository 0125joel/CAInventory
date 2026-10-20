function Get-CAInvSessionControl {
    <#
    .SYNOPSIS
        Domain 6.26 — Session controls and token management.
    .DESCRIPTION
        Layer 5 collector. Summarizes the sessionControls from the CA policies: sign-in frequency,
        persistent browser, application enforced restrictions, cloud app security (CAS), and
        continuous access evaluation (CAE)/token protection where present. These controls determine
        how long a session stays valid and are crucial during a migration: too strict leads to
        prompt fatigue, too loose undermines the benefit. Reads
        the already-fetched CAPolicies (layer 0).

        Condition-04 (Token Protection) reads secureSignInSession from the v1.0 set by preference
        and only falls back to the beta set when v1.0 doesn't deliver that property at all.

        That distinction is deliberate, and the reason is instructive: the Learn page for the v1.0
        resource conditionalAccessSessionControls lists five properties and omits
        secureSignInSession, but a real v1.0 response DOES deliver it (verified on a live tenant,
        25-08-2026: 13 of the 32 policies carried the field, with a populated value on the Token
        Protection policy). So the documentation lags behind the API here. If this check relied on
        beta exclusively, a query that v1.0 can answer perfectly well would go needlessly Not
        assessed the moment the beta endpoint hiccups.

        The beta set remains necessary for properties v1.0 genuinely doesn't know, such as
        continuousAccessEvaluation (confirmed absent in that same v1.0 response).

        Condition-06 (continuous access evaluation) is genuinely beta-only and so has no v1.0 branch.

        Condition-05 (resilience defaults) reads sessionControls.disableResilienceDefaults, which
        does live in v1.0 as normal. That check deliberately sits BEFORE the Condition-04 block:
        that block can return early when no source carries secureSignInSession, and Condition-05
        would then be silently skipped.

        A fetch failure (CAPoliciesFetchFailed on the context) is Not assessed for all four
        CheckIds this function writes. A confirmed-empty policy set (fetch succeeded, zero
        policies) is NOT the same thing and is left to flow through the normal per-check logic
        instead: Condition-03/07-style "no policy does X" branches already produce the right
        answer for zero policies without a special case (Condition-03 Review required, Condition-05
        Ready). Condition-06 reuses the existing CAPoliciesBetaError-driven distinction. Condition-04
        gets one explicit branch for "both v1.0 and beta confirm zero, neither failed" -> Gap,
        since with zero policies nothing can enforce Token Protection, which is a real finding.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.26'
    $src    = 'CA conditions/sessionControls'

    $ctx = $script:CAInvContext
    $caPolicies = @(Get-CAInvCaPolicy)

    if ($caPolicies.Count -eq 0 -and [bool](Get-CAInvProp $ctx 'CAPoliciesFetchFailed' $true)) {
        $notAssessedReason = 'CA policies not available (layer 0 not run, or not readable).'
        New-CAInvRecord -Domain $domain -CheckId 'Condition-03' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'sessionControls' -Status 'Not assessed' `
            -NotAssessedReason $notAssessedReason -GraphSource $src | Out-Null
        New-CAInvRecord -Domain $domain -CheckId 'Condition-04' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'tokenProtection' -Status 'Not assessed' `
            -NotAssessedReason $notAssessedReason -GraphSource $src | Out-Null
        New-CAInvRecord -Domain $domain -CheckId 'Condition-05' -ObjectType 'Tenant' `
            -Property 'sessionControls.disableResilienceDefaults' -Status 'Not assessed' `
            -NotAssessedReason $notAssessedReason -GraphSource $src | Out-Null
        New-CAInvRecord -Domain $domain -CheckId 'Condition-06' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'sessionControls.continuousAccessEvaluation.mode' -Status 'Not assessed' `
            -NotAssessedReason $notAssessedReason -ApiVersion 'beta' `
            -GraphSource 'GET /beta/identity/conditionalAccess/policies (sessionControls.continuousAccessEvaluation)' | Out-Null
        return
    }

    $withSession = 0
    foreach ($p in $caPolicies) {
        $sc = Get-CAInvProp $p 'sessionControls'
        if (-not $sc) { continue }

        $sif = Get-CAInvProp $sc 'signInFrequency'
        $persist = Get-CAInvProp $sc 'persistentBrowser'
        $appEnforced = Get-CAInvProp $sc 'applicationEnforcedRestrictions'
        $cas = Get-CAInvProp $sc 'cloudAppSecurity'

        $parts = @()
        if ($sif -and (Get-CAInvProp $sif 'isEnabled' $false)) {

            $parts += if ((Get-CAInvProp $sif 'frequencyInterval' '') -eq 'everyTime') {
                'signInFrequency=everyTime'
            }
            else {
                "signInFrequency=$(Get-CAInvProp $sif 'value')$(Get-CAInvProp $sif 'type')"
            }
        }
        if ($persist -and (Get-CAInvProp $persist 'isEnabled' $false)) { $parts += "persistentBrowser=$(Get-CAInvProp $persist 'mode')" }
        if ($appEnforced -and (Get-CAInvProp $appEnforced 'isEnabled' $false)) { $parts += 'appEnforcedRestrictions' }
        if ($cas -and (Get-CAInvProp $cas 'isEnabled' $false)) { $parts += "cloudAppSecurity=$(Get-CAInvProp $cas 'cloudAppSecurityType')" }

        if ($parts.Count -eq 0) { continue }
        $withSession++
        New-CAInvRecord -Domain $domain -CheckId 'Condition-03' -ObjectType 'ConditionalAccessPolicy' `
            -ObjectId (Get-CAInvProp $p 'id') -ObjectName (Get-CAInvProp $p 'displayName') -Property 'sessionControls' `
            -ObservedValue ($parts -join '; ') -Status 'Ready' -GraphSource $src | Out-Null
    }

    if ($withSession -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-03' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'sessionControls' -ObservedValue 'No CA policy at all uses session controls.' `
            -Status 'Review required' -ManualReview -GraphSource $src `
            -Recommendation ('No session controls are active. Consider sign-in frequency and persistent browser for sensitive apps, and token protection/CAE where the license permits.') | Out-Null
    }

    $resilienceOff = @($caPolicies | Where-Object {
            [bool](Get-CAInvProp $_ 'sessionControls.disableResilienceDefaults' $false)
        })

    if ($resilienceOff.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-05' -ObjectType 'Tenant' `
            -Property 'sessionControls.disableResilienceDefaults' `
            -ObservedValue "Not a single one of the $($caPolicies.Count) CA policies turns off resilience defaults." `
            -Status 'Ready' -GraphSource $src | Out-Null
    }
    else {
        foreach ($rp in $resilienceOff) {
            $scope = Get-CAInvPolicyUserScope -Policy $rp

            $advice = if ($scope.TargetsAllUsers) {
                'Turn resilience defaults back on unless there''s a documented reason to keep them off. They keep existing sessions working during an outage of the primary authentication service; the effect of turning them off cannot be tested in advance, since there''s no dry run via the Backup Authentication Service. Check afterward in the sign-in logs with the filter "Token issuer type == Microsoft Entra Backup Auth" whether the backup service was used.'
            }
            else {
                'This policy targets part of the tenant ({0}), but disabling resilience defaults reduces resilience for ALL users in the tenant, not just that target audience. Turn them back on unless there''s a documented reason to keep them off. The effect cannot be tested in advance, since there''s no dry run via the Backup Authentication Service. Check afterward in the sign-in logs with the filter "Token issuer type == Microsoft Entra Backup Auth" whether the backup service was used.' -f @($scope.Summary)
            }

            New-CAInvRecord -Domain $domain -CheckId 'Condition-05' -ObjectType 'ConditionalAccessPolicy' `
                -ObjectId (Get-CAInvProp $rp 'id') -ObjectName (Get-CAInvProp $rp 'displayName') `
                -Property 'sessionControls.disableResilienceDefaults' `
                -ObservedValue "disableResilienceDefaults=true; state: $(Get-CAInvProp $rp 'state' 'unknown'); target: $($scope.Summary)" `
                -Status 'Gap' -GraphSource $src -Recommendation $advice | Out-Null
        }
    }

    $betaPolicies = @(if ($ctx.PSObject.Properties.Name -contains 'CAPoliciesBeta') { @($ctx.CAPoliciesBeta) } else { @() })
    $betaError = if ($ctx.PSObject.Properties.Name -contains 'CAPoliciesBetaError') { [string]$ctx.CAPoliciesBetaError } else { '' }
    $caeSrc = 'GET /beta/identity/conditionalAccess/policies (sessionControls.continuousAccessEvaluation)'

    if ($betaPolicies.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($betaError)) {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-06' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'sessionControls.continuousAccessEvaluation.mode' -Status 'Not assessed' `
            -NotAssessedReason ('continuousAccessEvaluation only exists in the beta policy set, and it could not be retrieved: {0}' -f @($betaError)) `
            -ApiVersion 'beta' -GraphSource $caeSrc | Out-Null
    }
    else {
        $caeSeen = 0
        foreach ($bp in $betaPolicies) {
            $mode = [string](Get-CAInvProp $bp 'sessionControls.continuousAccessEvaluation.mode' '')
            if ([string]::IsNullOrWhiteSpace($mode)) { continue }
            $caeSeen++

            $pName = Get-CAInvProp $bp 'displayName'
            $policyId = Get-CAInvProp $bp 'id'
            $pState = [string](Get-CAInvProp $bp 'state' 'unknown')

            switch ($mode) {
                'disabled' {

                    New-CAInvRecord -Domain $domain -CheckId 'Condition-06' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $policyId -ObjectName $pName -Property 'sessionControls.continuousAccessEvaluation.mode' `
                        -ObservedValue "mode=disabled; state: $pState" -Status 'Review required' `
                        -ApiVersion 'beta' -GraphSource $caeSrc `
                        -Recommendation ('This policy turns off Continuous Access Evaluation. CAE is on by default and revokes a session almost immediately when an account is disabled, the password changes, or risk rises; without CAE, a token remains valid until it expires. Check whether there''s a documented reason behind this, e.g. an application that can''t tolerate mid-session revocation, and in that case limit the opt-out to that application.') | Out-Null
                }
                'strictLocation' {
                    New-CAInvRecord -Domain $domain -CheckId 'Condition-06' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $policyId -ObjectName $pName -Property 'sessionControls.continuousAccessEvaluation.mode' `
                        -ObservedValue "mode=strictLocation; state: $pState" -Status 'Review required' `
                        -ApiVersion 'beta' -GraphSource $caeSrc `
                        -Recommendation ('This policy enforces strict location enforcement. The risk is asymmetric: with shared or undeterminable egress, you lock out users who are actually coming from a trusted address, and you won''t notice until after enabling it. Walk through four conditions before this goes live. First, all authentication and resource traffic comes from known, owned egress addresses. Second, all those addresses are recorded as a named location. Third, non-Microsoft 365 apps don''t route through Global Secure Access. Fourth, validate this with the sign-in log field "IP address (seen by resource)", not with the address the client itself reports.') | Out-Null
                }
                'strictEnforcement' {
                    New-CAInvRecord -Domain $domain -CheckId 'Condition-06' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $policyId -ObjectName $pName -Property 'sessionControls.continuousAccessEvaluation.mode' `
                        -ObservedValue "mode=strictEnforcement; state: $pState" -Status 'Ready' `
                        -ApiVersion 'beta' -GraphSource $caeSrc | Out-Null
                }
                default {

                    New-CAInvRecord -Domain $domain -CheckId 'Condition-06' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $policyId -ObjectName $pName -Property 'sessionControls.continuousAccessEvaluation.mode' `
                        -Status 'Not assessed' `
                        -NotAssessedReason ('Unknown CAE mode ''{0}''; this module recognizes strictEnforcement, strictLocation, and disabled. The Prefer header for evolvable enum members is already being sent, so this points to a new value on Microsoft''s side.' -f @($mode)) `
                        -ApiVersion 'beta' -GraphSource $caeSrc | Out-Null
                }
            }
        }

        if ($caeSeen -eq 0) {

            New-CAInvRecord -Domain $domain -CheckId 'Condition-06' -ObjectType 'Tenant' `
                -Property 'sessionControls.continuousAccessEvaluation.mode' `
                -ObservedValue "None of the $($betaPolicies.Count) CA policies sets its own CAE mode; the tenant default applies." `
                -Status 'Ready' -ApiVersion 'beta' -GraphSource $caeSrc | Out-Null
        }
    }

    $tpProp = 'sessionControls.secureSignInSession.isEnabled'
    $v1Carries = @($caPolicies | Where-Object { $null -ne (Get-CAInvProp $_ 'sessionControls.secureSignInSession') }).Count -gt 0

    if ($v1Carries) {
        $tpSource = $caPolicies
        $tpApi = 'v1.0'
        $tpSrc = 'GET /identity/conditionalAccess/policies (sessionControls.secureSignInSession)'
    }
    elseif ($betaPolicies.Count -gt 0) {
        $tpSource = $betaPolicies
        $tpApi = 'beta'
        $tpSrc = 'GET /beta/identity/conditionalAccess/policies (sessionControls.secureSignInSession)'
    }
    elseif ($caPolicies.Count -eq 0 -and [string]::IsNullOrWhiteSpace($betaError)) {
        $tpSource = @()
        $tpApi = 'v1.0'
        $tpSrc = 'GET /identity/conditionalAccess/policies (sessionControls.secureSignInSession)'
    }
    else {

        $reason = if (-not [string]::IsNullOrWhiteSpace($betaError)) {
            'No v1.0 policy carries the secureSignInSession property, and the beta policy set could not be retrieved: {0}' -f @($betaError)
        }
        else {
            'No v1.0 policy carries the secureSignInSession property, and no beta policy set is available (layer 0 not run, or no beta access).'
        }
        New-CAInvRecord -Domain $domain -CheckId 'Condition-04' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'tokenProtection' -Status 'Not assessed' -NotAssessedReason $reason `
            -GraphSource 'GET /identity/conditionalAccess/policies (sessionControls.secureSignInSession)' | Out-Null
        Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$withSession CA policies with session controls."
        return
    }

    $tpPolicies = @($tpSource | Where-Object {
        $_.state -eq 'enabled' -and [bool](Get-CAInvProp $_ $tpProp $false)
    })
    if ($tpPolicies.Count -gt 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-04' -ObjectType 'ConditionalAccessPolicy' `
            -ObjectId (Get-CAInvProp $tpPolicies[0] 'id') -ObjectName (Get-CAInvProp $tpPolicies[0] 'displayName') -Property 'tokenProtection' `
            -ObservedValue "$($tpPolicies.Count) enabled policy(s) enforce Token Protection" `
            -Status 'Ready' -ApiVersion $tpApi -GraphSource $tpSrc | Out-Null
    }
    else {

        $disabledTp = @($tpSource | Where-Object {
            $_.state -ne 'enabled' -and [bool](Get-CAInvProp $_ $tpProp $false)
        })
        $observed = if ($disabledTp.Count -gt 0) {
            "No ENABLED CA policy enforces Token Protection. $($disabledTp.Count) non-enabled policy(s) do carry the control: $(@($disabledTp | ForEach-Object { Get-CAInvProp $_ 'displayName' }) -join ', ')."
        }
        else {
            'No enabled CA policy enforces Token Protection.'
        }
        $advice = if ($disabledTp.Count -gt 0) {
            'A Token Protection policy is already staged but not enabled. Finish the pilot and turn it on; first check report-only results over a period covering all clients in use, since there''s no exhaustive list of clients that cannot present a device-bound token.'
        }
        else {
            "Consider Token Protection for critical resources (Exchange Online, SharePoint Online, Teams) to limit token theft — Microsoft's own deployment guide recommends starting with privileged users on managed Windows devices."
        }
        New-CAInvRecord -Domain $domain -CheckId 'Condition-04' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'tokenProtection' -ObservedValue $observed `
            -Status 'Gap' -ApiVersion $tpApi -GraphSource $tpSrc `
            -Recommendation $advice | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$withSession CA policies with session controls."
}
