function Get-CAInvIdentityProtection {
    <#
    .SYNOPSIS
        Domain 6.22 — Identity Protection.
    .DESCRIPTION
        Layer 6 collector. Reads riskyUsers and riskDetections and summarizes the current risk
        picture. Identity Protection is the source that risk-based CA policies (sign-in risk, user
        risk) rely on; without P2 those signals don't exist and every risk-based control is
        meaningless. This function requires Entra ID P2: without that license, riskyUsers/
        riskDetections go Not assessed. The requirement is set as
        `licenseRequirement` on Evidence-07/Evidence-08 in `config/checkids.json` and enforced by
        Test-CAInvLicensePrecondition. Evidence-09 is deliberately EXCLUDED from that: it only reads
        CA policy conditions, and precisely without P2 a missing risk policy is a genuine Gap
        rather than something unmeasurable. Fails soft on missing permissions.

        Evidence-09 distinguishes a failed CA policy fetch (Not assessed, via
        CAPoliciesFetchFailed on the context) from a confirmed empty policy set (Gap: zero
        policies cannot respond to risk, that's a real finding, not a missing measurement).
    #>
    [CmdletBinding()]
    param()

    $domain = '6.22'
    $src    = 'GET /identityProtection/riskyUsers; GET /identityProtection/riskDetections'

    $caPolicies = @(Get-CAInvCaPolicy)
    if ($caPolicies.Count -eq 0) {
        $fetchFailed = [bool](Get-CAInvProp $script:CAInvContext 'CAPoliciesFetchFailed' $true)
        if ($fetchFailed) {
            New-CAInvRecord -Domain $domain -CheckId 'Evidence-09' -ObjectType 'ConditionalAccessPolicy' `
                -Property 'riskBasedPolicy' -Status 'Not assessed' `
                -NotAssessedReason ('CA policies not available (layer 0 not run, or not readable).') | Out-Null
        }
        else {
            New-CAInvRecord -Domain $domain -CheckId 'Evidence-09' -ObjectType 'ConditionalAccessPolicy' `
                -Property 'riskBasedPolicy' -ObservedValue 'No CA policies exist in this tenant.' `
                -Status 'Gap' `
                -Recommendation ('Set up a risk-based CA policy (e.g. "require MFA for risky sign-in"). With zero CA policies, nothing can respond to risk.') | Out-Null
        }
    }
    else {
        $riskPolicy = @($caPolicies | Where-Object {
            $_.state -eq 'enabled' -and (
                @(Get-CAInvProp $_ 'conditions.signInRiskLevels' @()).Count -gt 0 -or
                @(Get-CAInvProp $_ 'conditions.userRiskLevels' @()).Count -gt 0
            )
        }) | Select-Object -First 1
        if ($riskPolicy) {
            New-CAInvRecord -Domain $domain -CheckId 'Evidence-09' -ObjectType 'ConditionalAccessPolicy' `
                -ObjectId $riskPolicy.id -ObjectName $riskPolicy.displayName -Property 'riskBasedPolicy' `
                -ObservedValue 'Enabled CA policy responds to sign-in risk and/or user risk.' `
                -Status 'Ready' | Out-Null
        }
        else {
            New-CAInvRecord -Domain $domain -CheckId 'Evidence-09' -ObjectType 'ConditionalAccessPolicy' `
                -Property 'riskBasedPolicy' -ObservedValue 'No enabled CA policy responds to sign-in/user risk.' `
                -Status 'Gap' `
                -Recommendation ('Set up a risk-based CA policy (e.g. "require MFA for risky sign-in"). Risk detection without a policy that acts on it changes nothing about the actual risk.') | Out-Null
        }
    }

    $riskyUsersLicensed = Test-CAInvLicensePrecondition -CheckId 'Evidence-07' -Domain $domain `
        -ObjectType 'RiskyUser' -Property 'identityProtection' -GraphSource $src `
        -Consequence ('Risk-based CA controls cannot be enforced without this license.')
    $detectionsLicensed = Test-CAInvLicensePrecondition -CheckId 'Evidence-08' -Domain $domain `
        -ObjectType 'RiskDetection' -Property 'riskDetections' -GraphSource $src `
        -Consequence ('Without this license, Graph doesn''t return risk detections.')
    if (-not $riskyUsersLicensed -or -not $detectionsLicensed) { return }

    $ruResp = Invoke-CAInvGraphOrNotAssessed -Uri 'identityProtection/riskyUsers' -ApiVersion 'v1.0' `
        -Domain $domain -CheckId 'Evidence-07' -ObjectType 'RiskyUser' -Property 'riskyUsers' `
        -GraphSource 'GET /identityProtection/riskyUsers' -NotAssessedReasonPrefix ('Could not read riskyUsers')
    if (-not $ruResp.Failed) {
        $risky = @($ruResp.Value | Where-Object { (Get-CAInvProp $_ 'riskState' 'none') -notin @('none', 'dismissed', 'remediated') })
        Write-CAInvRaw -Domain $domain -Endpoint 'riskyUsers' -Data $risky | Out-Null
        New-CAInvRecord -Domain $domain -CheckId 'Evidence-07' -ObjectType 'RiskyUser' `
            -Property 'riskyUsers' -ObservedValue "$($risky.Count) users with active risk" `
            -Status ($(if ($risky.Count -gt 0) { 'Review required' } else { 'Ready' })) `
            -ManualReview:($risky.Count -gt 0) `
            -GraphSource 'GET /identityProtection/riskyUsers' `
            -Recommendation ($(if ($risky.Count -gt 0) { 'Investigate the risky users and confirm that risk-based CA policies (user risk) are active to catch them.' } else { $null })) | Out-Null
    }

    $window = Get-CAInvEffectiveLookbackWindow
    $since = ([DateTimeOffset]::UtcNow.AddDays(-$window)).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $rdMaxPages = 20
    $rdResp = Invoke-CAInvGraph -Uri "identityProtection/riskDetections?`$filter=detectedDateTime ge $since" -ApiVersion 'v1.0' -MaxPages $rdMaxPages
    if (-not $rdResp.Failed) {
        $detections = @($rdResp.Value)
        $rdCappedNote = if ($detections.Count -ge ($rdMaxPages * 100)) { " (paging limit reached; possibly incomplete within the window)" } else { '' }
        New-CAInvRecord -Domain $domain -CheckId 'Evidence-08' -ObjectType 'RiskDetection' `
            -Property 'riskDetections' -ObservedValue "$($detections.Count) risicodetecties in $window d$rdCappedNote" `
            -Status 'Ready' -GraphSource 'GET /identityProtection/riskDetections' | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message 'Identity Protection assessed.'
}
