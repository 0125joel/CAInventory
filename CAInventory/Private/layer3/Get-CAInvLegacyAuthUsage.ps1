function Get-CAInvLegacyAuthUsage {
    <#
    .SYNOPSIS
        Domain 6.16 — Legacy authentication (usage).
    .DESCRIPTION
        Layer 3 collector. Configuration here is NOT the same as usage: a tenant allowing legacy
        protocols says nothing about whether they're being used, and vice versa.
        This collector therefore counts observed sign-ins with a legacy
        clientApp (IMAP/POP/SMTP/MAPI/ActiveSync/'Other clients') within the effective log
        window. What counts as legacy is in an explicit allowlist (Get-CAInvLegacyClientApp); an
        unknown or unrecognized clientApp does NOT count as legacy but is reported separately.

        Without sign-in data the status is explicitly Not assessed and NEVER Ready: an empty
        observation is not proof that legacy auth isn't used. The collector always includes the
        window it used.

        If this collector finds legacy usage (Gap), it calls Get-CAInvLegacyAuthUsageKql for a
        user/app/device-type breakdown via Log Analytics. Without
        Azure context/workspace, nothing happens there — the Condition-09 conclusion itself stays
        unchanged, the drilldown (Condition-11) is purely supplementary evidence.

        Condition-10 gates on CAPoliciesFetchFailed, not on an empty policy set: a confirmed zero
        CA policies falls through to the existing "no blocking policy found" branch, which is
        already Gap. Only a failed fetch is Not assessed.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.16'
    $src    = 'GET /auditLogs/signIns (clientAppUsed legacy)'

    $data = Get-CAInvSignInData
    $window = $data.Window
    if ($data.Failed) {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-09' -ObjectType 'SignIn' `
            -Property 'legacyAuthUsage' -Status 'Not assessed' `
            -NotAssessedReason ('No sign-in data available (could not read /auditLogs/signIns: {0}); legacy auth usage was not measured. Window={1} d.' -f @($data.ErrorMessage, $window)) `
            -GraphSource $src | Out-Null
        return
    }
    $signIns = @($data.SignIns)

    $legacy = [System.Collections.Generic.List[object]]::new()
    $blockedByCa = [System.Collections.Generic.List[object]]::new()
    $unknownCount = 0
    $unknownClients = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $signIns) {
        $raw = "$(Get-CAInvProp $s 'clientAppUsed')".Trim()
        switch (Get-CAInvClientAppClass -ClientAppUsed $raw) {
            'legacy' {
                $errorCode = [int](Get-CAInvProp $s 'status.errorCode' 0)
                if ($errorCode -eq 0) { $legacy.Add($s) }
                elseif ($errorCode -eq 53003) { [void]$blockedByCa.Add($s) }

            }
            'unknown' {
                $unknownCount++
                if (-not [string]::IsNullOrWhiteSpace($raw)) { [void]$unknownClients.Add($raw) }
            }
        }
    }

    $byUser = @($legacy | ForEach-Object { Get-CAInvProp $_ 'userPrincipalName' } | Where-Object { $_ } | Select-Object -Unique)

    $blockedNote = if ($blockedByCa.Count -gt 0) {
        " In addition, $($blockedByCa.Count) attempt(s) with a legacy client were correctly blocked by Conditional Access."
    } else { '' }
    $unknownNote = if ($unknownCount -gt 0) {
        $names = @($unknownClients | Sort-Object) -join ', '
        $namesPart = if ($names) { " Values: $names." } else { ' Values: empty.' }
        " In addition, $unknownCount sign-in(s) with an unknown or unrecognized clientApp; those don't count as legacy.$namesPart"
    } else { '' }

    New-CAInvRecord -Domain $domain -CheckId 'Condition-09' -ObjectType 'SignIn' `
        -Property 'legacyAuthUsage' `
        -ObservedValue "$($legacy.Count) legacy sign-ins by $($byUser.Count) users in the window of $window days.$blockedNote$unknownNote" `
        -Status ($(if ($legacy.Count -gt 0) { 'Gap' } else { 'Review required' })) `
        -ManualReview:($legacy.Count -eq 0) -GraphSource $src -RawPath $data.RawPath `
        -Recommendation ($(if ($legacy.Count -gt 0) {
            'Active legacy auth usage detected. Legacy protocols bypass MFA and CA. Block them with a CA policy once the affected users/apps have been migrated.'
        } else {
            ('No legacy sign-ins observed in the window; that''s an indicator, not proof. Confirm before blocking legacy auth.') +
            $(if ($unknownCount -gt 0) { ' Note: there are sign-ins with an unknown clientApp; these say nothing about the protocol used and were not counted as legacy.' } else { '' })
        })) | Out-Null

    if ($legacy.Count -gt 0) {
        Get-CAInvLegacyAuthUsageKql
    }

    $caPolicies = @(Get-CAInvCaPolicy)
    if ($caPolicies.Count -eq 0 -and [bool](Get-CAInvProp $script:CAInvContext 'CAPoliciesFetchFailed' $true)) {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-10' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'legacyAuthBlockingPolicy' -Status 'Not assessed' `
            -NotAssessedReason ('CA policies not available (layer 0 not run, or not readable).') `
 | Out-Null
    }
    else {

        $blockingPolicy = @($caPolicies | Where-Object {
            $_.state -eq 'enabled' -and
            (Get-CAInvPolicyUserScope -Policy $_).TargetsAllUsers -and
            @(@(Get-CAInvProp $_ 'conditions.clientAppTypes' @()) | Where-Object { $_ -in @('exchangeActiveSync', 'other') }).Count -gt 0 -and
            (@(Get-CAInvProp $_ 'grantControls.builtInControls' @()) -contains 'block')
        }) | Select-Object -First 1
        if ($blockingPolicy -and $legacy.Count -gt 0) {
            New-CAInvRecord -Domain $domain -CheckId 'Condition-10' -ObjectType 'ConditionalAccessPolicy' `
                -ObjectId $blockingPolicy.id -ObjectName $blockingPolicy.displayName -Property 'legacyAuthBlockingPolicy' `
                -ObservedValue "There is an enabled, tenant-wide blocking policy ('$($blockingPolicy.displayName)'), but $($legacy.Count) legacy sign-in(s) in the window of $window days still succeeded (see Condition-09)." `
                -Status 'Review required' -ManualReview `
                -Recommendation ('The policy exists and is scoped tenant-wide, but demonstrably doesn''t cover this traffic. Check app exceptions, named-location exclusions, and whether the sign-ins predate the policy''s enablement.') | Out-Null
        }
        elseif ($blockingPolicy) {
            New-CAInvRecord -Domain $domain -CheckId 'Condition-10' -ObjectType 'ConditionalAccessPolicy' `
                -ObjectId $blockingPolicy.id -ObjectName $blockingPolicy.displayName -Property 'legacyAuthBlockingPolicy' `
                -ObservedValue 'Enabled, tenant-wide policy blocks legacy authentication.' `
                -Status 'Ready' | Out-Null
        }
        else {
            New-CAInvRecord -Domain $domain -CheckId 'Condition-10' -ObjectType 'ConditionalAccessPolicy' `
                -Property 'legacyAuthBlockingPolicy' -ObservedValue 'No enabled, tenant-wide CA policy blocks legacy authentication (exchangeActiveSync/other).' `
                -Status 'Gap' `
                -Recommendation ('Set up a CA policy that blocks legacy authentication. Legacy protocols bypass MFA entirely, regardless of whether usage is currently observed (see Condition-09).') | Out-Null
        }
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($legacy.Count) legacy sign-ins observed, $unknownCount with unknown clientApp (window $window d)."
}
