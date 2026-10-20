function Get-CAInvMethodUsageMatrix {
    <#
    .SYNOPSIS
        Domain 6.5/6.6/6.8/6.23 — Method matrix: allowed, registered, eligible, used.
    .DESCRIPTION
        Supplementary function of layer 2. Collects NO new data itself,
        but combines four already-fetched sources into one row per method:
          - AuthMethodPolicy        (6.5, 'allowed')     -> EnabledInPolicy, targeting.
          - AuthStrengths           (6.6, 'eligible')    -> StrengthEligible.
          - UserRegistrationDetails (6.8, 'registered')  -> RegisteredUserCount, DefaultMethodCount.
          - SignIns                 (6.23, 'used')       -> ObservedSignInsLastNDays, LastObservedUse.

        Because the usage axis depends on layer 6, Invoke-CAInventory calls this function only at
        the END of the chain. Two fixed findings:
          Auth-05 is an inventory record (always Ready, Info): it records the four axes per method
          and passes no judgment of its own. If sign-ins are missing, that shows as 'Not assessed'
          in the usage axis of the ObservedValue and never as 0. The record used to go to 'Review
          required' + ManualReview in that case, but that filled the review queue with items
          carrying no decidable question: a human can't supply the missing sign-in data by pressing
          a button. The judgment lives in Auth-06 and Auth-07, and those require sign-in data, so
          they naturally stay away when it isn't there.

          Auth-06  Method on+registered but no observed usage within the window -> phase-out
                   candidate, low severity, always Review required.
          All three carry a caveat when Auth-02 reports that the migration to the authentication
          methods policy isn't complete yet: then the legacy MFA and SSPR settings still apply and
          this matrix doesn't measure the full picture.

          Auth-07  Method with demonstrable usage that is NOT in the allowedCombinations of a used
                   strength -> migration risk, high severity (Gap).

        Unconditional rule: not measured is not not-used. If the sign-in data is missing, the usage
        columns get Not assessed and NEVER the value zero, and the matrix record itself goes to
        Review required instead of Ready (0.38.0): a matrix a quarter of which is unmeasured
        shouldn't count toward the score.

        Usage axis: reads aggregated per-method counts
        (SignInData.MethodUsage, hashtable MethodId -> @{Count; LastUse}), not a raw sign-in array.
        With -SkipAzure or without a found Log Analytics workspace, MethodUsage stays empty and so
        the usage axis stays Not assessed (Graph-only structurally cannot provide this); with an
        Azure context, Get-CAInvSignInUsageKql fills these counts via a KQL query.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.5 / 6.6 / 6.8 / 6.23'
    $src    = 'Aggregatie: authenticationMethodsPolicy + authenticationStrengths + userRegistrationDetails + signIns'

    $ctx = $script:CAInvContext
    $policy    = @(if ($ctx.PSObject.Properties.Name -contains 'AuthMethodPolicy') { @($ctx.AuthMethodPolicy) } else { @() })
    $strengths = @(if ($ctx.PSObject.Properties.Name -contains 'AuthStrengths') { @($ctx.AuthStrengths) } else { @() })
    $regDetails = @(if ($ctx.PSObject.Properties.Name -contains 'UserRegistrationDetails') { @($ctx.UserRegistrationDetails) } else { @() })

    $modeMap = if ($ctx.PSObject.Properties['Config'] -and $ctx.Config -and $ctx.Config.PolicyMethodModeMap) {
        $ctx.Config.PolicyMethodModeMap
    }
    else {
        try { (Get-CAInvConfig).PolicyMethodModeMap } catch { $null }
    }
    $methodModes = if ($modeMap -and $modeMap.methodModes) { $modeMap.methodModes } else { $null }

    $signInData = if ($ctx.PSObject.Properties.Name -contains 'SignInData') { $ctx.SignInData } else { $null }
    $signInsAvailable = [bool]($signInData -and $signInData.HasAuthDetails)
    $methodUsage = if ($signInsAvailable) { Get-CAInvProp $signInData 'MethodUsage' @{} } else { @{} }

    $migrationState = if ($ctx.PSObject.Properties.Name -contains 'AuthMethodPolicyMigrationState') { $ctx.AuthMethodPolicyMigrationState } else { $null }
    $migrationIncomplete = ($null -ne $migrationState -and "$migrationState".Trim().ToLowerInvariant() -ne 'migrationcomplete')
    $migrationNote = if ($migrationIncomplete) {
        " NOTE: the authentication methods policy is at '$migrationState' and therefore isn't solely authoritative yet; the legacy MFA and SSPR settings still count too (see Auth-02)."
    }
    else { '' }

    if ($policy.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-05' -ObjectType 'AuthenticationMethod' `
            -Property 'methodUsageMatrix' -Status 'Not assessed' `
            -NotAssessedReason ('Authentication methods policy not available (6.5 not run, or not readable); matrix cannot be built.') `
            -GraphSource $src | Out-Null
        return
    }

    $allCombos = @($strengths | ForEach-Object { Get-CAInvProp $_ 'allowedCombinations' @() } | ForEach-Object { $_ })

    $window = Get-CAInvEffectiveLookbackWindow

    foreach ($m in $policy) {
        $methodId = $m.MethodId
        $enabled  = [bool]$m.EnabledInPolicy

        $registered = @($regDetails | Where-Object {
            @($_.MethodsRegistered) | Where-Object { "$_" -match [regex]::Escape($methodId) }
        }).Count
        $defaultCount = @($regDetails | Where-Object { "$($_.DefaultMfaMethod)" -match [regex]::Escape($methodId) }).Count

        $modeEntry = if ($methodModes) { $methodModes.PSObject.Properties[$methodId] } else { $null }
        $modesKnown = [bool]$modeEntry
        $methodModeList = if ($modeEntry) { @($modeEntry.Value) } else { @() }
        $strengthEligible = $false
        foreach ($combo in $allCombos) {
            $atoms = @("$combo".Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if (@($atoms | Where-Object { $methodModeList -contains $_ }).Count -gt 0) { $strengthEligible = $true; break }
        }
        $modeNote = if (-not $modesKnown) { " (methodId unknown in the mode translation table; strengthEligible cannot be determined)" } else { '' }

        if ($signInsAvailable) {
            $u = $methodUsage[$methodId]
            $observedCount = if ($u) { [int]$u.Count } else { 0 }
            $lastUse = if ($u) { $u.LastUse } else { $null }
            $usageText = "observed=$observedCount; last=$($lastUse)"
        }
        else {
            $observedCount = $null
            $usageText = 'usage Not assessed (no sign-in data; not measured is not not-used)'
        }

        $matrixStatus = if ($signInsAvailable) { 'Ready' } else { 'Review required' }
        $matrixAdvice = if ($signInsAvailable) { '' } else {
            'The usage axis is missing: without observed usage there''s no way to tell whether this method will be missed if you turn it off. Run again with an Azure context (without -SkipAzure) and Log Analytics Reader on the workspace, or confirm manually.'
        }

        New-CAInvRecord -Domain $domain -CheckId 'Auth-05' -ObjectType 'AuthenticationMethod' `
            -ObjectName $methodId -Property 'methodUsageMatrix' `
            -ObservedValue "enabled=$enabled; registered=$registered; default=$defaultCount; strengthEligible=$strengthEligible$modeNote; $usageText (window $window d).$migrationNote" `
            -Status $matrixStatus -GraphSource $src `
            -Recommendation $matrixAdvice | Out-Null

        if ($signInsAvailable -and $enabled -and $registered -gt 0 -and $observedCount -eq 0) {
            New-CAInvRecord -Domain $domain -CheckId 'Auth-06' -ObjectType 'AuthenticationMethod' `
                -ObjectName $methodId -Property 'phaseOutCandidate' `
                -ObservedValue "enabled and registered by $registered users, but no observed usage in the window of $window days." `
                -Status 'Review required' -ManualReview -GraphSource $src `
                -Recommendation (('Possibly a candidate for phase-out. Confirm first: a long tail of occasional usage can fall outside the measured window.') + $(if ($migrationIncomplete) { ' Don''t turn off the method before the migration to the authentication methods policy is complete: as long as the legacy policies still count, turning it off here doesn''t determine whether the method actually disappears (see Auth-02).' } else { '' })) | Out-Null
        }

        if ($signInsAvailable -and $observedCount -gt 0 -and -not $strengthEligible -and $strengths.Count -gt 0) {
            New-CAInvRecord -Domain $domain -CheckId 'Auth-07' -ObjectType 'AuthenticationMethod' `
                -ObjectName $methodId -Property 'usedButNotStrengthEligible' `
                -ObservedValue "$observedCount observed sign-in(s) with this method, but the method is not in any allowedCombination of the present strengths." `
                -Status 'Gap' -GraphSource $src `
                -Recommendation (('Migration risk: users relying on this method lose their working sign-in method once the strength is enabled. Plan a registration path to an allowed strong method before switching over.') + $(if ($migrationIncomplete) { ' Keep in mind that the authentication methods policy isn''t authoritative yet; also check the legacy MFA and SSPR policy before drawing conclusions about what a user can still use (see Auth-02).' } else { '' })) | Out-Null
        }
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Method matrix built over $($policy.Count) methods (usage data available=$signInsAvailable)."
}
