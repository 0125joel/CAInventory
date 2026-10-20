function Get-CAInvUserRegistrationDetail {
    <#
    .SYNOPSIS
        Domain 6.8 — User registration details (readiness report).
    .DESCRIPTION
        Layer 2 collector and the most important derived dataset in the script. Reads
        /reports/authenticationMethods/userRegistrationDetails (paginated) and enriches each row
        with its own computed fields:
          InAdminScope             - role holder according to the layer 1 role assignments (active
                                     AND PIM-eligible), with isAdmin from the report as fallback.
          AdminRoleNames           - the roles this user holds.
          InRecommendedAdminRoles  - falls within the fourteen roles for which Microsoft
                                     recommends phishing-resistant MFA (marker, not a filter).
          PasswordlessCapable      - isPasswordlessCapable from the report.
          PhishingResistantCapable - methodsRegistered contains FIDO2/Windows Hello/certificate.
          StrengthCapable          - MFA-capable (isMfaCapable) as a precondition for strong methods.
          NeedsManualReview        - MFA-capable but not registered, or an admin without a strong method.

        Use this as a readiness report, not as the sole source of truth (it
        includes reporting latency). The enriched set is kept on the context object
        (UserRegistrationDetails) so the method usage matrix reuses it at the end of the chain.

        Also generates Auth-13: checks each user's strongest
        registered method against a configurable minimum level from
        config/method-strength-map.json (SMS/voice < TAP < OTP < push < phishing-resistant). One
        aggregate record for the total, plus a Gap record per user below the minimum, split by
        recent sign-in activity via
        Split-CAInvUsersByActivity — same reasoning as Identity-02/Identity-04: a user who hasn't
        signed in for a long time won't get stuck once CA enforcement kicks in, and doesn't belong
        in the queue as a separately assessed migration risk. Unknown method types (not in the
        map) count as the weakest level and are logged separately, so a missing mapping never
        silently labels a user as 'strong enough'.

        Also stores per user which
        authentication strengths they satisfy: SatisfiedStrengths and UncertainStrengths, computed
        by Resolve-CAInvUserStrengthCoverage from the already-fetched AuthStrengths (Auth-04, runs
        before this in the same layer). No extra Graph call. Without AuthStrengths both lists stay
        empty and $ctx.StrengthCoverageKnown is $false, so the reporting layer can distinguish
        "not measured" from "satisfies no strength at all".

        Structural guest exclusion: Auth-11/002/003
        only count Member users. The raw evidence (Write-CAInvRaw) stays unfiltered — the evidence
        shows what Graph returned, only the analysis excludes guests. A missing/empty userType
        counts as Member: never silently drop a real Member due to a missing field.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.8'
    $src    = 'GET /reports/authenticationMethods/userRegistrationDetails'

    $resp = Invoke-CAInvGraphOrNotAssessed -Uri 'reports/authenticationMethods/userRegistrationDetails' -ApiVersion 'v1.0' -MaxPages 100 `
        -Domain $domain -CheckId 'Auth-11' -ObjectType 'Report' -Property 'userRegistrationDetails' `
        -GraphSource $src -NotAssessedReasonPrefix ('Could not read userRegistrationDetails')
    if ($resp.Failed) { return }

    $details = @($resp.Value)
    $raw = Write-CAInvRaw -Domain $domain -Endpoint 'userRegistrationDetails' -Data $details

    $beforeGuestFilter = $details.Count
    $details = @($details | Where-Object {
            $ut = Get-CAInvProp $_ 'userType' $null
            ([string]::IsNullOrWhiteSpace([string]$ut)) -or ($ut -eq 'Member')
        })
    $excludedGuests = $beforeGuestFilter - $details.Count
    if ($excludedGuests -gt 0) {
        Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$excludedGuests guest users excluded from Auth-11/002/003 (structural guest exclusion)."
    }

    if ($script:CAInvContext.PSObject.Properties.Name -contains 'SyncAccountIds') {
        $syncIds = @($script:CAInvContext.SyncAccountIds)
        if ($syncIds.Count -gt 0) {
            $beforeSyncFilter = $details.Count
            $details = @($details | Where-Object { $syncIds -notcontains [string](Get-CAInvProp $_ 'id' '') })
            $excludedSync = $beforeSyncFilter - $details.Count
            if ($excludedSync -gt 0) {
                Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$excludedSync sync account(s) excluded from Auth-11/002/003; those are assessed by Identity-05."
            }
        }
    }

    $privPrincipals = @(if ($script:CAInvContext.PSObject.Properties.Name -contains 'PrivilegedPrincipals') { @($script:CAInvContext.PrivilegedPrincipals) } else { @() })
    $rolesByPrincipal = @{}
    foreach ($pp in $privPrincipals) {
        $ppid = [string](Get-CAInvProp $pp 'principalId' '')
        if (-not $ppid) { continue }
        $roleName = [string](Get-CAInvProp $pp 'roleName' '')
        if (-not $rolesByPrincipal.ContainsKey($ppid)) { $rolesByPrincipal[$ppid] = [System.Collections.Generic.List[string]]::new() }
        if ($roleName -and -not $rolesByPrincipal[$ppid].Contains($roleName)) { [void]$rolesByPrincipal[$ppid].Add($roleName) }
    }
    $roleDataKnown = ($rolesByPrincipal.Count -gt 0)
    if (-not $roleDataKnown) {
        Write-CAInvLog -Level 'WARN' -Domain $domain -Message 'No role assignments available (layer 1 not run); Auth-12 falls back to the isAdmin field from the registration report, which may not count PIM-eligible assignments.'
    }

    $adminRoleConfig = $null
    if ($script:CAInvContext.PSObject.Properties['Config'] -and $script:CAInvContext.Config) {
        $cfg = $script:CAInvContext.Config
        $adminRoleConfig = if ($cfg -is [System.Collections.IDictionary]) {
            if ($cfg.Contains('AdminRoles')) { $cfg['AdminRoles'] } else { $null }
        }
        elseif ($cfg.PSObject.Properties['AdminRoles']) { $cfg.AdminRoles }
        else { $null }
    }
    $recommendedRoles = @(if ($adminRoleConfig) { @(Get-CAInvProp $adminRoleConfig 'phishingResistantRecommended' @()) } else { @() })

    $phishResistantMethods = @('fido2SecurityKey', 'windowsHelloForBusiness', 'passKeyDeviceBound',
        'passKeyDeviceBoundAuthenticator', 'certificateBasedAuthentication', 'x509CertificateSingleFactor',
        'x509CertificateMultiFactor')

    $strengthMap = $null
    if ($script:CAInvContext.PSObject.Properties['Config'] -and $script:CAInvContext.Config -and $script:CAInvContext.Config.MethodStrengthMap) {
        $strengthMap = $script:CAInvContext.Config.MethodStrengthMap
    }
    else {
        try { $strengthMap = (Get-CAInvConfig).MethodStrengthMap } catch { $strengthMap = $null }
    }
    $unknownWeight = if ($strengthMap -and ($null -ne $strengthMap.unknownWeight)) { [int]$strengthMap.unknownWeight } else { 0 }

    $autoMinimum = -not ($strengthMap -and ($null -ne $strengthMap.defaultMinimumWeight))
    $minWeight = if ($autoMinimum) { 0 } else { [int]$strengthMap.defaultMinimumWeight }
    $unknownMethodTypes = [System.Collections.Generic.HashSet[string]]::new()

    function Get-StrongestMethodWeight {
        param([string[]] $Methods, $StrengthMap, [int] $UnknownWeight, [System.Collections.Generic.HashSet[string]] $UnknownTracker)
        if (@($Methods).Count -eq 0) { return 0 }
        $best = 0
        foreach ($m in $Methods) {
            $w = $UnknownWeight
            $entry = if ($StrengthMap -and $StrengthMap.methods) { $StrengthMap.methods.PSObject.Properties[$m] } else { $null }
            if ($entry) { $w = [int]$entry.Value.weight } else { [void]$UnknownTracker.Add($m) }
            if ($w -gt $best) { $best = $w }
        }
        return $best
    }

    function Test-MethodSetBelowMfaStrength {

        param(
            [string[]] $Methods,
            $StrengthMap,
            [bool] $IsMfaRegistered,
            [System.Collections.Generic.HashSet[string]] $UnknownTracker
        )

        $hasMfaStrength = $false
        $hasUnresolved  = $false
        foreach ($m in @($Methods)) {
            $entry = if ($StrengthMap -and $StrengthMap.methods) { $StrengthMap.methods.PSObject.Properties[$m] } else { $null }
            if (-not $entry) {
                $hasUnresolved = $true
                [void]$UnknownTracker.Add($m)
                continue
            }
            $flagProp = $entry.Value.PSObject.Properties['mfaStrength']
            if (-not $flagProp -or $null -eq $flagProp.Value) { $hasUnresolved = $true; continue }
            if ([bool]$flagProp.Value) { $hasMfaStrength = $true }
        }

        if ($hasMfaStrength) { return $false }
        if ($hasUnresolved -and $IsMfaRegistered) { return $false }
        return $true
    }

    function Get-StrengthTierLabel {
        param([int] $Weight, $StrengthMap)
        if ($StrengthMap -and $StrengthMap.tiers) {
            $prop = $StrengthMap.tiers.PSObject.Properties["$Weight"]
            if ($prop) { return [string]$prop.Value }
        }
        return "Level $Weight"
    }

    $strengths = @(if ($script:CAInvContext.PSObject.Properties.Name -contains 'AuthStrengths') { @($script:CAInvContext.AuthStrengths) } else { @() })
    $strengthsKnown = $strengths.Count -gt 0

    $enriched = [System.Collections.Generic.List[object]]::new()
    foreach ($d in $details) {
        $methods = @(Get-CAInvProp $d 'methodsRegistered' @())
        $userId = [string](Get-CAInvProp $d 'id' '')
        $heldRoles = @(if ($rolesByPrincipal.ContainsKey($userId)) { @($rolesByPrincipal[$userId]) } else { @() })
        $isAdmin = if ($roleDataKnown) { $heldRoles.Count -gt 0 } else { [bool](Get-CAInvProp $d 'isAdmin' $false) }
        $inRecommended = ($recommendedRoles.Count -gt 0 -and @($heldRoles | Where-Object { $recommendedRoles -contains $_ }).Count -gt 0)
        $isMfaCapable = [bool](Get-CAInvProp $d 'isMfaCapable' $false)
        $isMfaRegistered = [bool](Get-CAInvProp $d 'isMfaRegistered' $false)
        $isPasswordless = [bool](Get-CAInvProp $d 'isPasswordlessCapable' $false)
        $phishResistant = [bool](@($methods | Where-Object { $phishResistantMethods -contains $_ }).Count)

        $needsReview = ($isMfaCapable -and -not $isMfaRegistered) -or ($isAdmin -and -not $phishResistant)

        $strongestWeight = Get-StrongestMethodWeight -Methods $methods -StrengthMap $strengthMap -UnknownWeight $unknownWeight -UnknownTracker $unknownMethodTypes
        $strongestLabel = Get-StrengthTierLabel -Weight $strongestWeight -StrengthMap $strengthMap
        $belowMinimum = if ($autoMinimum) {
            Test-MethodSetBelowMfaStrength -Methods $methods -StrengthMap $strengthMap `
                -IsMfaRegistered $isMfaRegistered -UnknownTracker $unknownMethodTypes
        }
        else { $strongestWeight -lt $minWeight }

        $coverage = if ($strengthsKnown) {
            Resolve-CAInvUserStrengthCoverage -MethodsRegistered $methods -Strengths $strengths `
                -StrengthMap $strengthMap -UnknownTracker $unknownMethodTypes
        }
        else { @{ Satisfied = @(); Uncertain = @() } }

        [void]$enriched.Add([PSCustomObject]@{
            UserId                   = Get-CAInvProp $d 'id'
            UserPrincipalName        = Get-CAInvProp $d 'userPrincipalName'
            UserType                 = Get-CAInvProp $d 'userType' 'unknown'
            MethodsRegistered        = $methods

            DefaultMfaMethod         = Get-CAInvProp $d 'userPreferredMethodForSecondaryAuthentication'
            InAdminScope             = $isAdmin
            AdminRoleNames           = $heldRoles
            InRecommendedAdminRoles  = $inRecommended
            StrengthCapable          = $isMfaCapable
            PasswordlessCapable      = $isPasswordless
            PhishingResistantCapable = $phishResistant
            IsMfaRegistered          = $isMfaRegistered
            NeedsManualReview        = $needsReview
            StrongestMethodWeight    = $strongestWeight
            StrongestMethodLabel     = $strongestLabel
            BelowMinimumStrength     = $belowMinimum
            SatisfiedStrengths       = @($coverage.Satisfied)
            UncertainStrengths       = @($coverage.Uncertain)
        })
    }

    Add-CAInvContextData -Context $script:CAInvContext -Name 'UserRegistrationDetails' -Value @($enriched)
    Add-CAInvContextData -Context $script:CAInvContext -Name 'StrengthCoverageKnown' -Value $strengthsKnown

    $total = $enriched.Count
    $mfaReg = @($enriched | Where-Object { $_.IsMfaRegistered }).Count
    $passwordless = @($enriched | Where-Object { $_.PasswordlessCapable }).Count
    $phish = @($enriched | Where-Object { $_.PhishingResistantCapable }).Count
    $reviewCount = @($enriched | Where-Object { $_.NeedsManualReview }).Count

    $urdCappedNote = if ($resp.Capped) { '; page limit reached (possibly incomplete)' } else { '' }
    New-CAInvRecord -Domain $domain -CheckId 'Auth-11' -ObjectType 'Report' `
        -Property 'registrationReadiness' `
        -ObservedValue "$total users; MFA-registered=$mfaReg; passwordless-capable=$passwordless; phishing-resistant=$phish; to-review=$reviewCount$urdCappedNote" `
        -Status 'Ready' -GraphSource $src -RawPath $raw `
        -Recommendation ('Use this as a readiness report, not as the sole source of truth: it includes reporting latency.') | Out-Null

    if ($reviewCount -gt 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-12' -ObjectType 'Report' `
            -Property 'needsManualReview' -ObservedValue "$reviewCount users are MFA-capable but not registered, or an admin without a phishing-resistant method." `
            -Status 'Review required' -ManualReview -GraphSource $src -RawPath $raw `
            -Recommendation ('Review these users before migration: an MFA-capable but unregistered user gets stuck once CA enforcement kicks in, and an admin without a strong method is elevated risk.') | Out-Null
    }
    else {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-12' -ObjectType 'Report' `
            -Property 'needsManualReview' -ObservedValue "0 users are MFA-capable but not registered, or an admin without a phishing-resistant method." `
            -Status 'Ready' -GraphSource $src -RawPath $raw | Out-Null
    }

    if (-not $strengthMap) {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-13' -ObjectType 'Report' `
            -Property 'methodStrengthMinimum' -Status 'Not assessed' `
            -NotAssessedReason ('config/method-strength-map.json is missing; the method minimum level could not be checked.') `
            -GraphSource $src | Out-Null
    }
    else {
        if ($unknownMethodTypes.Count -gt 0) {
            Write-CAInvLog -Level 'WARN' -Domain $domain -Message "Unknown method types without a weight in method-strength-map.json (counted as the weakest tier): $($unknownMethodTypes -join ', ')"
        }

        $belowMin = @($enriched | Where-Object { $_.BelowMinimumStrength })
        $minLabel = if ($autoMinimum) {
            'Multifactor authentication strength (Microsoft default)'
        }
        else { Get-StrengthTierLabel -Weight $minWeight -StrengthMap $strengthMap }

        $minRecommendation = if ($autoMinimum) {
            'No explicit weight floor is set, so the automatic floor applies: a user is below the minimum when none of their registered methods counts toward Microsoft''s built-in Multifactor authentication strength (source: learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths). These are therefore the users who cannot do MFA at all once enforcement kicks in. For a higher bar, set defaultMinimumWeight in config/method-strength-map.json to a weight (e.g. 3 for OTP and above, 5 for phishing-resistant).'
        }
        else {
            'Minimum level explicitly set to ''{0}'' (config/method-strength-map.json, defaultMinimumWeight={1}). Set that field to null to fall back to the automatic floor (methods that don''t count toward the MFA strength).' -f @($minLabel, $minWeight)
        }

        New-CAInvRecord -Domain $domain -CheckId 'Auth-13' -ObjectType 'Report' `
            -Property 'methodStrengthMinimum' `
            -ObservedValue "$($belowMin.Count) of $total users do not meet the minimum level ($minLabel)." `
            -Status 'Ready' -GraphSource $src -RawPath $raw `
            -Recommendation $minRecommendation | Out-Null

        $usersById = @{}
        if ($script:CAInvContext.PSObject.Properties.Name -contains 'Users') {
            foreach ($tu in @($script:CAInvContext.Users)) {
                $tuId = [string](Get-CAInvProp $tu 'id' '')
                if ($tuId) { $usersById[$tuId] = $tu }
            }
        }
        $belowMinWithActivity = @($belowMin | ForEach-Object {
            [PSCustomObject]@{ Original = $_; Upn = $_.UserPrincipalName; User = $usersById[[string]$_.UserId] }
        })
        $auth13Split = Split-CAInvUsersByActivity -Item $belowMinWithActivity

        foreach ($entry in $auth13Split.Active) {
            $u = $entry.Original
            New-CAInvRecord -Domain $domain -CheckId 'Auth-13' -ObjectType 'User' `
                -ObjectId $u.UserId -ObjectName $u.UserPrincipalName -Property 'strongestMethodBelowMinimum' `
                -ObservedValue "Strongest registered method: $($u.StrongestMethodLabel)." `
                -Status 'Gap' -GraphSource $src -RawPath $raw `
                -Recommendation $(if ($autoMinimum) {
                    'This user has no method at all that counts toward MFA. Have them register an MFA-worthy method (preferably phishing-resistant) before enforcement starts, or this user will get stuck immediately.'
                } else {
                    'Have this user register a method at or above ''{0}'' before enforcement starts for them.' -f @($minLabel)
                }) | Out-Null
        }

        if (-not $auth13Split.HasActivityData) {
            Write-CAInvLog -Level 'WARN' -Domain $domain -Message ("Auth-13: signInActivity missing for the entire population; {0} finding(s) not split by activity." -f $belowMin.Count)
        }
        elseif ($auth13Split.Dormant.Count -gt 0) {

            New-CAInvRecord -Domain $domain -CheckId 'Auth-13' -ObjectType 'Report' `
                -Property 'strongestMethodBelowMinimum (aggregate, dormant accounts)' `
                -ObservedValue (Get-CAInvDormantAggregateText -Dormant $auth13Split.Dormant -TotalCount $belowMin.Count `
                    -ActiveWithinDays $auth13Split.ActiveWithinDays -Subject 'users below the method minimum level') `
                -Status 'Gap' -GraphSource $src -RawPath $raw `
                -Recommendation ('These users are not a rollout priority: they''re not in use. Treat them as a cleanup action (disable, or have them register an MFA-worthy method after all) rather than reviewing them one by one. Review the {0} actually-active user(s) above separately.' -f @($auth13Split.Active.Count)) | Out-Null
        }
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$total registration profiles enriched ($reviewCount to review)."
}
