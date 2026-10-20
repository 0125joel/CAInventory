function Get-CAInvEmergencyAccess {
    <#
    .SYNOPSIS
        Domain 6.4 — Emergency access and break-glass. Heaviest function of layer 1.
    .DESCRIPTION
        Deliberately reads across layer boundaries (users, roles, CA policies) to determine
        break-glass readiness. A hard verdict is allowed on: number of accounts,
        accountEnabled, cloud-only vs synced, UPN on the .onmicrosoft.com domain, Global Admin
        assignment, explicit CA exclusion, and a recent test sign-in. Credential storage, PAW
        usage, physical access, and the emergency procedure remain 'Review required'. The check
        against registration-campaign targeting (Emergency-04) measures via the shared helper
        whether the account falls within the campaign scope, with the campaign's direct-members
        semantics: an exclusion via a nested group doesn't work and yields a Gap.

        Emergency-09 (UPN domain) runs on the same population as Emergency-02 through 08 (heuristic
        or explicit), with -ManualReview:(-not $explicit): on a name-pattern match the verdict
        stays visible but needs confirmation, on an explicitly supplied account it's a hard verdict.
        Same pattern as Emergency-01's own ManualReview logic.

        Identification of break-glass accounts: cloud-only users with permanent Global
        Administrator OR a name pattern (breakglass/emergency/bg-). Supply -EmergencyAccountUpn
        explicitly when the accounts have a non-matching name.
    #>
    [CmdletBinding()]
    param(
        [string[]] $EmergencyAccountUpn,
        [string[]] $EmergencyAccountId
    )

    $domain = '6.4'
    $src    = 'GET /users; /roleManagement; /identity/conditionalAccess/policies; /users/{id}/authentication/methods'

    $ctx = $script:CAInvContext

    if (-not $EmergencyAccountUpn -and $ctx.PSObject.Properties['EmergencyAccountUpn'] -and $ctx.EmergencyAccountUpn) {
        $EmergencyAccountUpn = @($ctx.EmergencyAccountUpn)
    }
    if (-not $EmergencyAccountId -and $ctx.PSObject.Properties['EmergencyAccountId'] -and $ctx.EmergencyAccountId) {
        $EmergencyAccountId = @($ctx.EmergencyAccountId)
    }

    $users = if ($ctx.PSObject.Properties.Name -contains 'Users') { $ctx.Users } else { @() }
    $privileged = if ($ctx.PSObject.Properties.Name -contains 'PrivilegedPrincipals') { $ctx.PrivilegedPrincipals } else { @() }
    $policies = @(Get-CAInvCaPolicy)

    $gaAll = @(Get-CAInvGlobalAdminPrincipal -Principal $privileged)

    $gaPermanentIds = @($gaAll | Where-Object { Test-CAInvPermanentAssignment $_ } | ForEach-Object { $_.principalId })
    $gaTimeBound = @($gaAll | Where-Object {
            (Get-CAInvProp $_ 'assignmentType' '') -eq 'Assigned' -and
            -not [string]::IsNullOrEmpty((Get-CAInvProp $_ 'endDateTime' ''))
        })
    $gaTimeBoundIds = @($gaTimeBound | ForEach-Object { $_.principalId })

    $namePattern = '(?i)\b(break[-_ ]?glass|emergency|noodaccount|noodtoegang|bg-|breakglass)\b'
    $confirmed = @($users | Where-Object {
        ($EmergencyAccountUpn -and ($EmergencyAccountUpn -contains $_.userPrincipalName)) -or
        ($EmergencyAccountId -and ($EmergencyAccountId -contains $_.id)) -or
        ("$($_.userPrincipalName) $($_.displayName)" -match $namePattern)
    })
    $confirmedIds = @($confirmed | ForEach-Object { $_.id })
    $shortlist = @($users | Where-Object {
        ($gaPermanentIds -contains $_.id) -and ($_.onPremisesSyncEnabled -ne $true) -and ($confirmedIds -notcontains $_.id)
    })

    $explicit = ($EmergencyAccountUpn -or $EmergencyAccountId)
    $idBasis = if ($explicit) { 'explicitly provided (-EmergencyAccountUpn/-EmergencyAccountId)' } else { 'recognized by name pattern' }

    $countStatus = if ($confirmed.Count -ge 2) { 'Ready' } else { 'Gap' }
    New-CAInvRecord -Domain $domain -CheckId 'Emergency-01' -ObjectType 'EmergencyAccess' `
        -Property 'accountCount (confirmed)' -ObservedValue "$($confirmed.Count) ($idBasis)" -Status $countStatus `
        -GraphSource $src `
        -ManualReview:(-not $explicit) `
        -Recommendation ('Microsoft recommends at least two cloud-only break-glass accounts. Confirm the set with -EmergencyAccountUpn for a definitive verdict.') | Out-Null

    if ($shortlist.Count -gt 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Emergency-01' -ObjectType 'EmergencyAccess' `
            -Property 'possibleCandidates' `
            -ObservedValue (($shortlist | ForEach-Object { $_.userPrincipalName }) -join ', ') `
            -Status 'Review required' -ManualReview -GraphSource $src `
            -Recommendation ('Cloud-only accounts with permanent Global Admin. These may be emergency accounts or regular admin/service accounts; confirm which are break-glass via -EmergencyAccountUpn.') | Out-Null
    }

    $timeBound = @($users | Where-Object {
        ($gaTimeBoundIds -contains $_.id) -and ($_.onPremisesSyncEnabled -ne $true)
    })
    if ($timeBound.Count -gt 0) {
        $tbList = @(foreach ($u in $timeBound) {
            $inst = @($gaTimeBound | Where-Object { $_.principalId -eq $u.id }) | Select-Object -First 1
            "$($u.userPrincipalName) (until $(if ($inst) { $inst.endDateTime } else { 'unknown' }))"
        }) -join ', '
        New-CAInvRecord -Domain $domain -CheckId 'Emergency-01' -ObjectType 'EmergencyAccess' `
            -Property 'timeBoundGaAssignment' -ObservedValue $tbList `
            -Status 'Review required' -ManualReview -GraphSource $src `
            -Recommendation ('Cloud-only accounts with a Global Admin role that expires on an end date. These don''t count as permanent Global Admin and therefore don''t appear in the candidate list above. If one of these accounts is actually your emergency account, make the assignment permanent: emergency access that expires on its own isn''t emergency access.') | Out-Null
    }

    Add-CAInvContextData -Context $script:CAInvContext -Name 'EmergencyAccountsConfirmed' -Value @($confirmed)

    $fd10Src = 'GET /identity/conditionalAccess/policies (displayName classification) x confirmed emergency accounts'
    $managedPolicies = @(foreach ($p in $policies) {
        $origin = Get-CAInvPolicyManagedOrigin -Policy $p
        if ($origin.IsVendorManaged) { [PSCustomObject]@{ Policy = $p; Origin = $origin } }
    })
    foreach ($entry in $managedPolicies) {
        $mp = $entry.Policy
        $mpOrigin = $entry.Origin
        $mpName = [string](Get-CAInvProp $mp 'displayName' '')
        $mpOriginLabel = if ($mpOrigin.Origin -eq 'microsoftManaged') { 'Microsoft-managed' } else { 'Baseline security mode' }

        if (-not (Test-CAInvPolicyRestrictsSignIn -Policy $mp)) { continue }

        if ($confirmed.Count -eq 0) {
            New-CAInvRecord -Domain $domain -CheckId 'Foundation-10' -ObjectType 'ConditionalAccessPolicy' `
                -ObjectId (Get-CAInvProp $mp 'id') -ObjectName $mpName -Property "$mpOriginLabel; break-glass exclusion" `
                -ObservedValue "$mpOriginLabel, state on. There are no confirmed emergency accounts to check against (see Emergency-01)." `
                -Status 'Review required' -ManualReview -GraphSource $fd10Src `
                -Recommendation ('Confirm the emergency accounts (-EmergencyAccountUpn) for a definitive verdict on their exclusion from this policy.') | Out-Null
            continue
        }

        $notExcludedNames = [System.Collections.Generic.List[string]]::new()
        $anyUncertain = $false
        foreach ($u in $confirmed) {
            $ex = Test-CAInvUserExcludedFromPolicy -Policy $mp -UserId $u.id
            if (-not $ex.Excluded) {
                [void]$notExcludedNames.Add($u.userPrincipalName)
                if ($ex.Certainty -ne 'high') { $anyUncertain = $true }
            }
        }
        $fd10Status = if ($notExcludedNames.Count -eq 0) { 'Ready' } elseif ($anyUncertain) { 'Review required' } else { 'Gap' }
        New-CAInvRecord -Domain $domain -CheckId 'Foundation-10' -ObjectType 'ConditionalAccessPolicy' `
            -ObjectId (Get-CAInvProp $mp 'id') -ObjectName $mpName -Property "$mpOriginLabel; break-glass exclusion" `
            -ObservedValue ($(if ($notExcludedNames.Count -eq 0) {
                "$mpOriginLabel, state on. All confirmed emergency accounts are excluded."
            } else {
                "$mpOriginLabel, state on. Not excluded: $($notExcludedNames -join ', ')."
            })) `
            -Status $fd10Status -GraphSource $fd10Src -ManualReview:$anyUncertain `
            -Recommendation ('Exclude the emergency accounts from this policy, just as you would in your own policies. Microsoft recommends a separate security group for this, e.g. EmergencyAccess. You can adjust a managed policy''s state and exclusions; renaming or deleting it is not possible.') | Out-Null
    }

    if ($confirmed.Count -eq 0) {

        New-CAInvRecord -Domain $domain -CheckId 'Emergency-01' -ObjectType 'EmergencyAccess' `
            -Property 'identification' -Status 'Review required' -ManualReview `
            -ObservedValue 'No confirmed break-glass accounts (no -EmergencyAccountUpn and no name-pattern match).' `
            -Recommendation ('Provide the emergency accounts explicitly with -EmergencyAccountUpn; that yields the full verdict (cloud-only, CA exclusion, recent test).') | Out-Null
        return
    }

    $candidates = $confirmed

    $raw = Write-CAInvRaw -Domain $domain -Endpoint 'emergencyAccessCandidates' -Data $candidates

    $campaign = Get-CAInvRegistrationCampaign

    foreach ($u in $candidates) {
        $isSynced = ($u.onPremisesSyncEnabled -eq $true)

        $isGa = ($gaPermanentIds -contains $u.id)

        New-CAInvRecord -Domain $domain -CheckId 'Emergency-02' -ObjectType 'User' `
            -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'onPremisesSyncEnabled' `
            -ObservedValue $isSynced -Status ($(if ($isSynced) { 'Gap' } else { 'Ready' })) `
            -GraphSource $src `
            -Recommendation ('Break-glass accounts should be cloud-only and not synced.') -RawPath $raw | Out-Null

        New-CAInvRecord -Domain $domain -CheckId 'Emergency-02' -ObjectType 'User' `
            -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'accountEnabled; globalAdmin' `
            -ObservedValue ("enabled=$($u.accountEnabled); GA=$isGa") `
            -Status ($(if ($u.accountEnabled -and $isGa) { 'Ready' } else { 'Review required' })) `
            -GraphSource $src -ManualReview:(-not ($u.accountEnabled -and $isGa)) `
            -RawPath $raw | Out-Null

        $isOnMicrosoftDomain = [string]$u.userPrincipalName -match '(?i)@[^@]+\.onmicrosoft\.com$'
        New-CAInvRecord -Domain $domain -CheckId 'Emergency-09' -ObjectType 'User' `
            -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'upnDomain' `
            -ObservedValue $u.userPrincipalName -Status ($(if ($isOnMicrosoftDomain) { 'Ready' } else { 'Gap' })) `
            -GraphSource $src -ManualReview:(-not $explicit) `
            -Recommendation ('Microsoft recommends the .onmicrosoft.com domain for an emergency account''s UPN: it cannot be federated and doesn''t depend on DNS, so it''s independent of an outage in your own domain or federation.') -RawPath $raw | Out-Null

        $enabledPolicies = @($policies | Where-Object { Test-CAInvPolicyRestrictsSignIn -Policy $_ })
        $notExcludedFrom = [System.Collections.Generic.List[string]]::new()
        $uncertain = $false
        foreach ($p in $enabledPolicies) {
            $ex = Test-CAInvUserExcludedFromPolicy -Policy $p -UserId $u.id
            if (-not $ex.Excluded) {
                [void]$notExcludedFrom.Add($p.displayName)
                if ($ex.Certainty -ne 'high') { $uncertain = $true }
            }
        }
        $emg3Status = if ($notExcludedFrom.Count -eq 0) { 'Ready' } elseif ($uncertain) { 'Review required' } else { 'Gap' }
        New-CAInvRecord -Domain $domain -CheckId 'Emergency-03' -ObjectType 'User' `
            -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'caExclusion' `
            -ObservedValue ($(if ($notExcludedFrom.Count -eq 0) { 'Excluded from every policy that can block or restrict a sign-in' } else { "Not excluded from: $($notExcludedFrom -join ', ')" })) `
            -Status $emg3Status -GraphSource $src -ManualReview:$uncertain `
            -Recommendation ('Explicitly exclude break-glass accounts from every CA policy that can block or restrict a sign-in. Microsoft recommends doing this via a separate security group, e.g. EmergencyAccess, rather than per account. Report-only policies don''t need an exclusion: they block nothing. The deployment article says more briefly "excluded from all policies"; the emergency-access article is the specific article and therefore governs on this nuance.') -RawPath $raw | Out-Null

        $lastSignIn = Get-CAInvProp $u 'signInActivity.lastSignInDateTime'

        $window = Get-CAInvEffectiveLookbackWindow
        $recent = $false
        if ($lastSignIn) {
            try { $recent = ([DateTimeOffset]$lastSignIn) -ge ([DateTimeOffset]::UtcNow.AddDays(-$window)) } catch { $recent = $false }
        }
        New-CAInvRecord -Domain $domain -CheckId 'Emergency-05' -ObjectType 'User' `
            -ObjectId $u.id -ObjectName $u.userPrincipalName -Property "lastSignIn (window ${window}d)" `
            -ObservedValue ($(if ($lastSignIn) { $lastSignIn } else { 'none' })) `
            -Status ($(if ($recent) { 'Ready' } else { 'Gap' })) -GraphSource $src `
            -Recommendation ('Test break-glass accounts periodically; record the test.') -RawPath $raw | Out-Null

        $campSrc = 'GET /policies/authenticationMethodsPolicy (registrationCampaign)'
        if ($campaign.Failed) {
            New-CAInvRecord -Domain $domain -CheckId 'Emergency-04' -ObjectType 'User' `
                -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'registrationCampaignTargeting' `
                -Status 'Not assessed' `
                -NotAssessedReason ('Could not read authenticationMethodsPolicy: {0}' -f @($campaign.ErrorMessage)) `
                -GraphSource $campSrc | Out-Null
        }
        else {
            $scope = Test-CAInvUserInCampaignScope -UserId $u.id -Campaign $campaign
            if (-not $campaign.EffectivelyOn) {
                New-CAInvRecord -Domain $domain -CheckId 'Emergency-04' -ObjectType 'User' `
                    -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'registrationCampaignTargeting' `
                    -ObservedValue "Campaign is off (state=$($campaign.State)); no proof-up risk." `
                    -Status 'Ready' -GraphSource $campSrc -RawPath $raw | Out-Null
            }
            elseif ($scope.ExcludedDirect) {
                New-CAInvRecord -Domain $domain -CheckId 'Emergency-04' -ObjectType 'User' `
                    -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'registrationCampaignTargeting' `
                    -ObservedValue 'Directly excluded from the campaign (user, or direct member of the exclusion group).' `
                    -Status 'Ready' -GraphSource $campSrc -RawPath $raw | Out-Null
            }
            elseif ($scope.ExcludedNestedOnly) {

                New-CAInvRecord -Domain $domain -CheckId 'Emergency-04' -ObjectType 'User' `
                    -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'registrationCampaignTargeting' `
                    -ObservedValue 'Only excluded via a NESTED group; the campaign only honors direct members, so the account effectively falls within the campaign.' `
                    -Status 'Gap' -GraphSource $campSrc -ManualReview:($scope.Certainty -ne 'high') -RawPath $raw `
                    -Recommendation ('Exclude break-glass accounts DIRECTLY: as an individual user in excludeTargets, or as a direct member of the exclusion group. Nested exclusion doesn''t work for the campaign.') | Out-Null
            }
            elseif ($scope.InScope) {

                New-CAInvRecord -Domain $domain -CheckId 'Emergency-04' -ObjectType 'User' `
                    -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'registrationCampaignTargeting' `
                    -ObservedValue "Within the campaign targeting (method=$($campaign.TargetedMethod)); not excluded." `
                    -Status 'Review required' -ManualReview -GraphSource $campSrc -RawPath $raw `
                    -Recommendation ('Explicitly exclude break-glass accounts from the registration campaign (excludeTargets, direct). A proof-up nudge can block emergency access; whether that happens depends on the registered method and flow.') | Out-Null
            }
            else {
                New-CAInvRecord -Domain $domain -CheckId 'Emergency-04' -ObjectType 'User' `
                    -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'registrationCampaignTargeting' `
                    -ObservedValue 'Falls outside the campaign''s include targeting.' `
                    -Status 'Ready' -GraphSource $campSrc -ManualReview:($scope.Certainty -ne 'high') -RawPath $raw | Out-Null
            }
        }

        New-CAInvRecord -Domain $domain -CheckId 'Emergency-06' -ObjectType 'User' `
            -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'credentialStorage; PAW; procedure' `
            -Status 'Review required' -ManualReview -GraphSource 'handmatig register' -ApiVersion 'n/a' `
            -Recommendation ('Validate the vaulting procedure, four-eyes principle, PAW usage, and the emergency runbook.') | Out-Null
    }

    Write-CAInvEmergencyMethodFinding -Domain $domain -Account $candidates -RawPath $raw

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($candidates.Count) break-glass candidates assessed."
}
