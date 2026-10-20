function Test-CAInvReferentialIntegrity {
    <#
    .SYNOPSIS
        Referential integrity checks that cross datasets.
    .DESCRIPTION
        Runs after the collectors and uses the datasets kept in the context object (CAPolicies,
        Groups, PrivilegedPrincipals, Users, UserRegistrationDetails, ServicePrincipals,
        CompliancePolicyByPlatform). Covers the checks that cross the
        already-collected datasets:
          - Foundation-05: CA policy references a group that no longer exists.
          - Identity-06/Identity-10: excluded group without an owner / with privileged users.
          - Identity-08: a group referenced by an enabled CA policy (include or exclude) is not
            role-assignable.
          - Foundation-12: application exclusion present (signalling).
          - Foundation-14: application exclusion without an owner (full cross-check, resolves the
            service principal owners of every excluded app).
          - Identity-03: a user within an enabled 'All users' policy is not MFA-capable. Split on
            recent sign-in activity: only users who still signed in
            within the activity window get their own record to review; the dormant rest goes into
            an aggregate. See Write-CAInvUserMfaCapabilityFinding.
          - Identity-04: heuristic service account within an enabled 'All users' policy.
          - Device-04: CA requires a compliant device for a platform without an assigned compliance
            policy on that platform (crosses with CompliancePolicyByPlatform from 6.18).
          - Identity-20 (01-09-2026): an enabled 'All users' policy requires a compliant device, the
            tenant has guests, and the policy does not explicitly exclude guests
            (conditions.users.excludeGuestsOrExternalUsers/legacy excludeUsers). Without any
            cross-tenant trust of MFA/device (CrossTenantTrustKnown/AnyCrossTenantDeviceOrMfaTrust,
            set by Get-CAInvExternalIdentity/Identity-14) no guest can then satisfy this: Gap. If
            trust exists with at least one partner, it cannot be confirmed that it covers all
            guests: Review required. Source: Microsoft Learn, b2b-fundamentals ("If you're
            enforcing device-based Conditional Access policies, use exclusion lists to allow access
            to B2B users").
        The reliability per check determines Gap vs Review required.

        Not built: 'SSPR and MFA methods inconsistent'. The SSPR enablement status and
        target audience cannot be read reliably via Graph (see Get-CAInvSspr, Auth-15); a
        cross-check on incomplete source data would give a false sense of confidence that the
        design explicitly wants to avoid. This remains a manual check until that Graph
        limitation goes away.
    #>
    [CmdletBinding()]
    param()

    $ctx = $script:CAInvContext

    $policies = @(Get-CAInvCaPolicy)
    $groups   = if ($ctx.PSObject.Properties.Name -contains 'Groups') { $ctx.Groups } else { @() }
    $privileged = if ($ctx.PSObject.Properties.Name -contains 'PrivilegedPrincipals') { $ctx.PrivilegedPrincipals } else { @() }

    $tenantUsers = @(if ($ctx.PSObject.Properties.Name -contains 'Users') { @($ctx.Users) } else { @() })
    $registrationDetails = @(if ($ctx.PSObject.Properties.Name -contains 'UserRegistrationDetails') { @($ctx.UserRegistrationDetails) } else { @() })
    $complianceByPlatform = if ($ctx.PSObject.Properties.Name -contains 'CompliancePolicyByPlatform') { $ctx.CompliancePolicyByPlatform } else { $null }

    $syncAccountIds = @(if ($ctx.PSObject.Properties.Name -contains 'SyncAccountIds') { @($ctx.SyncAccountIds) } else { @() })

    if (@($policies).Count -eq 0) {
        Write-CAInvLog -Level 'WARN' -Message 'Integrity: no CA policies available; checks skipped.'
        return
    }

    $usersKnown = ($ctx.PSObject.Properties.Name -contains 'Users')
    $guests = @($tenantUsers | Where-Object { $_.userType -eq 'Guest' })
    $crossTenantTrustKnown = [bool](Get-CAInvProp $ctx 'CrossTenantTrustKnown' $false)
    $anyCrossTenantTrust = [bool](Get-CAInvProp $ctx 'AnyCrossTenantDeviceOrMfaTrust' $false)

    if ($usersKnown -and $guests.Count -eq 0) {
        New-CAInvRecord -Domain '6.21' -CheckId 'Identity-20' -ObjectType 'Tenant' `
            -Property 'guestDeviceCaExposure' -ObservedValue '0 guests in the tenant; guest-vs-device CA exposure is not applicable.' `
            -Status 'Ready' -GraphSource 'GET /users (userType eq Guest)' | Out-Null
    }

    $groupIds = @($groups | ForEach-Object { $_.id })

    $touKnown = $ctx.PSObject.Properties.Name -contains 'TermsOfUse'
    $touIdSet = if ($touKnown) { @($ctx.TermsOfUse | ForEach-Object { $_.id }) } else { @() }
    $acKnown = $ctx.PSObject.Properties.Name -contains 'AuthContexts'
    $acIdSet = if ($acKnown) { @($ctx.AuthContexts | ForEach-Object { $_.id }) } else { @() }
    $regDetailsAvailable = $registrationDetails.Count -gt 0
    $regByUserId = @{}
    foreach ($rd in $registrationDetails) { if ($rd.UserId) { $regByUserId[$rd.UserId] = $rd } }

    $reportedApp = [System.Collections.Generic.HashSet[string]]::new()
    $reportedNotCapable = [System.Collections.Generic.HashSet[string]]::new()
    $notCapableInScope = [System.Collections.Generic.List[object]]::new()
    $reportedServiceInScope = [System.Collections.Generic.HashSet[string]]::new()
    $serviceInScope = [System.Collections.Generic.List[object]]::new()
    $reportedCmpGap = [System.Collections.Generic.HashSet[string]]::new()
    $privilegedIds = @($privileged | ForEach-Object { $_.principalId })
    $ownerMap = @{}
    foreach ($g in $groups) { $ownerMap[$g.id] = $g.ownerCount }

    $reportedOwnerless = [System.Collections.Generic.HashSet[string]]::new()
    $reportedPrivGroup = [System.Collections.Generic.HashSet[string]]::new()

    $reportedNotAssignable = [System.Collections.Generic.HashSet[string]]::new()
    $assignableMap = @{}
    foreach ($g in $groups) { $assignableMap[$g.id] = $g.isAssignableToRole }

    foreach ($p in $policies) {
        $users = Get-CAInvProp $p 'conditions.users'
        if (-not $users) { continue }

        $gc = Get-CAInvProp $p 'grantControls'
        $grantControls = @(Get-CAInvProp $gc 'builtInControls' @())
        $hasStrength = [bool](Get-CAInvProp $gc 'authenticationStrength.id')
        $totalControls = $grantControls.Count + $(if ($hasStrength) { 1 } else { 0 })
        $operator = [string](Get-CAInvProp $gc 'operator' 'AND')
        $compliantDeviceRequired = ($p.state -eq 'enabled') -and ($grantControls -contains 'compliantDevice') -and ($operator -ne 'OR' -or $totalControls -le 1)

        $excludeGroups = @(Get-CAInvProp $users 'excludeGroups' @())
        $includeGroups = @(Get-CAInvProp $users 'includeGroups' @())

        $refGroups = @()
        $refGroups += $includeGroups
        $refGroups += $excludeGroups
        $refGroups = $refGroups | Where-Object { $_ } | Select-Object -Unique

        foreach ($gid in $refGroups) {

            $res = Resolve-CAInvGroupReference -GroupId $gid -KnownActiveIds $groupIds
            switch ($res.State) {
                'missing' {
                    New-CAInvRecord -Domain '6.2' -CheckId 'Foundation-05' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $p.id -ObjectName $p.displayName -Property 'referencedGroupId' `
                        -ObservedValue $gid -Status 'Gap' `
                        -GraphSource 'cross: CA-policies x groups (direct resolve)' `
                        -Recommendation ('Group no longer exists; fix or remove the reference.') | Out-Null
                }
                'deleted' {
                    New-CAInvRecord -Domain '6.2' -CheckId 'Foundation-05' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $p.id -ObjectName $p.displayName -Property 'referencedGroupId' `
                        -ObservedValue "$gid (soft-deleted)" -Status 'Gap' `
                        -GraphSource 'cross: CA-policies x directory/deletedItems' `
                        -Recommendation ('Reference points to a deleted group; restore the group or remove the reference before the retention period expires.') | Out-Null
                }
                'unknown' {
                    New-CAInvRecord -Domain '6.2' -CheckId 'Foundation-05' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $p.id -ObjectName $p.displayName -Property 'referencedGroupId' `
                        -ObservedValue $gid -Status 'Not assessed' `
                        -NotAssessedReason ('Group resolution failed due to a permission or transient error.') `
                        -GraphSource 'cross: CA-policies x groups (direct resolve)' | Out-Null
                }

            }

            if ($p.state -eq 'enabled' -and $groupIds -contains $gid) {
                $isAssignable = $assignableMap[$gid]
                if ($isAssignable -eq $false -and $reportedNotAssignable.Add($gid)) {
                    $g = $groups | Where-Object { $_.id -eq $gid } | Select-Object -First 1

                    $isDynamic = -not [string]::IsNullOrWhiteSpace([string](Get-CAInvProp $g 'membershipRule' ''))
                    $isSynced  = ((Get-CAInvProp $g 'onPremisesSyncEnabled' $false) -eq $true)

                    $observed = if ($isDynamic) { 'False (dynamisch lidmaatschap)' }
                        elseif ($isSynced) { 'False (on-prem gesynchroniseerd)' }
                        else { 'False' }

                    $advice = if ($isDynamic) {
                        'A group with dynamic membership can never be role-assignable. Replace this CA group with a static, cloud-only group made role-assignable at creation, or deliberately accept that regular group administrators can change its membership.'
                    }
                    elseif ($isSynced) {
                        'An on-premises synced group cannot be role-assignable, and its membership is managed in AD besides. Replace this CA group with a cloud-only group made role-assignable at creation.'
                    }
                    else {
                        'Assess whether this group''s membership is adequately protected. With a regular group, a group owner can add themselves or others to the CA scope or exclusion. If you want to rule that out with a role-assignable group, note that isAssignableToRole is immutable and can only be set at CREATION time: that means creating a new group, moving the membership over, and repointing the CA policy, with the accompanying restrictions (P1 license, no dynamic rules, no nesting, max 500 per tenant). Note that this is our own judgment call, not Microsoft guidance; for the break-glass exclusion Microsoft recommends a regular dedicated security group. A lighter alternative is restricting ownership of this group, or placing it under a restricted management administrative unit.'
                    }

                    New-CAInvRecord -Domain '6.12' -CheckId 'Identity-08' -ObjectType 'Group' `
                        -ObjectId $gid -ObjectName $g.displayName -Property 'isAssignableToRole' `
                        -ObservedValue $observed -Status 'Review required' `
                        -GraphSource 'cross: CA includeGroups/excludeGroups x groups.isAssignableToRole' `
                        -Recommendation $advice | Out-Null
                }
            }
        }

        if ($p.state -eq 'enabled') {
            foreach ($gid in @($excludeGroups | Where-Object { $_ })) {
                if ($groupIds -notcontains $gid) { continue }

                $oc = $ownerMap[$gid]
                if ($null -ne $oc -and $oc -eq 0 -and $reportedOwnerless.Add($gid)) {
                    $g = $groups | Where-Object { $_.id -eq $gid } | Select-Object -First 1
                    New-CAInvRecord -Domain '6.12' -CheckId 'Identity-06' -ObjectType 'Group' `
                        -ObjectId $gid -ObjectName $g.displayName -Property 'ownerCount' `
                        -ObservedValue 0 -Status 'Gap' `
                        -GraphSource 'cross: CA excludeGroups x group owners' `
                        -Recommendation ('Assign an owner to this CA exclusion group, or remove the exception.') | Out-Null
                }

                $tm = Get-CAInvTransitiveMember -GroupId $gid
                if (-not $tm.Failed) {
                    $privInGroup = @($tm.Members | Where-Object { $privilegedIds -contains $_.id })
                    if ($privInGroup.Count -gt 0 -and $reportedPrivGroup.Add($gid)) {
                        $g = $groups | Where-Object { $_.id -eq $gid } | Select-Object -First 1
                        New-CAInvRecord -Domain '6.31' -CheckId 'Identity-10' -ObjectType 'Group' `
                            -ObjectId $gid -ObjectName $g.displayName -Property 'privilegedMembers' `
                            -ObservedValue "$($privInGroup.Count) privileged principal(s) in the exclusion group of policy '$($p.displayName)'" `
                            -Status 'Review required' -ManualReview `
                            -GraphSource 'cross: excludeGroups transitiveMembers x privileged principals' `
                            -Recommendation ('Excluding privileged users from CA increases risk; validate the legitimacy.') | Out-Null
                    }
                }
            }
        }

        $excludeApps = @(Get-CAInvProp $p 'conditions.applications.excludeApplications' @())
        if ($excludeApps.Count -gt 0) {
            $exApps = @($excludeApps | Where-Object { $_ -and $_ -ne 'Office365' })
            if ($exApps.Count -gt 0) {

                $appLabels = @(foreach ($appId in $exApps) {
                    $sp = Resolve-CAInvServicePrincipalByAppId -AppId $appId
                    $name = [string](Get-CAInvProp $sp 'displayName' '')
                    if ([string]::IsNullOrWhiteSpace($name)) { "$appId (not resolvable)" } else { "$name ($appId)" }
                })

                New-CAInvRecord -Domain '6.14' -CheckId 'Foundation-12' -ObjectType 'ConditionalAccessPolicy' `
                    -ObjectId $p.id -ObjectName $p.displayName -Property 'excludeApplications' `
                    -ObservedValue ($appLabels -join ', ') -Status 'Review required' -ManualReview `
                    -GraphSource 'cross: CA excludeApplications x servicePrincipals (naamresolutie)' `
                    -Recommendation ('Confirm that each excluded app is deliberately kept out of the policy here, and account for service dependencies: excluding one app doesn''t mean the user escapes the policy, because cloud apps call each other (Teams uses SharePoint Online and Exchange Online). Conversely, a policy on another app can still affect this one. The per-app ownership check runs via Foundation-14.') | Out-Null
            }

            foreach ($appId in $exApps) {
                if (-not $reportedApp.Add($appId)) { continue }

                $sp = Resolve-CAInvServicePrincipalByAppId -AppId $appId
                $spId = [string](Get-CAInvProp $sp 'id' '')

                if ($spId -and (Test-CAInvServicePrincipalIsForeign -ServicePrincipal $sp)) {
                    New-CAInvRecord -Domain '6.14' -CheckId 'Foundation-14' -ObjectType 'Application' `
                        -ObjectId $appId -ObjectName (Get-CAInvProp $sp 'displayName') -Property 'owners' `
                        -ObservedValue 'Multi-tenant app, managed outside this tenant; ownership is not applicable here.' `
                        -Status 'Ready' `
                        -GraphSource 'cross: CA excludeApplications x servicePrincipals.appOwnerOrganizationId' | Out-Null
                    continue
                }

                if (-not $spId) {
                    New-CAInvRecord -Domain '6.14' -CheckId 'Foundation-14' -ObjectType 'Application' `
                        -ObjectId $appId -Property 'owners' -Status 'Not assessed' `
                        -NotAssessedReason ('Could not resolve the service principal for appId {0}.' -f @($appId)) `
                        -GraphSource 'cross: CA excludeApplications x servicePrincipals x owners' | Out-Null
                    continue
                }

                $ownResp = Invoke-CAInvGraph -Uri "servicePrincipals/$spId/owners?`$select=id" -ApiVersion 'v1.0'
                if ($ownResp.Failed) {
                    New-CAInvRecord -Domain '6.14' -CheckId 'Foundation-14' -ObjectType 'Application' `
                        -ObjectId $appId -ObjectName (Get-CAInvProp $sp 'displayName') -Property 'owners' -Status 'Not assessed' `
                        -NotAssessedReason ('Could not read owners of service principal {0}: {1}' -f @($spId, $ownResp.ErrorMessage)) `
                        -GraphSource 'cross: CA excludeApplications x servicePrincipals x owners' | Out-Null
                    continue
                }

                $ownerCount = @($ownResp.Value).Count
                if ($ownerCount -eq 0) {
                    New-CAInvRecord -Domain '6.14' -CheckId 'Foundation-14' -ObjectType 'Application' `
                        -ObjectId $appId -ObjectName (Get-CAInvProp $sp 'displayName') -Property 'owners' `
                        -ObservedValue 0 -Status 'Gap' `
                        -GraphSource 'cross: CA excludeApplications x servicePrincipals x owners' `
                        -Recommendation ('This app is excluded from CA but has no owner. Without an owner, nobody is accountable for this exception; assign one or remove the exclusion.') | Out-Null
                }
            }
        }

        $isEnabledAllUsers = ($p.state -eq 'enabled') -and (Get-CAInvPolicyUserScope -Policy $p).TargetsAllUsers
        if ($isEnabledAllUsers -and $tenantUsers.Count -gt 0) {
            foreach ($u in $tenantUsers) {
                if ($u.userType -ne 'Member' -or -not $u.accountEnabled) { continue }

                if ($syncAccountIds.Count -gt 0 -and $syncAccountIds -contains [string]$u.id) { continue }
                $excl = Test-CAInvUserExcludedFromPolicy -Policy $p -UserId $u.id
                if ($excl.Excluded) { continue }

                if ($regDetailsAvailable -and $reportedNotCapable.Add($u.id)) {
                    $rd = $regByUserId[$u.id]
                    if ($rd -and -not $rd.StrengthCapable) {
                        [void]$notCapableInScope.Add([PSCustomObject]@{
                                User       = $u
                                PolicyName = [string]$p.displayName
                            })
                    }
                }

                if ($reportedServiceInScope.Add($u.id) -and (Test-CAInvServiceAccountName -User $u)) {
                    [void]$serviceInScope.Add([PSCustomObject]@{
                            Id         = [string]$u.id
                            Upn        = [string]$u.userPrincipalName
                            PolicyName = [string]$p.displayName
                            User       = $u
                        })
                }
            }
        }

        if ($complianceByPlatform -and $compliantDeviceRequired) {
            $platformsCond = Get-CAInvProp $p 'conditions.platforms'
            $includePlatforms = @(Get-CAInvProp $platformsCond 'includePlatforms' @())
            $excludePlatforms = @(Get-CAInvProp $platformsCond 'excludePlatforms' @())
            $targetPlatforms = if (-not $platformsCond -or $includePlatforms.Count -eq 0 -or ($includePlatforms -contains 'all')) {
                @('Windows', 'iOS', 'Android', 'macOS')
            }
            else {
                @($includePlatforms | ForEach-Object {
                    switch ("$_".ToLowerInvariant()) {
                        'windows'      { 'Windows' }
                        'windowsphone' { 'Windows' }
                        'ios'          { 'iOS' }
                        'android'      { 'Android' }
                        'macos'        { 'macOS' }
                        default        { $null }
                    }
                } | Where-Object { $_ } | Select-Object -Unique)
            }
            if ($excludePlatforms.Count -gt 0) {
                $excludedNormalized = @($excludePlatforms | ForEach-Object {
                    switch ("$_".ToLowerInvariant()) {
                        'windows'      { 'Windows' }
                        'windowsphone' { 'Windows' }
                        'ios'          { 'iOS' }
                        'android'      { 'Android' }
                        'macos'        { 'macOS' }
                        default        { $null }
                    }
                } | Where-Object { $_ })
                $targetPlatforms = @($targetPlatforms | Where-Object { $_ -notin $excludedNormalized })
            }

            foreach ($plat in $targetPlatforms) {
                if ($complianceByPlatform.ContainsKey($plat) -and -not $complianceByPlatform[$plat] -and $reportedCmpGap.Add("$($p.id)|$plat")) {
                    New-CAInvRecord -Domain '6.18' -CheckId 'Device-04' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $p.id -ObjectName $p.displayName -Property 'compliantDeviceGrant' `
                        -ObservedValue "Requires a compliant device for $plat, but no assigned compliance policy on that platform." `
                        -Status 'Gap' `
                        -GraphSource 'cross: CA grantControls.compliantDevice x CompliancePolicyByPlatform (6.18)' `
                        -Recommendation ('Assign a compliance policy for {0}, or add this platform to the policy''s scope exclusion until that''s arranged.' -f @($plat)) | Out-Null
                }
            }
        }

        if ($usersKnown -and $guests.Count -gt 0 -and $crossTenantTrustKnown -and $isEnabledAllUsers -and $compliantDeviceRequired) {
            $excludeUsersList = @(Get-CAInvProp $users 'excludeUsers' @())
            $guestExclusionTypes = [string](Get-CAInvProp $users 'excludeGuestsOrExternalUsers.guestOrExternalUserTypes' '')
            $guestsExcluded = ($excludeUsersList -contains 'GuestsOrExternalUsers') -or (-not [string]::IsNullOrWhiteSpace($guestExclusionTypes) -and $guestExclusionTypes -ne 'none')
            if (-not $guestsExcluded) {
                if ($anyCrossTenantTrust) {
                    New-CAInvRecord -Domain '6.21' -CheckId 'Identity-20' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $p.id -ObjectName $p.displayName -Property 'guestDeviceCaExposure' `
                        -ObservedValue "Requires a compliant device for all users (incl. $($guests.Count) guest(s)), with no guest exclusion. There is cross-tenant trust with at least one partner tenant (Identity-14), but it cannot be confirmed that it covers all guests." `
                        -Status 'Review required' -ManualReview `
                        -GraphSource 'cross: CA grantControls.compliantDevice x conditions.users x crossTenantAccessPolicy/partners (Identity-14)' `
                        -Recommendation ('Confirm per guest home tenant whether cross-tenant trust actually covers MFA/device compliance, or explicitly exclude guests from this policy.') | Out-Null
                }
                else {
                    New-CAInvRecord -Domain '6.21' -CheckId 'Identity-20' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $p.id -ObjectName $p.displayName -Property 'guestDeviceCaExposure' `
                        -ObservedValue "Requires a compliant device for all users (incl. $($guests.Count) guest(s)), with no guest exclusion and no cross-tenant trust of MFA/device compliance at all." `
                        -Status 'Gap' `
                        -GraphSource 'cross: CA grantControls.compliantDevice x conditions.users x crossTenantAccessPolicy/partners (Identity-14)' `
                        -Recommendation ('No guest can then satisfy this requirement: their device can never be made compliant for this tenant. Configure cross-tenant trust with your guests'' partner tenant(s), or explicitly exclude guests from this policy.') | Out-Null
                }
            }
        }

        $touIds = @(@(Get-CAInvProp $p 'grantControls.termsOfUse' @()) | Where-Object { $_ })
        if ($touIds.Count -gt 0) {
            if (-not $touKnown) {
                New-CAInvRecord -Domain '6.30' -CheckId 'Foundation-15' -ObjectType 'ConditionalAccessPolicy' `
                    -ObjectId $p.id -ObjectName $p.displayName -Property 'referencedTermsOfUse' -Status 'Not assessed' `
                    -NotAssessedReason ('Terms of Use agreements not available (layer 0 could not read identityGovernance/termsOfUse/agreements); reference cannot be checked.') `
                    -GraphSource 'cross: CA grantControls.termsOfUse x identityGovernance/termsOfUse/agreements' | Out-Null
            }
            else {
                $missingTou = @($touIds | Where-Object { $touIdSet -notcontains $_ })
                if ($missingTou.Count -gt 0) {
                    New-CAInvRecord -Domain '6.30' -CheckId 'Foundation-15' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $p.id -ObjectName $p.displayName -Property 'referencedTermsOfUse' `
                        -ObservedValue "References Terms of Use id(s) that no longer exist: $($missingTou -join ', ')" `
                        -Status 'Gap' `
                        -GraphSource 'cross: CA grantControls.termsOfUse x identityGovernance/termsOfUse/agreements' `
                        -Recommendation ('Terms of Use no longer exists; restore the agreement or remove the reference from the policy.') | Out-Null
                }
                else {
                    New-CAInvRecord -Domain '6.30' -CheckId 'Foundation-15' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $p.id -ObjectName $p.displayName -Property 'referencedTermsOfUse' `
                        -ObservedValue "All $($touIds.Count) referenced Terms of Use id(s) exist." `
                        -Status 'Ready' `
                        -GraphSource 'cross: CA grantControls.termsOfUse x identityGovernance/termsOfUse/agreements' | Out-Null
                }
            }
        }

        $acIds = @(@(Get-CAInvProp $p 'conditions.applications.includeAuthenticationContextClassReferences' @()) | Where-Object { $_ })
        if ($acIds.Count -gt 0) {
            if (-not $acKnown) {
                New-CAInvRecord -Domain '6.30' -CheckId 'Foundation-15' -ObjectType 'ConditionalAccessPolicy' `
                    -ObjectId $p.id -ObjectName $p.displayName -Property 'referencedAuthContext' -Status 'Not assessed' `
                    -NotAssessedReason ('Authentication context class references not available (layer 0 could not read identity/conditionalAccess/authenticationContextClassReferences); reference cannot be checked.') `
                    -GraphSource 'cross: CA includeAuthenticationContextClassReferences x authenticationContextClassReferences' | Out-Null
            }
            else {
                $missingAc = @($acIds | Where-Object { $acIdSet -notcontains $_ })
                if ($missingAc.Count -gt 0) {
                    New-CAInvRecord -Domain '6.30' -CheckId 'Foundation-15' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $p.id -ObjectName $p.displayName -Property 'referencedAuthContext' `
                        -ObservedValue "References authentication context id(s) that no longer exist: $($missingAc -join ', ')" `
                        -Status 'Gap' `
                        -GraphSource 'cross: CA includeAuthenticationContextClassReferences x authenticationContextClassReferences' `
                        -Recommendation ('Authentication context no longer exists; restore the context or remove the reference from the policy.') | Out-Null
                }
                else {
                    New-CAInvRecord -Domain '6.30' -CheckId 'Foundation-15' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $p.id -ObjectName $p.displayName -Property 'referencedAuthContext' `
                        -ObservedValue "All $($acIds.Count) referenced authentication context id(s) exist." `
                        -Status 'Ready' `
                        -GraphSource 'cross: CA includeAuthenticationContextClassReferences x authenticationContextClassReferences' | Out-Null
                }
            }
        }
    }

    Write-CAInvUserMfaCapabilityFinding -NotCapableInScope $notCapableInScope
    Write-CAInvServiceAccountInScopeFinding -ServiceInScope $serviceInScope

    Write-CAInvLog -Level 'INFO' -Message 'Referential integrity checks completed.'
}
