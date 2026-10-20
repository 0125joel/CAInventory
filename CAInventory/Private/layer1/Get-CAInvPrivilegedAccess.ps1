function Get-CAInvPrivilegedAccess {
    <#
    .SYNOPSIS
        Domain 6.13 — Directory roles and privileged access.
    .DESCRIPTION
        Reads active role assignments via roleManagement/directory/roleAssignmentScheduleInstances
        (not the barer roleAssignments endpoint) and resolves the Global Administrator role.
        Objectively flags the number of permanent Global Administrators.

        'Permanent' here specifically means: assignmentType = 'Assigned' AND no endDateTime — i.e.
        a fixed assignment, not a temporary PIM activation. A user who just activated their
        eligible GA role (assignmentType = 'Activated') also shows up in this endpoint while the
        activation is active, but does NOT count as permanent: that would undermine the whole point
        of PIM eligibility. The old roleAssignments endpoint doesn't make
        that distinction, all active assignments look identical there). Confirmed via Microsoft
        Learn (unifiedRoleAssignmentScheduleInstance): assignmentType is 'Assigned' or 'Activated',
        endDateTime is null for a non-expiring assignment.

        Keeps the privileged principals in the context object so the integrity check 'excluded
        group contains privileged users' can cross against it — this now also
        covers principals who are only privileged via an active PIM activation, which is more
        complete than before.
        PIM eligibility is read along where available; a missing PIM license leads to a
        'Not assessed' on the eligibility part, not to a hard failure.

        The accessReviews/definitions call (Identity-12) passes -Heartbeat (10-09-2026): a
        live-tenant run observed a 429 retry on this exact endpoint where the second attempt took
        over two minutes despite Retry-After only asking for 5s — the same silent-wait risk that
        -Heartbeat already addresses for Get-CAInvSignInData, on a different endpoint this time.
        roleAssignmentScheduleInstances and roleEligibilityScheduleInstances (both -MaxPages 100,
        both in this same function, both ahead of the accessReviews call in execution order) got
        -Heartbeat too, same day: no incident on either one yet, but the same shape of risk
        (paginated, could grow large on a bigger tenant) sitting right next to a call that already
        misbehaved once. See Invoke-CAInvWithHeartbeat for why it's opt-in per call rather than
        Invoke-CAInvGraph's default.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.13'
    $src    = 'GET /roleManagement/directory/roleAssignmentScheduleInstances'

    $roleDefMap = @{}
    $rdResp = Invoke-CAInvGraph -Uri 'roleManagement/directory/roleDefinitions?$select=id,displayName,templateId' -ApiVersion 'v1.0'
    if (-not $rdResp.Failed) {
        foreach ($rd in @($rdResp.Value)) { $roleDefMap[$rd.id] = $rd }
    }

    $resp = Invoke-CAInvGraphOrNotAssessed -Uri 'roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal' -ApiVersion 'v1.0' -MaxPages 100 -Heartbeat `
        -Domain $domain -CheckId 'Identity-09' -ObjectType 'DirectoryRole' -Property 'roleAssignmentScheduleInstances' `
        -GraphSource $src -NotAssessedReasonPrefix ('Could not read role assignments')
    if ($resp.Failed) { return }

    $assignments = @($resp.Value)
    $raw = Write-CAInvRaw -Domain $domain -Endpoint 'roleAssignmentScheduleInstances' -Data $assignments

    $privileged = foreach ($a in $assignments) {
        $rdId = Get-CAInvProp $a 'roleDefinitionId'
        $rd = if ($rdId) { $roleDefMap[$rdId] } else { $null }
        $principal = Get-CAInvProp $a 'principal'
        [PSCustomObject]@{
            principalId    = Get-CAInvProp $principal 'id'
            principalType  = Get-CAInvProp $principal '@odata.type'
            principalName  = Get-CAInvProp $principal 'displayName'
            roleName       = if ($rd) { $rd.displayName } else { $rdId }
            roleTemplate   = if ($rd) { $rd.templateId } else { $null }
            assignmentType = Get-CAInvProp $a 'assignmentType'
            endDateTime    = Get-CAInvProp $a 'endDateTime'
        }
    }
    Add-CAInvContextData -Context $script:CAInvContext -Name 'PrivilegedPrincipals' -Value @($privileged)

    $gaAllUsers = @(Get-CAInvGlobalAdminPrincipal -Principal $privileged -UsersOnly)
    $gaUsers = @($gaAllUsers | Where-Object { Test-CAInvPermanentAssignment $_ })
    $gaActivated = @($gaAllUsers | Where-Object { (Get-CAInvProp $_ 'assignmentType' '') -eq 'Activated' })

    $status = if ($gaUsers.Count -ge 1 -and $gaUsers.Count -le 4) { 'Ready' } else { 'Review required' }
    $gaRec = if ($gaUsers.Count -eq 0) {
        'No permanent Global Admins (possibly entirely via PIM eligibility). Verify that break-glass accounts do have permanent GA.'
    } elseif ($gaUsers.Count -gt 5) {
        'Many permanent Global Administrators; Microsoft recommends fewer than five. Reduce the number and consider PIM eligibility.'
    } elseif ($gaUsers.Count -eq 5) {
        'Exactly five permanent Global Administrators; Microsoft recommends fewer than five and itself shows an alert card on the Entra overview page from five onward. How many of these are day-to-day admins versus emergency accounts is covered by Identity-19, which actually subtracts the confirmed emergency accounts.'
    } else {
        'Number of permanent Global Administrators within the recommended range (fewer than five).'
    }

    if ($gaActivated.Count -gt 0) {
        $gaRec += ' In addition, {0} user(s) temporarily active as GA via a PIM activation (not counted as permanent, as intended).' -f @($gaActivated.Count)
    }
    New-CAInvRecord -Domain $domain -CheckId 'Identity-09' -ObjectType 'DirectoryRole' `
        -ObjectName 'Global Administrator' -Property 'permanentGlobalAdminCount' `
        -ObservedValue $gaUsers.Count -Status $status `
        -GraphSource $src -ManualReview:($status -eq 'Review required') `
        -Recommendation $gaRec `
        -RawPath $raw | Out-Null

    $eligResp = Invoke-CAInvGraph -Uri 'roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal' -ApiVersion 'v1.0' -MaxPages 100 -Heartbeat
    if ($eligResp.Failed) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-09' -ObjectType 'DirectoryRole' `
            -Property 'eligibleAssignments (PIM)' -Status 'Not assessed' `
            -NotAssessedReason ('PIM eligibility not readable (possibly no P2): {0}' -f @($eligResp.ErrorMessage)) `
            -GraphSource 'GET /roleManagement/directory/roleEligibilityScheduleInstances' `
            -LicenseRequirement 'Entra ID P2' | Out-Null
    }
    else {
        $elig = @($eligResp.Value)
        Write-CAInvRaw -Domain $domain -Endpoint 'roleEligibilityScheduleInstances' -Data $elig | Out-Null

        $eligPrincipals = foreach ($e in $elig) {
            $rdId = Get-CAInvProp $e 'roleDefinitionId'
            $rd = if ($rdId) { $roleDefMap[$rdId] } else { $null }
            $principal = Get-CAInvProp $e 'principal'

            [PSCustomObject]@{
                principalId = Get-CAInvProp $principal 'id'
                principalType = Get-CAInvProp $principal '@odata.type'
                principalName = Get-CAInvProp $principal 'displayName'
                roleName = if ($rd) { $rd.displayName } else { $rdId }
                roleTemplate = if ($rd) { $rd.templateId } else { $null }
                assignmentType = 'Eligible'
                endDateTime = Get-CAInvProp $e 'endDateTime'
            }
        }
        $combined = @($privileged) + @($eligPrincipals)
        $script:CAInvContext.PrivilegedPrincipals = $combined
        New-CAInvRecord -Domain $domain -CheckId 'Identity-09' -ObjectType 'DirectoryRole' `
            -Property 'eligibleAssignmentCount' -ObservedValue $elig.Count -Status 'Ready' `
            -GraphSource 'GET /roleManagement/directory/roleEligibilityScheduleInstances' -LicenseRequirement 'Entra ID P2' | Out-Null
    }

    if (Test-CAInvLicensePrecondition -CheckId 'Identity-11' -Domain $domain `
            -ObjectType 'Policy' -Property 'roleActivationPolicy' `
            -GraphSource 'GET /policies/roleManagementPolicies' `
            -Consequence ('Without PIM, there is no role activation policy to assess.')) {
        $rmpResp = Invoke-CAInvGraph -Uri "policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'Directory'" -ApiVersion 'v1.0'
        if ($rmpResp.Failed) {
            New-CAInvRecord -Domain $domain -CheckId 'Identity-11' -ObjectType 'Policy' `
                -Property 'roleActivationPolicy' -Status 'Not assessed' `
                -NotAssessedReason ('Could not read roleManagementPolicies: {0}. May require Entra ID P2.' -f @($rmpResp.ErrorMessage)) `
                -GraphSource 'GET /policies/roleManagementPolicies' | Out-Null
        }
        else {
            $orgDefault = @($rmpResp.Value) | Select-Object -First 1
            if (-not $orgDefault) {
                New-CAInvRecord -Domain $domain -CheckId 'Identity-11' -ObjectType 'Policy' `
                    -Property 'roleActivationPolicy' -Status 'Not assessed' `
                    -NotAssessedReason ('No organization-wide role activation policy found.') `
                    -GraphSource 'GET /policies/roleManagementPolicies' | Out-Null
            }
            else {
                $rulesResp = Invoke-CAInvGraph -Uri "policies/roleManagementPolicies/$($orgDefault.id)/rules" -ApiVersion 'v1.0'
                if ($rulesResp.Failed) {
                    New-CAInvRecord -Domain $domain -CheckId 'Identity-11' -ObjectType 'Policy' `
                        -ObjectId $orgDefault.id -Property 'roleActivationPolicy' -Status 'Not assessed' `
                        -NotAssessedReason ('Could not read activation rules: {0}' -f @($rulesResp.ErrorMessage)) `
                        -GraphSource 'GET /policies/roleManagementPolicies/{id}/rules' | Out-Null
                }
                else {
                    $enablementRule = @($rulesResp.Value) | Where-Object { (Get-CAInvProp $_ '@odata.type' '') -match 'EnablementRule' } | Select-Object -First 1
                    $enabledRules = @(Get-CAInvProp $enablementRule 'enabledRules' @())
                    $mfaRequired = $enabledRules -contains 'MultiFactorAuthentication'
                    $justificationRequired = $enabledRules -contains 'Justification'

                    $id11Status = if (-not $mfaRequired) { 'Gap' } elseif (-not $justificationRequired) { 'Review required' } else { 'Ready' }
                    $id11Recommendation = if (-not $mfaRequired) {
                        'Require MFA on PIM role activation; without this requirement, a compromised account can activate a privileged role without extra verification.'
                    }
                    elseif (-not $justificationRequired) {
                        'Require a justification on PIM role activation; without an audit trail, there''s no way to trace afterward why a privileged role was activated.'
                    }
                    else { $null }
                    New-CAInvRecord -Domain $domain -CheckId 'Identity-11' -ObjectType 'Policy' `
                        -ObjectId $orgDefault.id -Property 'roleActivationRequirements' `
                        -ObservedValue "MFA-on-activation=$mfaRequired; justification-required=$justificationRequired" `
                        -Status $id11Status -ManualReview:($id11Status -eq 'Review required') `
                        -GraphSource 'GET /policies/roleManagementPolicies/{id}/rules' `
                        -Recommendation $id11Recommendation | Out-Null
                }
            }
        }
    }

    if (Test-CAInvLicensePrecondition -CheckId 'Identity-12' -Domain $domain `
            -ObjectType 'AccessReview' -Property 'privilegedRoleAccessReviews' `
            -GraphSource 'GET /identityGovernance/accessReviews/definitions' `
            -Consequence ('Without this license, a tenant cannot set up access reviews.')) {
        $arResp = Invoke-CAInvGraph -Uri 'identityGovernance/accessReviews/definitions' -ApiVersion 'v1.0' -Heartbeat
        if ($arResp.Failed) {
            New-CAInvRecord -Domain $domain -CheckId 'Identity-12' -ObjectType 'AccessReview' `
                -Property 'privilegedRoleAccessReviews' -Status 'Not assessed' `
                -NotAssessedReason ('Could not read access review definitions: {0}. May require Entra ID Governance/P2.' -f @($arResp.ErrorMessage)) `
                -GraphSource 'GET /identityGovernance/accessReviews/definitions' | Out-Null
        }
        else {
            $arRaw = Write-CAInvRaw -Domain $domain -Endpoint 'accessReviewDefinitions' -Data $arResp.Value

            $roleReviews = @($arResp.Value | Where-Object {
                $scope = Get-CAInvProp $_ 'scope'
                $queries = @(Get-CAInvProp $scope 'query' '') + @(@(Get-CAInvProp $scope 'resourceScopes' @()) | ForEach-Object { Get-CAInvProp $_ 'query' '' })
                @($queries | Where-Object { $_ -match '/roleManagement/directory/' }).Count -gt 0
            })
            New-CAInvRecord -Domain $domain -CheckId 'Identity-12' -ObjectType 'AccessReview' `
                -Property 'privilegedRoleAccessReviews' -ObservedValue "$($roleReviews.Count) access review definition(s) targeting role assignments (of $(@($arResp.Value).Count) total)" `
                -Status ($(if ($roleReviews.Count -gt 0) { 'Ready' } else { 'Gap' })) `
                -GraphSource 'GET /identityGovernance/accessReviews/definitions' -RawPath $arRaw `
                -Recommendation ($(if ($roleReviews.Count -eq 0) { 'Set up a periodic access review for privileged role assignments; without review, privileged roles accumulate unnoticed.' } else { $null })) | Out-Null
        }
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($assignments.Count) active role assignments; $($gaUsers.Count) permanent GA users."
}
