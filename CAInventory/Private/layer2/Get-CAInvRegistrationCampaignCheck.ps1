function Get-CAInvRegistrationCampaignCheck {
    <#
    .SYNOPSIS
        Domain 6.7 — Authentication methods registration campaign (proof-up nudge).
    .DESCRIPTION
        Layer 2 collector. Reads the campaign via the shared helper Get-CAInvRegistrationCampaign
        (which caches the measurement so Emergency-04 in layer 1 uses the same source) and
        delivers three checks:

          Auth-08  Campaign status and configuration recorded (context).
          Auth-09  Legacy service/shared accounts within the campaign scope. The campaign can
                   force a non-interactive account through a proof-up it can never complete;
                   exclusion must use DIRECT targeting (direct user or direct member).
          Auth-10  Direct-member integrity for EVERY targeted group (include and exclude). The
                   campaign only honors DIRECT group members. Nested members of an exclusion
                   group still get nudged (exclusion doesn't work); nested members of an include
                   group are conversely NOT nudged (coverage gap).

        The break-glass check against the campaign is deliberately NOT here, but in the emergency
        access control (layer 1, Emergency-04), because that one knows the confirmed break-glass
        set.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.7'
    $src    = 'GET /policies/authenticationMethodsPolicy (registrationEnforcement/authenticationMethodsRegistrationCampaign)'

    $campaign = Get-CAInvRegistrationCampaign

    if ($campaign.Failed) {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-08' -ObjectType 'Policy' `
            -Property 'registrationCampaign' -Status 'Not assessed' `
            -NotAssessedReason ('Could not read authenticationMethodsPolicy: {0}' -f @($campaign.ErrorMessage)) `
            -GraphSource $src | Out-Null
        Write-CAInvLog -Level 'WARN' -Domain $domain -Message 'Registration campaign not readable; layer 2 checks Not assessed.'
        return
    }

    $incGroupCount = @($campaign.IncludeGroupIds).Count
    $excGroupCount = @($campaign.ExcludeGroupIds).Count
    $configText = "state=$($campaign.State); effectiefAan=$($campaign.EffectivelyOn); methode=$($campaign.TargetedMethod); " +
                  "alleGebruikers=$($campaign.AllUsersIncluded); includeGroepen=$incGroupCount; excludeGroepen=$excGroupCount; " +
                  "excludeUsers=$(@($campaign.ExcludeUserIds).Count); snoozeDagen=$($campaign.SnoozeDurationInDays); enforceNaSnoozes=$($campaign.EnforceAfterSnoozes)"

    New-CAInvRecord -Domain $domain -CheckId 'Auth-08' -ObjectType 'Policy' `
        -Property 'registrationCampaign' -ObservedValue $configText `
        -Status 'Ready' -GraphSource $src -RawPath $campaign.RawPath | Out-Null

    if (-not $campaign.EffectivelyOn) {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-09' -ObjectType 'Policy' `
            -Property 'serviceAccountsInScope' -ObservedValue 'Campaign is off; no accounts in scope.' `
            -Status 'Ready' -GraphSource $src -RawPath $campaign.RawPath | Out-Null
        New-CAInvRecord -Domain $domain -CheckId 'Auth-10' -ObjectType 'Policy' `
            -Property 'groupTargetDirectMembers' -ObservedValue 'Campaign is off; no group targeting active.' `
            -Status 'Ready' -GraphSource $src -RawPath $campaign.RawPath | Out-Null
        Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Registration campaign is off (state=$($campaign.State))."
        return
    }

    $ctx = $script:CAInvContext
    $users = @()
    if (($ctx.PSObject.Properties.Name -contains 'Users') -and $ctx.Users) { $users = @($ctx.Users) }
    if ($users.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-09' -ObjectType 'User' `
            -Property 'serviceAccountsInScope' -Status 'Not assessed' `
            -NotAssessedReason ('User population not available (layer 1/Identity not run in this run).') `
            -GraphSource $src | Out-Null
    }
    else {

        $svcAccounts = @($users | Where-Object { Test-CAInvServiceAccountName -User $_ })

        $inScope = [System.Collections.Generic.List[object]]::new()
        foreach ($u in $svcAccounts) {
            $scope = Test-CAInvUserInCampaignScope -UserId $u.id -Campaign $campaign
            if (-not $scope.InScope -and -not $scope.ExcludedNestedOnly) { continue }

            [void]$inScope.Add([PSCustomObject]@{
                    Id                 = [string]$u.id
                    Upn                = [string]$u.userPrincipalName
                    ExcludedNestedOnly = [bool]$scope.ExcludedNestedOnly
                    User               = $u
                })
        }

        if ($inScope.Count -eq 0) {
            New-CAInvRecord -Domain $domain -CheckId 'Auth-09' -ObjectType 'Policy' `
                -Property 'serviceAccountsInScope' `
                -ObservedValue "No heuristically recognized service/shared accounts within the campaign scope ($($svcAccounts.Count) candidate(s) tested)." `
                -Status 'Ready' -GraphSource $src -RawPath $campaign.RawPath | Out-Null
        }
        else {
            $split = Split-CAInvUsersByActivity -Item @($inScope)
            if (-not $split.HasActivityData) {
                Write-CAInvLog -Level 'WARN' -Domain $domain -Message ("Auth-09: signInActivity missing for the entire population; {0} finding(s) not split by activity." -f $inScope.Count)
            }

            foreach ($e in $split.Active) {
                $observed = if ($e.ExcludedNestedOnly) {
                    'In scope: only excluded via a nested group (campaign ignores nesting).'
                } else {
                    'In scope of the campaign (included and not directly excluded).'
                }
                if ($split.HasActivityData) {
                    $observed += if ($null -eq $e.LastSignIn) { ' Never signed in.' } else { " Last sign-in $($e.LastSignIn.ToString('yyyy-MM-dd'))." }
                }
                New-CAInvRecord -Domain $domain -CheckId 'Auth-09' -ObjectType 'User' `
                    -ObjectId $e.Id -ObjectName $e.Upn -Property 'serviceAccountInScope (heuristic)' `
                    -ObservedValue $observed -Status 'Review required' -ManualReview `
                    -GraphSource $src -RawPath $campaign.RawPath `
                    -Recommendation ('Confirm the account''s purpose; a non-interactive service/shared account cannot complete a proof-up nudge. Exclude it with DIRECT targeting: as a direct user in excludeTargets, or as a direct member of the exclusion group (nested exclusion doesn''t work).') | Out-Null
            }

            if ($split.Dormant.Count -gt 0) {
                New-CAInvRecord -Domain $domain -CheckId 'Auth-09' -ObjectType 'Policy' `
                    -Property 'serviceAccountInScope (heuristic, dormant accounts, aggregate)' `
                    -ObservedValue (Get-CAInvDormantAggregateText -Dormant $split.Dormant -TotalCount $inScope.Count `
                        -ActiveWithinDays $split.ActiveWithinDays -Subject 'heuristically recognized service accounts within the campaign scope') `
                    -Status 'Review required' -ManualReview -GraphSource $src -RawPath $campaign.RawPath `
                    -Recommendation ('These accounts are in the campaign scope but never sign in, so they never actually process the nudge. Treat them as a cleanup action rather than excluding them one by one. Review the {0} actually-active account(s) above separately.' -f @($split.Active.Count)) | Out-Null
            }

            Write-CAInvLog -Level 'INFO' -Domain $domain -Message ("Auth-09: {0} candidate(s) in scope, of which {1} active and {2} dormant." -f $inScope.Count, $split.Active.Count, $split.Dormant.Count)
        }
    }

    $groupTargets = @()
    $groupTargets += @($campaign.IncludeGroupIds | ForEach-Object { [PSCustomObject]@{ Id = $_; Role = 'include' } })
    $groupTargets += @($campaign.ExcludeGroupIds | ForEach-Object { [PSCustomObject]@{ Id = $_; Role = 'exclude' } })

    if ($groupTargets.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-10' -ObjectType 'Policy' `
            -Property 'groupTargetDirectMembers' `
            -ObservedValue 'Campaign does not target any groups (only all-users and/or individual users).' `
            -Status 'Ready' -GraphSource $src -RawPath $campaign.RawPath | Out-Null
    }
    else {
        foreach ($gt in $groupTargets) {
            $gid = $gt.Id
            if ([string]::IsNullOrWhiteSpace($gid)) { continue }

            $dm = Get-CAInvDirectMember -GroupId $gid
            $tm = Get-CAInvTransitiveMember -GroupId $gid

            if ($dm.Failed -or $tm.Failed) {
                New-CAInvRecord -Domain $domain -CheckId 'Auth-10' -ObjectType 'Group' `
                    -ObjectId $gid -Property "groupTargetDirectMembers ($($gt.Role))" -Status 'Not assessed' `
                    -NotAssessedReason ('Could not fully read the membership of group {0}.' -f @($gid)) `
                    -GraphSource $src -RawPath $campaign.RawPath | Out-Null
                continue
            }

            $directIds = @($dm.Members | ForEach-Object { $_.id })
            $transIds  = @($tm.Members | ForEach-Object { $_.id })
            $nestedOnly = @($transIds | Where-Object { $directIds -notcontains $_ })

            if ($nestedOnly.Count -eq 0) {
                New-CAInvRecord -Domain $domain -CheckId 'Auth-10' -ObjectType 'Group' `
                    -ObjectId $gid -Property "groupTargetDirectMembers ($($gt.Role))" `
                    -ObservedValue "$($directIds.Count) direct member(s); no nested members. The campaign's direct-member resolution covers this group completely." `
                    -Status 'Ready' -GraphSource $src -RawPath $campaign.RawPath | Out-Null
                continue
            }

            if ($gt.Role -eq 'exclude') {
                New-CAInvRecord -Domain $domain -CheckId 'Auth-10' -ObjectType 'Group' `
                    -ObjectId $gid -Property 'excludeGroupNestedMembers' `
                    -ObservedValue "$($nestedOnly.Count) nested member(s) fall outside the exclusion (of $($transIds.Count) transitive, $($directIds.Count) direct)." `
                    -Status 'Gap' -GraphSource $src -RawPath $campaign.RawPath `
                    -Recommendation ('This exclusion group contains nested members that the campaign does NOT exclude: only direct members count. Make the accounts involved direct members of the exclusion group, or exclude them individually as a user in excludeTargets.') | Out-Null
            }
            else {
                New-CAInvRecord -Domain $domain -CheckId 'Auth-10' -ObjectType 'Group' `
                    -ObjectId $gid -Property 'includeGroupNestedMembers' `
                    -ObservedValue "$($nestedOnly.Count) nested member(s) are NOT nudged (of $($transIds.Count) transitive, $($directIds.Count) direct)." `
                    -Status 'Review required' -ManualReview -GraphSource $src -RawPath $campaign.RawPath `
                    -Recommendation ('This include group contains nested members the campaign does NOT reach: only direct members get nudged. Confirm whether that''s intended; if not, make the members direct, or target them individually.') | Out-Null
            }
        }
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Registration campaign assessed (state=$($campaign.State), $($groupTargets.Count) group targets)."
}
