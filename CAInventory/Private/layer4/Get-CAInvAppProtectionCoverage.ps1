function Get-CAInvAppProtectionCoverage {
    <#
    .SYNOPSIS
        Domain 6.18 — Does the app protection policy cover the CA policy's target audience?
    .DESCRIPTION
        Layer 4 collector, and the second half of the question Device-09 opens. Device-09 measures
        whether app protection policy EXISTS and whether anything is assigned. Between that and
        reality sits the lockout this check is about: a CA policy on all users next to an app
        protection policy that's only assigned to the pilot group gives a green Ready at Device-09
        while everyone outside that group gets blocked on iOS and Android.

        The criterion is deliberately NOT equality of groups but one-way containment: everyone in
        the CA policy's include scope, minus the excludes, must be covered by at least one
        assigned app protection policy. Broader MAM policy than the CA scope is fine. A check that
        requires both sides to use the same groups triggers on virtually every tenant (CA on
        'All users', MAM on 'All employees') and is then exactly the noisy check CLAUDE.md
        prohibits.

        The comparison is hybrid, and that's a cost trade-off, not a compromise in strictness.
        First structurally on group ID: if a policy covers all licensed users, or every CA include
        group is literally a target on a policy with no exclusions of its own, coverage is proven
        without a single extra call. Only on a structural mismatch are the transitive members of
        both sides fetched to count whether users actually fall outside. That keeps both the false
        alarms (different but overlapping groups) and member resolution on a tenant-wide
        population out of the ordinary run.

        Four things determine whether a policy counts here at all, or how heavily the outcome
        weighs:

        First, the operator. With 'Require one of the selected controls' (operator OR and more
        than one control), app protection is optional and the lockout doesn't exist; those
        policies are skipped. One exception: OR with only 'approvedApplication' alongside it is
        exactly the migration state Microsoft prescribes in migrate-approved-client-app. There the
        coverage gap isn't a blocker today, but becomes one once the approved-client-app control
        drops away, so the outcome there is Review required instead of Gap.

        Second, the platform. A CA policy that targets iOS and Android while only iOS policy is
        assigned excludes all Android users. The comparison therefore happens per platform, with
        the same conditions.platforms normalization as Device-04. Windows stays outside the
        measurement: app protection on Windows is preview and has a different object model, so a
        policy that only targets Windows yields Not assessed and no verdict.

        Third, the excludes on both sides. The CA excludes are subtracted from the target
        audience, otherwise every emergency account gets flagged as a lockout risk. The MAM
        exclusions are subtracted from coverage per policy, because a user excluded from policy A
        can still be covered by policy B; so the covered set is computed per policy and only
        unioned afterward.

        Fourth, what can't be established. Role-based CA targeting isn't expanded: includeRoles
        only makes the target audience larger, so a measured gap stays valid, but measured full
        coverage isn't proven then and becomes Review required. A target type Graph returns that
        isn't known here downgrades the verdict for that platform to Not assessed instead of being
        silently skipped.

        Nested groups are the open uncertainty. Microsoft explicitly documents that assignments of
        APPS include nested groups, but says nothing anywhere about assignments of app protection
        policy. This check computes transitively, the cautious side: rather no false alarm than a
        fabricated gap. Where that difference can matter is in the recommendation, and the
        uncertainty is documented next to the
        same question for the registration campaign.

        The protections themselves are read via the same two endpoints as Device-09 and therefore
        come from the Graph cache; the assignments are the only dedicated fetch, and only for
        policy that's actually assigned.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.18'
    $src    = 'GET /deviceAppManagement/{ios|android}ManagedAppProtections/{id}/assignments; cross: CA conditions.users x assignment targets'

    $ok = Test-CAInvLicensePrecondition -CheckId 'Device-11' -Domain $domain `
        -ObjectType 'AppProtectionPolicy' -Property 'appProtectionCoverage' -GraphSource $src `
        -Consequence ('Without Intune, there is no app protection policy, so there''s no target-audience coverage to weigh against a CA policy either.')
    if (-not $ok) { return }

    $relevant = @(Get-CAInvAppProtectionRequiringPolicy)

    if ($relevant.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Device-11' -ObjectType 'Tenant' `
            -Property 'appProtectionCoverage' `
            -ObservedValue "No CA policy enforces 'Require app protection policy', so there is no target audience to weigh app protection policy coverage against." `
            -Status 'Ready' -GraphSource $src | Out-Null
        Write-CAInvLog -Level 'INFO' -Domain $domain -Message 'Device-11: no CA policy enforces the app protection control.'
        return
    }

    $byPlatform = @{}
    $failures = [System.Collections.Generic.List[string]]::new()
    $rawRows = [System.Collections.Generic.List[object]]::new()

    foreach ($ep in @(
            @{ Uri = 'deviceAppManagement/iosManagedAppProtections'; Platform = 'iOS' }
            @{ Uri = 'deviceAppManagement/androidManagedAppProtections'; Platform = 'Android' }
        )) {
        $byPlatform[$ep.Platform] = [System.Collections.Generic.List[object]]::new()

        $resp = Invoke-CAInvGraph -Uri $ep.Uri -ApiVersion 'v1.0'
        if ($resp.Failed) {
            $failures.Add("$($ep.Platform): $($resp.ErrorMessage)")
            continue
        }

        foreach ($pol in @($resp.Value)) {
            if (-not [bool](Get-CAInvProp $pol 'isAssigned' $false)) { continue }

            $polId = [string](Get-CAInvProp $pol 'id' '')
            $target = Resolve-CAInvAppProtectionAssignment -PolicyId $polId -CollectionUri $ep.Uri
            if ($target.Failed) {
                $failures.Add("$($ep.Platform)/$polId assignments: $($target.ErrorMessage)")
                continue
            }

            $entry = [PSCustomObject]@{
                Platform         = $ep.Platform
                Id               = $polId
                DisplayName      = [string](Get-CAInvProp $pol 'displayName' '')
                AllLicensedUsers = $target.AllLicensedUsers
                IncludeGroupIds  = @($target.IncludeGroupIds)
                ExcludeGroupIds  = @($target.ExcludeGroupIds)
                UnknownTargets   = @($target.UnknownTargets)
            }
            [void]$byPlatform[$ep.Platform].Add($entry)
            [void]$rawRows.Add($entry)
        }
    }

    $raw = Write-CAInvRaw -Domain $domain -Endpoint 'managedAppProtectionAssignments' -Data @($rawRows)

    if ($failures.Count -gt 0 -and $rawRows.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Device-11' -ObjectType 'AppProtectionPolicy' `
            -Property 'appProtectionCoverage' -Status 'Not assessed' `
            -NotAssessedReason ('Could not read any app protection policy assignment, so coverage cannot be weighed against the CA target audience. {0}' -f @($failures -join '; ')) `
            -GraphSource $src -RawPath $raw | Out-Null
        return
    }

    $partialRead = ($failures.Count -gt 0)
    $problems = 0
    $covered = [System.Collections.Generic.List[string]]::new()

    foreach ($item in $relevant) {
        $policy = $item.Policy
        $polName = [string](Get-CAInvProp $policy 'displayName' '')
        $polId = [string](Get-CAInvProp $policy 'id' '')

        $platforms = @(Resolve-CAInvCaMobilePlatform -Policy $policy)
        if ($platforms.Count -eq 0) {
            $problems++
            New-CAInvRecord -Domain $domain -CheckId 'Device-11' -ObjectType 'ConditionalAccessPolicy' `
                -ObjectId $polId -ObjectName $polName -Property 'appProtectionCoverage' `
                -Status 'Not assessed' `
                -NotAssessedReason ('This policy requires app protection but doesn''t touch iOS or Android. App protection on Windows is in preview and has a different object model, so coverage cannot be measured here.') `
                -GraphSource $src -RawPath $raw | Out-Null
            continue
        }

        foreach ($plat in $platforms) {
            $prots = @($byPlatform[$plat])
            $label = "$polName ($plat)"

            if ($prots.Count -eq 0) {
                $problems++
                $status = if ($item.Mode -eq 'migration') { 'Review required' } else { 'Gap' }
                $suffix = if ($item.Mode -eq 'migration') { ' Today the ''approved client app'' control still catches this, but that control is read-only and is being retired; then this becomes a blocker.' } else { '' }
                New-CAInvRecord -Domain $domain -CheckId 'Device-11' -ObjectType 'ConditionalAccessPolicy' `
                    -ObjectId $polId -ObjectName $label -Property 'appProtectionCoverage' `
                    -ObservedValue "The policy requires app protection on $plat, but there is no assigned app protection policy at all for $plat." `
                    -Status $status -GraphSource $src -RawPath $raw `
                    -Recommendation ('Create app protection policy for {0} and assign it to the groups covered by this policy, or remove {0} from the policy''s platform condition until that''s arranged.{1}' -f @($plat, $suffix)) | Out-Null
                continue
            }

            $unknown = @($prots | ForEach-Object { $_.UnknownTargets } | Where-Object { $_ } | Sort-Object -Unique)
            if ($unknown.Count -gt 0) {
                $problems++
                New-CAInvRecord -Domain $domain -CheckId 'Device-11' -ObjectType 'ConditionalAccessPolicy' `
                    -ObjectId $polId -ObjectName $label -Property 'appProtectionCoverage' `
                    -Status 'Not assessed' `
                    -NotAssessedReason ('The app protection policy for {0} uses an assignment type this check doesn''t recognize: {1}. Coverage therefore cannot be reliably determined; guessing here would produce an unwarranted green or red verdict.' -f @($plat, ($unknown -join ', '))) `
                    -GraphSource $src -RawPath $raw | Out-Null
                continue
            }

            $verdict = Resolve-CAInvAppProtectionCoverage -Policy $policy -Protections $prots
            if ($partialRead -and $verdict.Status -eq 'Ready') {
                $verdict = [PSCustomObject]@{
                    Status  = 'Review required'
                    Observed = $verdict.Observed
                    Reason  = 'Not all app protection assignments could be read ({0}), so full coverage is not proven.' -f @($failures -join '; ')
                    Recommendation = 'Repeat the measurement with the missing permissions, or confirm coverage manually in Intune before enabling the policy.'
                }
            }

            if ($verdict.Status -eq 'Ready') {
                [void]$covered.Add($label)
                continue
            }

            $problems++
            $status = $verdict.Status
            if ($status -eq 'Gap' -and $item.Mode -eq 'migration') { $status = 'Review required' }

            if ($status -eq 'Not assessed') {
                New-CAInvRecord -Domain $domain -CheckId 'Device-11' -ObjectType 'ConditionalAccessPolicy' `
                    -ObjectId $polId -ObjectName $label -Property 'appProtectionCoverage' `
                    -Status $status -GraphSource $src -RawPath $raw `
                    -NotAssessedReason $verdict.Reason | Out-Null
            }
            else {
                $extra = if ($item.Mode -eq 'migration') { ' Today the ''approved client app'' control still catches this, but that control is read-only and is being retired; then this becomes a blocker.' } else { '' }
                New-CAInvRecord -Domain $domain -CheckId 'Device-11' -ObjectType 'ConditionalAccessPolicy' `
                    -ObjectId $polId -ObjectName $label -Property 'appProtectionCoverage' `
                    -Status $status -GraphSource $src -RawPath $raw `
                    -ObservedValue $verdict.Observed -Recommendation "$($verdict.Recommendation)$extra" | Out-Null
            }
        }
    }

    if ($problems -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Device-11' -ObjectType 'Tenant' `
            -Property 'appProtectionCoverage' `
            -ObservedValue "$($covered.Count) CA policy/platform combination(s) checked; the target audience of every policy that enforces app protection falls entirely within an assigned app protection policy: $($covered -join ', ')" `
            -Status 'Ready' -GraphSource $src -RawPath $raw | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Device-11: $($relevant.Count) enforcing CA policy(s), $($rawRows.Count) assigned app protection policy(s), $problems finding(s)."
}

function Get-CAInvAppProtectionRequiringPolicy {
    <#
    .SYNOPSIS
        The CA policies for which missing app protection coverage actually matters.
    .DESCRIPTION
        Filters the policies that carry the 'compliantApplication' control and determines
        whether that control is actually enforced. Under 'Require one of the selected controls'
        (operator OR with more than one control), the user can get in via another control and
        the lockout doesn't exist. The only exception is the Microsoft-prescribed migration
        state, where 'approvedApplication' is the only alternative alongside app protection:
        that control has been read-only since 30 June 2026 and is going away, so there the
        coverage gap is deferred rather than absent. The same operator check appears at Device-04
        in Test-CAInvReferentialIntegrity.
    .OUTPUTS
        PSCustomObject[] with Policy and Mode ('enforced' | 'migration').
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $out = [System.Collections.Generic.List[object]]::new()

    foreach ($p in @(Get-CAInvCaPolicy)) {
        if ((Get-CAInvProp $p 'state' '') -eq 'disabled') { continue }

        $gc = Get-CAInvProp $p 'grantControls'
        $bic = @(Get-CAInvProp $gc 'builtInControls' @())
        if ($bic -notcontains 'compliantApplication') { continue }

        $hasStrength = [bool](Get-CAInvProp $gc 'authenticationStrength.id')
        $total = $bic.Count + $(if ($hasStrength) { 1 } else { 0 })
        $operator = [string](Get-CAInvProp $gc 'operator' 'AND')

        if ($operator -ne 'OR' -or $total -le 1) {
            [void]$out.Add([PSCustomObject]@{ Policy = $p; Mode = 'enforced' })
            continue
        }

        $alternatives = @($bic | Where-Object { $_ -ne 'compliantApplication' })
        $onlyApproved = (-not $hasStrength) -and $alternatives.Count -gt 0 -and
                        @($alternatives | Where-Object { $_ -ne 'approvedApplication' }).Count -eq 0
        if ($onlyApproved) {
            [void]$out.Add([PSCustomObject]@{ Policy = $p; Mode = 'migration' })
        }
    }

    return @($out)
}

function Resolve-CAInvAppProtectionAssignment {
    <#
    .SYNOPSIS
        Reads the assignments of a single app protection policy and splits them by target type.
    .DESCRIPTION
        Translates the targetedManagedAppPolicyAssignment collection into the three forms that
        matter for coverage: all licensed users, included groups, and excluded groups. An
        @odata.type not known here is not silently skipped but returned as UnknownTargets, so the
        consumer can write 'Not assessed' instead of claiming coverage that rests on an
        incomplete interpretation. The v1.0 reference now shows, alongside the classic
        groupAssignmentTarget, also a form with entraObjectId and targetType, and that is exactly
        such a case.
    .PARAMETER PolicyId
        Id of the app protection policy.
    .PARAMETER CollectionUri
        The collection the policy lives under, e.g. deviceAppManagement/iosManagedAppProtections.
    .OUTPUTS
        PSCustomObject: @{ AllLicensedUsers; IncludeGroupIds; ExcludeGroupIds; UnknownTargets; Failed; ErrorMessage }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string] $PolicyId,
        [Parameter(Mandatory)] [string] $CollectionUri
    )

    $include = [System.Collections.Generic.List[string]]::new()
    $exclude = [System.Collections.Generic.List[string]]::new()
    $unknown = [System.Collections.Generic.List[string]]::new()
    $all = $false

    $resp = Invoke-CAInvGraph -Uri "$CollectionUri/$PolicyId/assignments" -ApiVersion 'v1.0'
    if ($resp.Failed) {
        return [PSCustomObject]@{
            AllLicensedUsers = $false; IncludeGroupIds = @(); ExcludeGroupIds = @()
            UnknownTargets = @(); Failed = $true; ErrorMessage = $resp.ErrorMessage
        }
    }

    foreach ($a in @($resp.Value)) {
        $t = Get-CAInvProp $a 'target'
        if (-not $t) { continue }

        $type = [string](Get-CAInvProp $t '@odata.type' '')
        $short = ($type -replace '^#', '') -replace '^microsoft\.graph\.', ''
        $gid = [string](Get-CAInvProp $t 'groupId' '')

        switch ($short) {
            'allLicensedUsersAssignmentTarget' { $all = $true }
            'groupAssignmentTarget' {
                if ($gid) { [void]$include.Add($gid) } else { [void]$unknown.Add('groupAssignmentTarget without groupId') }
            }
            'exclusionGroupAssignmentTarget' {
                if ($gid) { [void]$exclude.Add($gid) } else { [void]$unknown.Add('exclusionGroupAssignmentTarget without groupId') }
            }
            default {
                $label = if ($short) { $short } else { 'assignment without @odata.type' }
                [void]$unknown.Add($label)
            }
        }
    }

    return [PSCustomObject]@{
        AllLicensedUsers = $all
        IncludeGroupIds  = @($include | Sort-Object -Unique)
        ExcludeGroupIds  = @($exclude | Sort-Object -Unique)
        UnknownTargets   = @($unknown | Sort-Object -Unique)
        Failed           = $false
        ErrorMessage     = $null
    }
}

function Resolve-CAInvAppProtectionCoverage {
    <#
    .SYNOPSIS
        Determines whether the target audience of a single CA policy falls within the assigned
        app protection policy.
    .DESCRIPTION
        Performs the hybrid comparison described in Get-CAInvAppProtectionCoverage: first
        structurally on group ID, and only on a mismatch at member level via
        Get-CAInvTransitiveMember. Role-based targeting is not expanded and propagates
        asymmetrically: includeRoles enlarges the target audience, so a found gap remains valid
        while full coverage is then unproven; excludeRoles shrinks the target audience and so can
        remove a found gap, which also makes the gap uncertain.
    .PARAMETER Policy
        The CA policy object.
    .PARAMETER Protections
        The assigned app protection policies for a single platform, as built by the collector.
    .OUTPUTS
        PSCustomObject: @{ Status; Observed; Reason; Recommendation }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Protections
    )

    $nestingNote = 'Watch out with nested groups: Microsoft documents nesting for app assignments but not for app protection policy assignments, so don''t rely on it without confirming it in the tenant.'

    $blanket = @($Protections | Where-Object { $_.AllLicensedUsers -and @($_.ExcludeGroupIds).Count -eq 0 })
    if ($blanket.Count -gt 0) {
        return [PSCustomObject]@{
            Status = 'Ready'
            Observed = "Policy '$($blanket[0].DisplayName)' is assigned to all licensed users with no exclusions."
            Reason = $null; Recommendation = $null
        }
    }

    $users = Get-CAInvProp $Policy 'conditions.users'
    $includeUsers  = @(Get-CAInvProp $users 'includeUsers' @())
    $includeGroups = @(Get-CAInvProp $users 'includeGroups' @())
    $includeRoles  = @(Get-CAInvProp $users 'includeRoles' @())
    $excludeUsers  = @(Get-CAInvProp $users 'excludeUsers' @())
    $excludeGroups = @(Get-CAInvProp $users 'excludeGroups' @())
    $excludeRoles  = @(Get-CAInvProp $users 'excludeRoles' @())

    $scope = Get-CAInvPolicyUserScope -Policy $Policy

    $namedUsers = @($includeUsers | Where-Object { $_ -notin @('All', 'None', 'GuestsOrExternalUsers') })

    if (-not $scope.TargetsAllUsers -and $includeGroups.Count -gt 0 -and $namedUsers.Count -eq 0) {
        $clean = @($Protections | Where-Object { @($_.ExcludeGroupIds).Count -eq 0 })
        $cleanIds = @($clean | ForEach-Object { $_.IncludeGroupIds } | Where-Object { $_ })
        $missing = @($includeGroups | Where-Object { $_ -and $_ -notin $cleanIds })
        if ($missing.Count -eq 0) {
            if ($includeRoles.Count -gt 0) {
                return [PSCustomObject]@{
                    Status = 'Review required'
                    Observed = "All $($includeGroups.Count) target group(s) of the policy are assigned on the app protection policy, but the policy also targets $($includeRoles.Count) role(s) and role members are not expanded here."
                    Reason = $null
                    Recommendation = 'Manually confirm that the members of that role/those roles are also covered by an app protection policy; otherwise they''ll be blocked as soon as the policy is enabled. {0}' -f @($nestingNote)
                }
            }
            return [PSCustomObject]@{
                Status = 'Ready'
                Observed = "All $($includeGroups.Count) target group(s) of the policy are literally assigned on an app protection policy with no exclusions of its own."
                Reason = $null; Recommendation = $null
            }
        }
    }

    $ctx = $script:CAInvContext
    $tenantUsers = @(if ($ctx.PSObject.Properties.Name -contains 'Users') { @($ctx.Users) } else { @() })

    if ($scope.TargetsAllUsers -and $tenantUsers.Count -eq 0) {
        return [PSCustomObject]@{
            Status = 'Not assessed'
            Observed = $null
            Reason = 'The policy targets all users, but the user population was not fetched in this run (layer 1 not run, or /users not readable), so coverage cannot be counted.'
            Recommendation = $null
        }
    }

    $failedGroups = [System.Collections.Generic.List[string]]::new()
    $tenantIds = @($tenantUsers | ForEach-Object { [string](Get-CAInvProp $_ 'id' '') } | Where-Object { $_ })

    $caIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($scope.TargetsAllUsers) {
        foreach ($id in $tenantIds) { [void]$caIds.Add($id) }
    }
    else {
        foreach ($u in $namedUsers) { [void]$caIds.Add([string]$u) }
        foreach ($g in $includeGroups) {
            $m = Add-CAInvUserMember -GroupId $g -Target $caIds
            if (-not $m) { [void]$failedGroups.Add($g) }
        }
    }

    if ($caIds.Count -eq 0) {
        return [PSCustomObject]@{
            Status = 'Not assessed'
            Observed = $null
            Reason = 'The policy''s target audience cannot be determined: no readable users or groups were found in the include scope.'
            Recommendation = $null
        }
    }

    foreach ($u in $excludeUsers) { [void]$caIds.Remove([string]$u) }
    foreach ($g in $excludeGroups) {
        $ex = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $m = Add-CAInvUserMember -GroupId $g -Target $ex
        if (-not $m) { [void]$failedGroups.Add($g); continue }
        foreach ($id in $ex) { [void]$caIds.Remove($id) }
    }

    $mamIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($prot in $Protections) {
        $inc = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if ($prot.AllLicensedUsers) {
            foreach ($id in $tenantIds) { [void]$inc.Add($id) }
        }
        foreach ($g in @($prot.IncludeGroupIds)) {
            $m = Add-CAInvUserMember -GroupId $g -Target $inc
            if (-not $m) { [void]$failedGroups.Add($g) }
        }
        foreach ($g in @($prot.ExcludeGroupIds)) {
            $ex = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $m = Add-CAInvUserMember -GroupId $g -Target $ex
            if (-not $m) { [void]$failedGroups.Add($g); continue }
            foreach ($id in $ex) { [void]$inc.Remove($id) }
        }
        foreach ($id in $inc) { [void]$mamIds.Add($id) }
    }

    $uncovered = @($caIds | Where-Object { -not $mamIds.Contains($_) })
    $failedText = if ($failedGroups.Count -gt 0) { " $($failedGroups.Count) group(s) could not be read, so the count may be incomplete." } else { '' }

    if ($uncovered.Count -eq 0) {
        if ($failedGroups.Count -gt 0) {
            return [PSCustomObject]@{
                Status = 'Review required'
                Observed = "No user outside the app protection policy found among the $($caIds.Count) measured target-audience member(s), but the picture is incomplete.$failedText"
                Reason = $null
                Recommendation = 'Repeat the measurement with read access on the groups involved, or confirm coverage manually in Intune. {0}' -f @($nestingNote)
            }
        }
        if ($includeRoles.Count -gt 0) {
            return [PSCustomObject]@{
                Status = 'Review required'
                Observed = "All $($caIds.Count) measured target-audience member(s) fall under an assigned app protection policy, but the policy also targets $($includeRoles.Count) role(s) and role members are not expanded here."
                Reason = $null
                Recommendation = 'Manually confirm that the members of that role/those roles are also covered by an app protection policy. {0}' -f @($nestingNote)
            }
        }
        return [PSCustomObject]@{
            Status = 'Ready'
            Observed = "All $($caIds.Count) target-audience member(s) fall under an assigned app protection policy."
            Reason = $null; Recommendation = $null
        }
    }

    $upnById = @{}
    foreach ($u in $tenantUsers) {
        $uid = [string](Get-CAInvProp $u 'id' '')
        if ($uid) { $upnById[$uid] = [string](Get-CAInvProp $u 'userPrincipalName' '') }
    }
    $sample = @($uncovered | Select-Object -First 5 | ForEach-Object {
            if ($upnById.ContainsKey($_) -and $upnById[$_]) { $upnById[$_] } else { $_ }
        })
    $sampleText = if ($sample.Count -gt 0) { " Example: $($sample -join ', ')." } else { '' }

    $observed = "$($uncovered.Count) of $($caIds.Count) target-audience member(s) fall outside every assigned app protection policy.$sampleText$failedText"

    if ($excludeRoles.Count -gt 0) {
        return [PSCustomObject]@{
            Status = 'Review required'
            Observed = "$observed The policy also excludes $($excludeRoles.Count) role(s); those members are not expanded here, so some of these users may still fall outside the policy."
            Reason = $null
            Recommendation = 'Determine which of these users actually fall under the policy and assign the app protection policy to their groups before enabling the policy. {0}' -f @($nestingNote)
        }
    }

    if ($failedGroups.Count -gt 0) {
        return [PSCustomObject]@{
            Status = 'Review required'
            Observed = $observed
            Reason = $null
            Recommendation = 'The picture is incomplete because not every group was readable; confirm coverage in Intune and assign the app protection policy to the groups covered by this policy. {0}' -f @($nestingNote)
        }
    }

    return [PSCustomObject]@{
        Status = 'Gap'
        Observed = $observed
        Reason = $null
        Recommendation = 'These users cannot satisfy the control and will be blocked as soon as the policy is enabled, regardless of what they do. Assign the app protection policy to the groups covered by this policy, or narrow the policy''s target audience to what the policy actually covers. {0}' -f @($nestingNote)
    }
}

function Add-CAInvUserMember {
    <#
    .SYNOPSIS
        Adds the transitive user members of a group to a collection.
    .DESCRIPTION
        Thin wrapper around Get-CAInvTransitiveMember that lets through only user objects: a
        transitive member list also contains the nested groups themselves and can contain
        devices or service principals, and those don't count as a target-audience member.
    .PARAMETER GroupId
        The group whose members are fetched.
    .PARAMETER Target
        The collection the user IDs are added to.
    .OUTPUTS
        [bool] $true if the group could be read.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $GroupId,
        [Parameter(Mandatory)] $Target
    )

    if ([string]::IsNullOrWhiteSpace($GroupId)) { return $true }

    $tm = Get-CAInvTransitiveMember -GroupId $GroupId
    if ($tm.Failed) { return $false }

    foreach ($m in @($tm.Members)) {
        $type = [string](Get-CAInvProp $m '@odata.type' '')
        $upn = [string](Get-CAInvProp $m 'userPrincipalName' '')
        if ($type -and $type -notmatch 'microsoft\.graph\.user$') { continue }
        if (-not $type -and -not $upn) { continue }
        $id = [string](Get-CAInvProp $m 'id' '')
        if ($id) { [void]$Target.Add($id) }
    }
    return $true
}

function Resolve-CAInvCaMobilePlatform {
    <#
    .SYNOPSIS
        The mobile platforms (iOS, Android) that a CA policy affects.
    .DESCRIPTION
        Normalizes conditions.platforms the same way as Device-04's compliance cross-check and
        then keeps only iOS and Android: those are the platforms for which app protection policy
        is generally available and for which Graph has its own managedAppProtections collection.
        If the platform condition is missing, or is 'all', the policy affects both.
    .PARAMETER Policy
        The CA policy object.
    .OUTPUTS
        [string[]] with zero, one, or two values from iOS and Android.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] $Policy
    )

    $cond = Get-CAInvProp $Policy 'conditions.platforms'
    $inc = @(Get-CAInvProp $cond 'includePlatforms' @())
    $exc = @(Get-CAInvProp $cond 'excludePlatforms' @())

    $normalize = {
        param($values)
        @($values | ForEach-Object {
                switch ("$_".ToLowerInvariant()) {
                    'ios'     { 'iOS' }
                    'android' { 'Android' }
                    default   { $null }
                }
            } | Where-Object { $_ })
    }

    $targets = @(if (-not $cond -or $inc.Count -eq 0 -or ($inc -contains 'all')) {
            @('iOS', 'Android')
        }
        else {
            @(& $normalize $inc)
        })

    if ($exc.Count -gt 0) {
        $excluded = @(& $normalize $exc)
        $targets = @($targets | Where-Object { $_ -notin $excluded })
    }

    return [string[]]@($targets | Select-Object -Unique)
}
