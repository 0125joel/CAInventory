function Write-CAInvServiceAccountInScopeFinding {
    <#
    .SYNOPSIS
        Writes the Identity-04 findings (heuristic service account within 'All users' scope),
        split by recent sign-in activity.
    .DESCRIPTION
        Same shape and same reason as Identity-03 (see Write-CAInvUserMfaCapabilityFinding): an
        account that hasn't signed in for years doesn't get stuck anywhere under CA enforcement,
        so it doesn't belong in the queue as an individually-reviewed migration risk. On the
        reference tenant, 9 of the 12 heuristically recognized service accounts hadn't signed in
        within 90 days, 5 of which had never signed in at all.

        The heuristic itself doesn't change here: a name stays a name, so the outcome stays
        'Review required'. What changes is how many times a human gets asked the same question.
    .PARAMETER Layer
        The layer name under which the records are written.
    .PARAMETER ServiceInScope
        Objects with Id, Upn, PolicyName, and User (the Graph user object).
    .OUTPUTS
        None. Writes records via New-CAInvRecord.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ServiceInScope
    )

    $entries = @($ServiceInScope)
    if ($entries.Count -eq 0) {

        New-CAInvRecord -Domain '6.11' -CheckId 'Identity-04' -ObjectType 'Tenant' `
            -Property 'accountPurpose (heuristic)' `
            -ObservedValue "No heuristically recognized service accounts within 'All users' scope" `
            -Status 'Ready' -GraphSource 'cross: CA All-users scope x account-name heuristic' | Out-Null
        return
    }

    $src = 'cross: CA All-users scope x account-name heuristic'
    $split = Split-CAInvUsersByActivity -Item $entries

    if (-not $split.HasActivityData) {
        Write-CAInvLog -Level 'WARN' -Domain '6.11' -Message ("Identity-04: signInActivity is missing for the entire population; {0} finding(s) not split by activity." -f $entries.Count)
    }

    foreach ($e in $split.Active) {
        $activityText = if (-not $split.HasActivityData) { '' }
            elseif ($null -eq $e.LastSignIn) { ' Never signed in.' }
            else { " Last sign-in $($e.LastSignIn.ToString('yyyy-MM-dd'))." }
        New-CAInvRecord -Domain '6.11' -CheckId 'Identity-04' -ObjectType 'User' `
            -ObjectId $e.Id -ObjectName $e.Upn -Property 'accountPurpose (heuristic)' `
            -ObservedValue "Name suggests a service/shared account, within scope of enabled 'All users' policy '$($e.PolicyName)' and not excluded.$activityText" `
            -Status 'Review required' -ManualReview `
            -GraphSource $src `
            -Recommendation ('A non-interactive account within CA scope can get stuck on MFA. Confirm the account''s purpose and exclude it if it doesn''t do interactive sign-in.') | Out-Null
    }

    if ($split.Dormant.Count -gt 0) {
        New-CAInvRecord -Domain '6.11' -CheckId 'Identity-04' -ObjectType 'Tenant' `
            -Property 'accountPurpose (heuristic, dormant accounts, aggregate)' `
            -ObservedValue (Get-CAInvDormantAggregateText -Dormant $split.Dormant -TotalCount $entries.Count `
                -ActiveWithinDays $split.ActiveWithinDays -Subject "heuristically recognized service accounts within 'All users' scope") `
            -Status 'Review required' -ManualReview -GraphSource $src `
            -Recommendation ('These accounts fall within CA scope but aren''t in use, so they can''t get stuck either. Treat them as a cleanup action rather than reviewing them one by one. Review the {0} actually-active account(s) above separately.' -f @($split.Active.Count)) | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain '6.11' -Message ("Identity-04: {0} candidate(s) in scope, of which {1} active and {2} dormant." -f $entries.Count, $split.Active.Count, $split.Dormant.Count)
}
