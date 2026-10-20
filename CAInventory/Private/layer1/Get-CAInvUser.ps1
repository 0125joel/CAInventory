function Get-CAInvUser {
    <#
    .SYNOPSIS
        Domain 6.11 — Users and identity populations.
    .DESCRIPTION
        Reads the user population with the core fields for CA scoping. Separates objective
        properties (userType, accountEnabled, onPremisesSyncEnabled) from interpretation: the
        classification of possible service/shared accounts is a heuristic and is always returned
        as 'Review required'. Keeps the users in the
        context object for reuse by later checks.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.11'
    $select = 'id,userPrincipalName,displayName,userType,accountEnabled,onPremisesSyncEnabled,mail,createdDateTime,signInActivity'
    $src    = 'GET /users'

    $resp = Invoke-CAInvGraphOrNotAssessed -Uri "users?`$select=$select" -ApiVersion 'v1.0' -MaxPages 100 `
        -Domain $domain -CheckId 'Identity-01' -ObjectType 'User' -Property 'users' `
        -GraphSource $src -NotAssessedReasonPrefix ('Could not read /users')
    if ($resp.Failed) { return }

    $users = @($resp.Value)
    $raw = Write-CAInvRaw -Domain $domain -Endpoint 'users' -Data $users
    Add-CAInvContextData -Context $script:CAInvContext -Name 'Users' -Value $users

    $members    = @($users | Where-Object { $_.userType -eq 'Member' }).Count
    $guests     = @($users | Where-Object { $_.userType -eq 'Guest' }).Count
    $synced     = @($users | Where-Object { $_.onPremisesSyncEnabled -eq $true }).Count
    $cloudOnly  = $users.Count - $synced

    $usrCappedNote = if ($resp.Capped) { '; page limit reached (possibly incomplete)' } else { '' }
    New-CAInvRecord -Domain $domain -CheckId 'Identity-01' -ObjectType 'Tenant' `
        -Property 'userPopulation' `
        -ObservedValue ("total=$($users.Count); members=$members; guests=$guests; synced=$synced; cloud-only=$cloudOnly$usrCappedNote") `
        -Status 'Ready' -GraphSource $src -RawPath $raw | Out-Null

    $candidates = @(foreach ($u in $users) {
        if (Test-CAInvServiceAccountName -User $u) {
            [PSCustomObject]@{ Id = [string]$u.id; Upn = [string]$u.userPrincipalName; User = $u }
        }
    })

    if ($candidates.Count -gt 0) {
        $split = Split-CAInvUsersByActivity -Item $candidates

        foreach ($c in $split.Active) {
            $lastText = if ($null -eq $c.LastSignIn) { 'never signed in' } else { "last sign-in $($c.LastSignIn.ToString('yyyy-MM-dd'))" }
            $activityText = if ($split.HasActivityData) { " ($lastText)" } else { '' }
            New-CAInvRecord -Domain $domain -CheckId 'Identity-02' -ObjectType 'User' `
                -ObjectId $c.Id -ObjectName $c.Upn -Property 'accountPurpose (heuristic)' `
                -ObservedValue "Name suggests a service/shared/test account$activityText" -Status 'Review required' `
                -GraphSource $src -ManualReview `
                -Recommendation ('Confirm the account''s purpose; service accounts call for separate CA interpretation.') `
                -RawPath $raw | Out-Null
        }

        if (-not $split.HasActivityData) {
            Write-CAInvLog -Level 'WARN' -Domain $domain -Message ("Identity-02: signInActivity missing for the entire population; {0} finding(s) not split by activity." -f $candidates.Count)
        }
        elseif ($split.Dormant.Count -gt 0) {
            New-CAInvRecord -Domain $domain -CheckId 'Identity-02' -ObjectType 'Tenant' `
                -Property 'accountPurpose (heuristic, dormant accounts, aggregate)' `
                -ObservedValue (Get-CAInvDormantAggregateText -Dormant $split.Dormant -TotalCount $candidates.Count `
                    -ActiveWithinDays $split.ActiveWithinDays -Subject 'heuristically recognized service/shared accounts') `
                -Status 'Review required' -ManualReview -GraphSource $src -RawPath $raw `
                -Recommendation ('These accounts don''t block the rollout: they''re not in use. Treat them as a cleanup action (disable or remove) rather than reviewing each one''s account purpose individually. Review the {0} actually-active candidate(s) above separately.' -f @($split.Active.Count)) | Out-Null
        }

        Write-CAInvLog -Level 'INFO' -Domain $domain -Message ("Identity-02: {0} heuristic candidate(s), of which {1} active and {2} dormant." -f $candidates.Count, $split.Active.Count, $split.Dormant.Count)
    }
    else {

        New-CAInvRecord -Domain $domain -CheckId 'Identity-02' -ObjectType 'Tenant' `
            -Property 'accountPurpose (heuristic)' `
            -ObservedValue '0 heuristic candidates (service/shared/test account)' `
            -Status 'Ready' -GraphSource $src -RawPath $raw | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($users.Count) users inventoried."
}
