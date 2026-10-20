function Write-CAInvUserMfaCapabilityFinding {
    <#
    .SYNOPSIS
        Writes the Identity-03 findings (not MFA-capable within 'All users' scope), split by
        recent sign-in activity.
    .DESCRIPTION
        On a tenant of 471 users, Identity-03 produced 112 separate
        records to review, while 79 of those accounts had NEVER signed in and only 5 were active
        within 90 days. A dormant account without an MFA method doesn't block the CA rollout;
        it's a cleanup action. Conflating the two costs review time without advancing the
        rollout.

        So: only users who signed in within the activity window get their own record to review.
        The rest go into ONE aggregate record that includes the full list of accounts in the
        ObservedValue, so no measurement information is lost.

        The split itself has lived in Split-CAInvUsersByActivity since 21-08-2026, shared with
        the heuristic service-account checks (Identity-02, Identity-04, Auth-09) that need
        exactly the same distinction. See that helper for the window and for why a collection
        without activity data is NOT split.
    .PARAMETER Layer
        The layer name under which the records are written (the integrity checks run under
        layer 0).
    .PARAMETER NotCapableInScope
        Objects with a User property (the Graph user object) and a PolicyName property (the name
        of the enabled 'All users' policy the user fell under).
    .OUTPUTS
        None. Writes records via New-CAInvRecord.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$NotCapableInScope
    )

    $items = @($NotCapableInScope)
    if ($items.Count -eq 0) { return }

    $src = 'cross: CA All-users-scope x userRegistrationDetails.isMfaCapable'

    $entries = @(foreach ($item in $items) {
        [PSCustomObject]@{
            Id         = [string]$item.User.id
            Upn        = [string]$item.User.userPrincipalName
            PolicyName = [string]$item.PolicyName
            User       = $item.User
        }
    })

    $split = Split-CAInvUsersByActivity -Item $entries

    if (-not $split.HasActivityData) {
        Write-CAInvLog -Level 'WARN' -Domain '6.11' -Message ("Identity-03: signInActivity is missing for the entire population; {0} finding(s) not split by activity." -f $entries.Count)
        foreach ($e in $split.Active) { Write-CAInvNotCapableRecord -Entry $e -Source $src }
        return
    }

    foreach ($e in $split.Active) { Write-CAInvNotCapableRecord -Entry $e -Source $src }

    if ($split.Dormant.Count -gt 0) {
        $observed = Get-CAInvDormantAggregateText -Dormant $split.Dormant -TotalCount $entries.Count `
            -ActiveWithinDays $split.ActiveWithinDays -Subject "non-MFA-capable users within 'All users' scope"
        New-CAInvRecord -Domain '6.11' -CheckId 'Identity-03' -ObjectType 'Tenant' `
            -Property 'strengthCapable (dormant accounts, aggregate)' `
            -ObservedValue $observed `
            -Status 'Review required' -ManualReview `
            -GraphSource $src `
            -Recommendation ('These accounts don''t block the rollout: they''re not MFA-capable but also not in use. Treat them as a cleanup action (disable or remove) or deliberately exclude them, rather than reviewing them one by one. Review the {0} actually-active user(s) above separately.' -f @($split.Active.Count)) | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain '6.11' -Message ("Identity-03: {0} active user(s) within {1} days reported individually; {2} dormant account(s) summarized in an aggregate." -f $split.Active.Count, $split.ActiveWithinDays, $split.Dormant.Count)
}

function Write-CAInvNotCapableRecord {
    <#
    .SYNOPSIS
        Writes a single Identity-03 record. Only intended for
        Write-CAInvUserMfaCapabilityFinding.
    .PARAMETER Layer
        The layer name under which the record is written.
    .PARAMETER Entry
        An enriched object with Id, Upn, PolicyName, and LastSignIn.
    .PARAMETER Source
        The GraphSource text for the record.
    .OUTPUTS
        None. Writes a record via New-CAInvRecord.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][object]$Entry,
        [Parameter(Mandatory)][string]$Source
    )

    $lastText = if ($null -eq $Entry.LastSignIn) { 'never signed in' } else { "last sign-in $($Entry.LastSignIn.ToString('yyyy-MM-dd'))" }
    New-CAInvRecord -Domain '6.11' -CheckId 'Identity-03' -ObjectType 'User' `
        -ObjectId $Entry.Id -ObjectName $Entry.Upn -Property 'strengthCapable' `
        -ObservedValue "Not MFA-capable, within scope of enabled 'All users' policy '$($Entry.PolicyName)' ($lastText)." `
        -Status 'Review required' -ManualReview `
        -GraphSource $Source `
        -Recommendation ('User will get stuck once CA enforcement kicks in, because the report shows they cannot register/use an MFA method. Confirm (reporting latency possible) and register a method before migration.') | Out-Null
}
