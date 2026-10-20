function Split-CAInvUsersByActivity {
    <#
    .SYNOPSIS
        Splits a collection of users into recently active and dormant, based on signInActivity.
    .DESCRIPTION
        Shared source for every check that produces a per-user finding requiring review and that
        needs to distinguish between "can block the rollout" and "is a cleanup task".

        The reasoning behind this applies
        unchanged to the heuristic service-account checks (Identity-02, Identity-04, Auth-09): an
        account that hasn't signed in for years isn't blocking anything, so it doesn't belong in
        the queue as a separately reviewable migration risk. On the reference tenant, 9 of the 12
        heuristically recognized service accounts hadn't signed in within the window, 5 of which
        had never signed in at all.

        Two properties this helper deliberately has:

          - **Being unable to measure is not a dormant account.** When signInActivity is missing
            for the WHOLE collection (for example because AuditLog.Read.All wasn't granted),
            HasActivityData is $false and the caller shouldn't split. The presence of activity
            data is determined across the whole collection, not per user: a single user with no
            timestamp is a user who never signed in; a collection with no timestamps at all is a
            measurement problem.
          - **The last sign-in is the latest of three timestamps.** Graph omits the entire
            signInActivity object when there's nothing, and fills the three fields independently
            of each other; reading only lastSignInDateTime underestimates the activity of accounts
            that work exclusively non-interactively.

        The window is a parameter defaulting to 90, matching Microsoft's own 90-day account
        validation cadence and the module's -MaxLookbackDays ceiling.
    .PARAMETER Item
        Objects each carrying a User property with the Graph user object. Other properties on the
        object are left untouched and carried through to the output.
    .PARAMETER ActiveWithinDays
        Number of days within which a sign-in counts as 'recently active'.
    .OUTPUTS
        PSCustomObject: @{ Active (array); Dormant (array); NeverSignedIn (int); HasActivityData (bool); ActiveWithinDays (int) }
        Each element in Active/Dormant is the original object, enriched with LastSignIn
        ([datetime] in UTC, or $null when there is no timestamp).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Item,
        [ValidateRange(1, 3650)][int] $ActiveWithinDays = 90
    )

    $items = @($Item)
    $empty = [PSCustomObject]@{
        Active = @(); Dormant = @(); NeverSignedIn = 0
        HasActivityData = $false; ActiveWithinDays = $ActiveWithinDays
    }
    if ($items.Count -eq 0) { return $empty }

    $cutoff = (Get-Date).ToUniversalTime().AddDays(-$ActiveWithinDays)
    $anyActivityData = $false

    $enriched = foreach ($entry in $items) {
        $activity = Get-CAInvProp $entry.User 'signInActivity'
        $last = $null
        foreach ($field in @('lastSignInDateTime', 'lastNonInteractiveSignInDateTime', 'lastSuccessfulSignInDateTime')) {
            $value = Get-CAInvProp $activity $field
            if ([string]::IsNullOrWhiteSpace([string]$value)) { continue }
            $anyActivityData = $true

            $parsed = [datetime]::MinValue
            if ([datetime]::TryParse([string]$value, [ref]$parsed)) {
                $utc = $parsed.ToUniversalTime()
                if ($null -eq $last -or $utc -gt $last) { $last = $utc }
            }
        }
        $entry | Add-Member -NotePropertyName 'LastSignIn' -NotePropertyValue $last -Force -PassThru
    }
    $enriched = @($enriched)

    if (-not $anyActivityData) {
        return [PSCustomObject]@{
            Active = $enriched; Dormant = @(); NeverSignedIn = 0
            HasActivityData = $false; ActiveWithinDays = $ActiveWithinDays
        }
    }

    $active  = @($enriched | Where-Object { $null -ne $_.LastSignIn -and $_.LastSignIn -ge $cutoff })
    $dormant = @($enriched | Where-Object { $null -eq $_.LastSignIn -or $_.LastSignIn -lt $cutoff })

    [PSCustomObject]@{
        Active = $active
        Dormant = $dormant
        NeverSignedIn = @($dormant | Where-Object { $null -eq $_.LastSignIn }).Count
        HasActivityData = $true
        ActiveWithinDays = $ActiveWithinDays
    }
}

function Get-CAInvDormantAggregateText {
    <#
    .SYNOPSIS
        Builds the ObservedValue text for an aggregate record about dormant accounts.
    .DESCRIPTION
        Shared by Identity-02, Identity-03, Identity-04, and Auth-09 so the aggregates have the
        same shape and the same promise: the count, how many of those never signed in at all, and
        the FULL account list. That list isn't a nicety — it's the reason aggregating is allowed
        at all: no measurement information disappears from the report, only review work
        disappears from the queue.
    .PARAMETER Dormant
        The dormant items from Split-CAInvUsersByActivity (with a Upn property).
    .PARAMETER TotalCount
        The total the dormant group is drawn from.
    .PARAMETER ActiveWithinDays
        The activity window used.
    .PARAMETER Subject
        Short description of the population, e.g. "heuristically recognized service accounts".
    .OUTPUTS
        String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Dormant,
        [Parameter(Mandatory)][int] $TotalCount,
        [Parameter(Mandatory)][int] $ActiveWithinDays,
        [Parameter(Mandatory)][string] $Subject
    )

    $items = @($Dormant)
    $never = @($items | Where-Object { $null -eq $_.LastSignIn }).Count
    $neverText = if ($never -gt 0) { ", of which $never never signed in at all" } else { '' }
    $accounts = ($items | Sort-Object Upn | ForEach-Object { $_.Upn }) -join ', '
    "$($items.Count) of $TotalCount $Subject did not sign in during the last $ActiveWithinDays days$neverText. Accounts: $accounts"
}
