function Get-CAInvLegacyClientApp {
    <#
    .SYNOPSIS
        The explicit list of clientApp names that count as legacy authentication.
    .DESCRIPTION
        Deliberately an ALLOWLIST, not "everything except browser and modern clients". That
        inverted approach also counted 'Unknown' as legacy, even though Unknown literally means
        there's no information about the client used (Microsoft's own legacy-auth workbook uses
        three buckets: modern, Unknown, legacy). On tenants with a lot of non-interactive traffic,
        that produced a High-severity Gap without any legacy protocol actually being in play, and
        the Condition-11 drilldown rows ('Unknown') were useless for migration planning.

        The names match what Conditional Access itself groups under "Exchange ActiveSync clients"
        and "Other clients", and the allowlist in entra-workbook/
        ca-livegang-readiness.workbook.json. One definition of 'legacy' for both the module and
        the workbook.

        An unknown or new client type does NOT count as legacy; it falls into the 'unknown' class
        and is reported separately. Not measured is never the same as wrong.
    .OUTPUTS
        [string[]] The legacy clientApp names as Entra writes them.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return [string[]] @(
        'Exchange ActiveSync'
        'IMAP'
        'IMAP4'
        'POP'
        'POP3'
        'SMTP'
        'Authenticated SMTP'
        'MAPI'
        'MAPI Over HTTP'
        'Other clients'
        'Autodiscover'
        'Exchange Online PowerShell'
        'Exchange Web Services'
        'Offline Address Book'
        'Outlook Anywhere (RPC over HTTP)'
        'Outlook Service'
        'Reporting Web Services'
    )
}

function Get-CAInvClientAppClass {
    <#
    .SYNOPSIS
        Classifies a clientAppUsed value as 'legacy', 'modern', or 'unknown'.
    .DESCRIPTION
        The single place where the module decides what a clientApp value means, so Condition-09
        (Graph count) and Condition-11 (KQL drilldown) can never disagree.

        'unknown' covers three cases that all mean the same thing (we don't know): an empty
        value, the literal value 'Unknown', and a client type that appears in neither the
        legacy allowlist nor the modern list (e.g. a new type Microsoft adds later).
    .PARAMETER ClientAppUsed
        The raw clientAppUsed/ClientAppUsed value from the sign-in logs.
    .OUTPUTS
        [string] 'legacy', 'modern', or 'unknown'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ClientAppUsed
    )

    $c = "$ClientAppUsed".Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($c)) { return 'unknown' }

    $legacy = @(Get-CAInvLegacyClientApp | ForEach-Object { $_.ToLowerInvariant() })
    if ($legacy -contains $c) { return 'legacy' }

    if (@('browser', 'mobile apps and desktop clients') -contains $c) { return 'modern' }

    return 'unknown'
}
