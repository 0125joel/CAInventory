function Invoke-CAInvGraphOrNotAssessed {
    <#
    .SYNOPSIS
        DRY helper: combines an Invoke-CAInvGraph call with the standard 'Graph fails ->
        Not assessed' handling.
    .DESCRIPTION
        Before this helper, the pattern "call Invoke-CAInvGraph; on .Failed write a Not assessed
        record with NotAssessedReason 'Could not read X: <ErrorMessage>'" was repeated verbatim
        across dozens of collectors. This helper centralizes that one, most common case.

        Calls Invoke-CAInvGraph. On failure this function ITSELF writes the Not assessed record
        (NotAssessedReason = "<Prefix>: <ErrorMessage>") and then returns the same result object
        Invoke-CAInvGraph always returned. The caller still checks .Failed itself to decide
        whether to return/continue — that control flow differs per collector (end of function,
        loop continue) and therefore belongs with the caller, not in this helper.

        Only suited to the simple case: a single Not assessed record with only the standard
        fields. If a collector needs extra fields (-ManualReview, -Recommendation, -RawPath,
        -LicenseRequirement) or a composite/deviating reason, the explicit Invoke-CAInvGraph +
        New-CAInvRecord combination remains the right choice — don't force those cases through
        this helper.
    .PARAMETER Heartbeat
        Passed straight through to Invoke-CAInvGraph (see there): opt-in, off by default.
    .OUTPUTS
        PSCustomObject: the same result object as Invoke-CAInvGraph
        (@{ Value; ApiVersion; Uri; Failed; ErrorMessage; StatusCode; FromCache }).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string] $Uri,

        [ValidateSet('v1.0', 'beta')]
        [string] $ApiVersion = 'v1.0',

        [switch] $NoCache,

        [int] $MaxPages = 0,

        [Parameter(Mandatory)]
        [string] $Domain,

        [Parameter(Mandatory)]
        [string] $CheckId,

        [Parameter(Mandatory)]
        [string] $NotAssessedReasonPrefix,

        [string] $ObjectType,
        [string] $ObjectId,
        [string] $ObjectName,
        [string] $Property,
        [string] $GraphSource,

        [switch] $Heartbeat
    )

    $resp = Invoke-CAInvGraph -Uri $Uri -ApiVersion $ApiVersion -NoCache:$NoCache -MaxPages $MaxPages -Heartbeat:$Heartbeat

    if ($resp.Failed) {
        $src = if ($GraphSource) { $GraphSource } else { "GET $Uri" }
        New-CAInvRecord -Domain $Domain -CheckId $CheckId -ObjectType $ObjectType `
            -ObjectId $ObjectId -ObjectName $ObjectName -Property $Property -Status 'Not assessed' `
            -NotAssessedReason "${NotAssessedReasonPrefix}: $($resp.ErrorMessage)" `
            -GraphSource $src -ApiVersion $ApiVersion | Out-Null
    }

    return $resp
}
