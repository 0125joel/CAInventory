
$script:CAInvServiceAccountPattern = '(?i)\b(svc|service|sa-|admin-svc|shared|room|equip|test|automation|noreply|no-reply)\b'

function Test-CAInvServiceAccountName {
    <#
    .SYNOPSIS
        Heuristic: does this account look like a service, shared, or test account?
    .DESCRIPTION
        One definition for Identity-02 (flagging), Identity-04 (within 'All users' CA scope), and
        Auth-09 (within the registration campaign). The pattern previously lived verbatim in two
        files; that's exactly the kind of duplication where a change on one side silently creates
        a difference between three checks that, by definition, should measure the same
        population.

        This remains a NAME heuristic and therefore never yields a hard verdict. Graph has no
        field that marks an account as a service account: a shared mailbox, an application
        account, and an ordinary user are all three a user object. That's why the outcome is
        always 'Review required' and never 'Gap' (hard rule: never guess).
    .PARAMETER User
        A Graph user object with userPrincipalName and displayName.
    .OUTPUTS
        Boolean.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowNull()][object] $User
    )

    if (-not $User) { return $false }

    if ((Get-CAInvProp $User 'userType' '') -ne 'Member') { return $false }

    $name = "$(Get-CAInvProp $User 'userPrincipalName' '') $(Get-CAInvProp $User 'displayName' '')"
    return ($name -match $script:CAInvServiceAccountPattern)
}
