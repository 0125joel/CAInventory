function Write-CAInvTemporaryAccessPassFinding {
    <#
    .SYNOPSIS
        Auth-03 — Temporary Access Pass as a bootstrap path.
    .DESCRIPTION
        A Temporary Access Pass (TAP) is a temporary code that lets someone without a registered
        method sign in anyway, and register a real method from there. Microsoft explicitly
        positions it that way: "Users can sign in with a TAP to onboard other passwordless
        authentication methods" (Microsoft Learn, howto-authentication-temporary-access-pass,
        verified 25-08-2026).

        Why this is a go-live dependency: the rollout condition chain has two conditions that
        depend on this — "There is a bootstrap path for admins without a method" (wave 2) and
        "The tail has a route that isn't a blocker" (wave 3). Both were unmeasured in
        config/rollout-waves.json. Without a bootstrap path, a phishing-resistant policy becomes,
        for anyone who hasn't registered anything yet, not a tightening but a closed door.

        The flip side belongs in the same recommendation: TAP itself does NOT count as
        phishing-resistant (see Auth-13 and Emergency-07). Bootstrapping must therefore be
        finished BEFORE a phishing-resistant policy takes effect, not after. An emergency account
        with only a TAP is not a valid end state.

        The configuration comes from the same response Auth-01 already reads; there's no extra
        call. All TAP-specific fields are read defensively: Graph omits unset fields, so a missing
        lifetime means "default", not "zero".
    .PARAMETER Layer
        The layer name under which the record is written.
    .PARAMETER Domain
        The domain number (6.5).
    .PARAMETER Config
        The authenticationMethodConfiguration of temporaryAccessPass, or $null when the policy
        doesn't mention that method.
    .PARAMETER GraphSource
        The source designation for the record.
    .PARAMETER RawPath
        Path to the written raw evidence.
    .OUTPUTS
        None. Writes one record via New-CAInvRecord.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][string] $Domain,
        [Parameter(Mandatory)][AllowNull()][object] $Config,
        [Parameter(Mandatory)][string] $GraphSource,
        [string] $RawPath
    )

    $migrationState = Get-CAInvProp $script:CAInvContext 'AuthMethodPolicyMigrationState' $null
    $caveat = if ($migrationState -and $migrationState -ne 'migrationComplete') {
        " Note: the tenant is set to $migrationState, not migrationComplete, so the authentication methods policy is not yet solely authoritative (see Auth-02)."
    }
    else { '' }

    $state = [string](Get-CAInvProp $Config 'state' '')

    if (-not $Config -or $state -ne 'enabled') {
        $observed = if (-not $Config) {
            'Temporary Access Pass is not present in the authentication methods policy.'
        }
        else {
            "Temporary Access Pass is set to state=$state."
        }
        New-CAInvRecord -Domain $Domain -CheckId 'Auth-03' -ObjectType 'AuthenticationMethod' `
            -ObjectName 'temporaryAccessPass' -Property 'state' -ObservedValue $observed `
            -Status 'Review required' -ManualReview `
            -GraphSource $GraphSource -RawPath $RawPath `
            -Recommendation ('There is no demonstrable bootstrap path for anyone who hasn''t registered a method yet. Assess how admins without a method and the tail of the user population will get to a strong method without being locked out; a Temporary Access Pass is Microsoft''s intended route for that. Turn it on and target it at the group you''re onboarding. Important: a TAP itself does not count as phishing-resistant, so bootstrapping must be finished before you enable a phishing-resistant policy, and an emergency account with only a TAP is not a valid end state.' + $caveat) | Out-Null
        return
    }

    $includeTargets = @(Get-CAInvProp $Config 'includeTargets' @())
    $excludeTargets = @(Get-CAInvProp $Config 'excludeTargets' @())

    $lifetimeParts = @()
    foreach ($f in @(
            @{ Name = 'defaultLifetimeInMinutes'; Label = 'default' }
            @{ Name = 'minimumLifetimeInMinutes'; Label = 'minimum' }
            @{ Name = 'maximumLifetimeInMinutes'; Label = 'maximum' }
        )) {
        $v = Get-CAInvProp $Config $f.Name $null
        if ($null -ne $v) { $lifetimeParts += "$($f.Label) $v min" }
    }
    $lifetimeText = if ($lifetimeParts.Count -gt 0) { $lifetimeParts -join ', ' } else { 'lifetime not in the response (Graph default values apply)' }

    $usableOnce = Get-CAInvProp $Config 'isUsableOnce' $null
    $usableText = if ($null -eq $usableOnce) { 'isUsableOnce not in the response' } elseif ([bool]$usableOnce) { 'usable once' } else { 'usable multiple times until the lifetime expires' }

    $observed = "state=enabled; $lifetimeText; $usableText; includeTargets=$($includeTargets.Count); excludeTargets=$($excludeTargets.Count)"

    New-CAInvRecord -Domain $Domain -CheckId 'Auth-03' -ObjectType 'AuthenticationMethod' `
        -ObjectName 'temporaryAccessPass' -Property 'state' -ObservedValue $observed `
        -Status 'Ready' -GraphSource $GraphSource -RawPath $RawPath `
        -Recommendation ('There is a bootstrap path. Do check that the targeting covers the groups you''re onboarding, and keep in mind that a TAP itself is not phishing-resistant: bootstrapping must be finished before you enable a phishing-resistant policy, and an emergency account with only a TAP is not a valid end state.' + $caveat) | Out-Null
}
