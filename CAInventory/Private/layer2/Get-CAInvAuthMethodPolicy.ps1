function Get-CAInvAuthMethodPolicy {
    <#
    .SYNOPSIS
        Domain 6.5 — Authentication methods policy.
    .DESCRIPTION
        Layer 2 collector. Reads /policies/authenticationMethodsPolicy and the
        authenticationMethodConfigurations within it, and records per method whether it's on or
        off and what the targeting looks like. This is the 'allowed' axis of the method matrix: what the tenant policy ALLOWS, separate from what users have
        registered or actually use.

        The normalized method configurations are kept in the context object (AuthMethodPolicy) so
        Get-CAInvMethodUsageMatrix can combine them at the end of the chain without reading again.
        The newest methods often appear in beta first; this source stays on v1.0 but records
        unknown methods unchanged.

        Auth-02 reads the migration status (policyMigrationState) from the same response. That
        determines whether this policy is even authoritative at all: only at migrationComplete are
        the legacy MFA and SSPR settings ignored. If the tenant is still ahead of that, Auth-01 and
        the whole method matrix measure a policy that in practice isn't the only one in effect. The
        outcome of those checks is then factually correct and practically misleading, and a reader
        should know that.

        Auth-03 reads the Temporary Access Pass configuration from the same response: the bootstrap
        path Microsoft intends for someone who hasn't registered a method yet. Two conditions in
        the rollout order depend on it.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.5'
    $src    = 'GET /policies/authenticationMethodsPolicy'

    $resp = Invoke-CAInvGraphOrNotAssessed -Uri 'policies/authenticationMethodsPolicy' -ApiVersion 'v1.0' `
        -Domain $domain -CheckId 'Auth-01' -ObjectType 'Policy' -Property 'authenticationMethodConfigurations' `
        -GraphSource $src -NotAssessedReasonPrefix ('Could not read authenticationMethodsPolicy')
    if ($resp.Failed) { return }

    $policy = @($resp.Value) | Select-Object -First 1
    $configs = @(Get-CAInvProp $policy 'authenticationMethodConfigurations' @())
    $raw = Write-CAInvRaw -Domain $domain -Endpoint 'authenticationMethodConfigurations' -Data $configs

    Write-CAInvAuthMethodMigrationFinding -Domain $domain -Policy $policy -GraphSource $src -RawPath $raw

    if ($configs.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-01' -ObjectType 'Policy' `
            -Property 'authenticationMethodConfigurations' `
            -ObservedValue 'No method configurations found.' -Status 'Review required' `
            -ManualReview -GraphSource $src -RawPath $raw `
            -Recommendation ('Expected at least one configured method. Check whether the tenant is still running on the legacy MFA/SSPR policy.') | Out-Null

        New-CAInvRecord -Domain $domain -CheckId 'Auth-03' -ObjectType 'AuthenticationMethod' `
            -ObjectName 'temporaryAccessPass' -Property 'state' -Status 'Not assessed' `
            -NotAssessedReason ('The authentication methods policy contains no method configurations, so the state of Temporary Access Pass cannot be determined.') `
            -GraphSource $src -RawPath $raw | Out-Null
        return
    }

    $normalized = [System.Collections.Generic.List[object]]::new()
    $tapConfig = $null

    foreach ($c in $configs) {

        $odataType = Get-CAInvProp $c '@odata.type' ''
        $methodId  = Get-CAInvProp $c 'id' ''
        $methodName = if ($odataType) {
            ($odataType -replace '#microsoft\.graph\.', '' -replace 'AuthenticationMethodConfiguration', '')
        } else { $methodId }

        if ($methodName -eq 'temporaryAccessPass') { $tapConfig = $c }

        $state = Get-CAInvProp $c 'state' 'disabled'
        $includeTargets = @(Get-CAInvProp $c 'includeTargets' @())
        $excludeTargets = @(Get-CAInvProp $c 'excludeTargets' @())

        [void]$normalized.Add([PSCustomObject]@{
            MethodId       = $methodName
            State          = $state
            EnabledInPolicy = ($state -eq 'enabled')
            IncludeTargets = $includeTargets
            ExcludeTargets = $excludeTargets
        })

        $targetText = "includeTargets=$($includeTargets.Count); excludeTargets=$($excludeTargets.Count)"
        New-CAInvRecord -Domain $domain -CheckId 'Auth-01' -ObjectType 'AuthenticationMethod' `
            -ObjectName $methodName -Property 'state' `
            -ObservedValue "state=$state; $targetText" `
            -Status 'Ready' -GraphSource $src -RawPath $raw | Out-Null
    }

    Add-CAInvContextData -Context $script:CAInvContext -Name 'AuthMethodPolicy' -Value @($normalized)

    Write-CAInvTemporaryAccessPassFinding -Domain $domain -Config $tapConfig -GraphSource $src -RawPath $raw

    $enabledCount = @($normalized | Where-Object { $_.EnabledInPolicy }).Count
    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($normalized.Count) method configurations read ($enabledCount enabled)."
}
