function Resolve-CAInvServicePrincipalByAppId {
    <#
    .SYNOPSIS
        Looks up the service principal for an appId, first in the run context, then via Graph.
    .DESCRIPTION
        Shared resolution for Foundation-12 (naming excluded apps readably) and Foundation-14
        (ownership of excluded apps). Those two checks previously did this independently of each
        other, with the visible consequence that Foundation-12 reported raw GUIDs while
        Foundation-14 ten lines further down had already resolved the same appIds to a
        displayName. A reviewer would get a finding with 'd4ebce55-015a-49b5-a083-c84d1797ae8c'
        even though the name was known within the run.

        Resolution order:
          1. The ServicePrincipals collection on the context object (layer 3), if present.
          2. A targeted Graph query on appId. Invoke-CAInvGraph caches that per URI, including
             negative results, so an appId that doesn't resolve is queried once per run.

        Returns $null when the appId can't be resolved; that's an outcome, not an error. The
        caller decides whether that yields 'Not assessed' or just less-rich text.
    .PARAMETER AppId
        The application id (client id) from a CA policy.
    .OUTPUTS
        The service principal object, or $null.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][string] $AppId
    )

    $ctx = $script:CAInvContext
    $known = @(Get-CAInvProp $ctx 'ServicePrincipals' @())

    foreach ($sp in $known) {
        if ((Get-CAInvProp $sp 'appId' '') -eq $AppId) { return $sp }
    }

    $resp = Invoke-CAInvGraph -Uri "servicePrincipals?`$filter=appId eq '$AppId'&`$select=id,appId,displayName,appOwnerOrganizationId" -ApiVersion 'v1.0'
    if ($resp.Failed) { return $null }

    $found = @($resp.Value)
    if ($found.Count -eq 0) { return $null }
    return $found[0]
}

function Test-CAInvServicePrincipalIsForeign {
    <#
    .SYNOPSIS
        Is this service principal owned by a tenant other than the one under review?
    .DESCRIPTION
        A service principal with an appOwnerOrganizationId that isn't the tenant's own belongs to
        someone else's multi-tenant application: one of Microsoft's own first-party apps (Intune
        Enrollment, Device Registration Service, Windows 365, ...) or a SaaS vendor. Such service
        principals have, by definition, no owners in your tenant, because the object is only the
        local representation of an app managed elsewhere.

        That makes the ownership check (Foundation-14) meaningless there: 'zero owners' isn't a
        shortcoming anyone can fix, so it isn't a Gap. Without this distinction, Foundation-14
        reported six Microsoft apps as 'Gap: no owner' on the reference tenant — exactly the kind
        of noise that teaches a reviewer to click findings away.

        When appOwnerOrganizationId is missing or the tenant's own id is unknown, this function
        returns $false: being unable to determine ownership isn't evidence of foreign ownership,
        and the check should just run normally (never guess).
    .PARAMETER ServicePrincipal
        The service principal object.
    .OUTPUTS
        Boolean.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowNull()][object] $ServicePrincipal
    )

    if (-not $ServicePrincipal) { return $false }

    $owner = [string](Get-CAInvProp $ServicePrincipal 'appOwnerOrganizationId' '')
    if ([string]::IsNullOrWhiteSpace($owner)) { return $false }

    $tenantId = [string](Get-CAInvProp $script:CAInvContext 'TenantId' '')
    if ([string]::IsNullOrWhiteSpace($tenantId)) { return $false }

    return ($owner -ne $tenantId)
}
