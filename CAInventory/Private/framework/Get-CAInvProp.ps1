function Get-CAInvProp {
    <#
    .SYNOPSIS
        Safe property accessor for dynamic Microsoft Graph objects.
    .DESCRIPTION
        Microsoft Graph omits null/empty properties from the response. Under Set-StrictMode
        (Latest), directly accessing a missing property throws a PropertyNotFoundException. This
        helper returns the value when the property exists, and the given default otherwise.
        Supports a dot path for nested properties (e.g. 'conditions.users').

        First tries $Path as a LITERAL (non-nested) property name, before the dot-path traversal.
        This is needed for Graph's own annotation fields such as '@odata.type', which themselves
        have a literal dot in the name — without this step the dot-path splitter would try to read
        that as the nested property '@odata' → 'type', which doesn't exist, and would always
        silently return the default (discovered via a failing test on a derived @odata.type value,
        not via a crash — exactly the kind of silent bug this helper is meant to prevent).

        Supports both PSObject-like objects and hashtables/dictionaries. The latter is needed
        because not everything in the run context is a PSCustomObject: `$ctx.Preflight` and
        `$ctx.Config` are hashtables. On such an object, `PSObject.Properties['CheckIds']` doesn't
        exist, which meant this helper silently returned the default instead of the value before
        2026-08-21. Purely additive: paths that already worked keep behaving identically.

        Performance (2026-08-26): the read now happens inline, no longer via a scriptblock that
        returned a hashtable with a `Found` flag per segment. This helper is called hundreds of
        thousands of times in the sign-in summary, and there the fixed per-call cost dominates the
        actual work. Measured on the REAL sign-ins from run 20260826-075950 (42,456 of them,
        ~800,000 calls), old and new implementation in the same session and call shape: 9.7s/6.8s
        -> 4.4s/4.0s, with identical outcomes. The new variant is also more stable between rounds.

        Note the proportion: during a real run, the same loop cost 33-37s, so four to eight times
        as much as measured here. That loop isn't the problem; what happens around it during a
        full run (memory pressure over the complete collected dataset) is. This optimization is
        real, but doesn't explain the lion's share of that 33-37s.

        The distinction between "property exists with value `$null`" and "property doesn't exist"
        remains essential and must not be lost in a future change. It now runs through the
        structure itself: the found branch returns immediately, the not-found branch falls
        through. Deliberately NO sentinel variable in module scope: a `$script:` lookup inside a
        module cost ~21s extra over 850,000 calls in that same measurement, more than the whole
        optimization gained.
    .EXAMPLE
        $inc = Get-CAInvProp $policy 'conditions.users.includeGroups' @()
    .EXAMPLE
        $type = Get-CAInvProp $policy '@odata.type' ''
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory)]
        [string] $Path,

        $Default = $null
    )

    if ($null -eq $InputObject) { return $Default }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Path)) {
            $value = $InputObject[$Path]
            if ($null -eq $value) { return $Default }
            return $value
        }
    }
    else {
        $prop = $InputObject.PSObject.Properties[$Path]
        if ($prop) {
            if ($null -eq $prop.Value) { return $Default }
            return $prop.Value
        }
    }

    $current = $InputObject
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $current) { return $Default }

        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($segment)) { return $Default }
            $current = $current[$segment]
        }
        else {
            $segProp = $current.PSObject.Properties[$segment]
            if (-not $segProp) { return $Default }
            $current = $segProp.Value
        }
    }

    if ($null -eq $current) { return $Default }
    return $current
}
