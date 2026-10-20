function Get-CAInvConditionKey {
    <#
    .SYNOPSIS
        The decision key for a rollout condition that has no measurement of its own.
    .DESCRIPTION
        The decisions a reviewer checks off in the report are stored in the browser under
        localStorage['cainv-decisions:' + tenantId], keyed on the finding key from
        Get-CAInvRolloutFindingKey. A condition without mapped checkIds has no finding at all,
        though, and therefore no key: precisely the conditions that the requireAllConditionsMeasured
        criterion needs to be able to check off were not checkable before this key existed.

        This function supplies that missing key. The shape deliberately matches the finding key
        (tenantId is prepended client-side, the rest is this) and uses the POSITION of the
        condition within its wave (or within nonSequentialConditions), not the label. A label
        can be reworded without any change in meaning, which would silently orphan its decisions.
        A sequence number is fragile against a reordering of config/rollout-waves.json, but
        reorderings are rare in practice: new conditions get added and existing ones are never
        resorted, so position is the stable identity.

        Client-side, the key stays an opaque string: the JS in New-CAInvRolloutPlan.ps1 only ever
        does decisions[key], never parses it. So the key shape may change freely as long as both
        sides (writing here, reading there) use the same recipe.

        The CONDITION segment distinguishes these keys from finding keys in the same store; a
        CheckId can never take that value.
    .PARAMETER ScopeId
        The wave id, or 'nonseq' for the standalone conditions per policy type.
    .PARAMETER Index
        The position (0-based) of the condition within its wave, resp. within
        nonSequentialConditions, in the order of config/rollout-waves.json.
    .OUTPUTS
        String. The key without the tenant prefix; the client prepends that itself.
    .EXAMPLE
        Get-CAInvConditionKey -ScopeId 'admins' -Index 0
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string] $ScopeId,
        [Parameter(Mandatory)][int] $Index
    )

    return ('CONDITION|{0}|{1}' -f $ScopeId, $Index)
}
