function Get-CAInvRoleTemplateId {
    <#
    .SYNOPSIS
        Reads a fixed role/policy GUID from config/admin-roles.json (roleTemplateIds).
    .DESCRIPTION
        These GUIDs (Global Administrator, Directory Synchronization Accounts, the
        restricted guestUserRoleId) were hardcoded in four files, while config/admin-roles.json
        already carries source/verifiedOn provenance for exactly this kind of value. One shared
        reader instead of four separate copies of the same fallback logic.

        Falls back to $Fallback (with a WARN) when the config key is missing: these GUIDs are
        stable, Microsoft-published constants, not measured values — a broken or outdated config
        must therefore never hard-fail role recognition.
    .PARAMETER Name
        Key under roleTemplateIds in config/admin-roles.json, e.g. 'globalAdministrator'.
    .PARAMETER Fallback
        The last known GUID, used when the config key is missing or empty.
    .OUTPUTS
        String: the GUID.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $Fallback
    )

    $id = [string](Get-CAInvProp $script:CAInvContext "Config.AdminRoles.roleTemplateIds.$Name.id" '')
    if ([string]::IsNullOrWhiteSpace($id)) {
        Write-CAInvLog -Level 'WARN' -Message "Role GUID '$Name' not found in config/admin-roles.json (roleTemplateIds); falling back to hardcoded value."
        return $Fallback
    }
    return $id
}
