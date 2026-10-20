function Get-CAInvGlobalAdminPrincipal {
    <#
    .SYNOPSIS
        Filters a set of privileged principals down to the Global Administrator role.
    .DESCRIPTION
        Owner of the fixed templateId of Global Administrator (config/admin-roles.json,
        roleTemplateIds.globalAdministrator) and of the fallback to the role name in case the role
        definition doesn't resolve. Those two were, before 0.37.0, written out in
        Get-CAInvPrivilegedAccess, Get-CAInvEmergencyAccess, and Get-CAInvDailyAdmin.

        Deliberately does NOT filter on permanence or principal type on its own: those choices
        differ per consumer. Combine with Test-CAInvPermanentAssignment for "permanent" and with
        -UsersOnly where only users count.
    .EXAMPLE
        $ga = Get-CAInvGlobalAdminPrincipal -Principal $ctx.PrivilegedPrincipals
    .EXAMPLE
        $permanentGaUsers = @(Get-CAInvGlobalAdminPrincipal -Principal $priv -UsersOnly |
            Where-Object { Test-CAInvPermanentAssignment $_ })
    .OUTPUTS
        Array of the principals that hold the Global Administrator role (empty if there are none).
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyCollection()]
        $Principal,

        [switch] $UsersOnly
    )

    $gaTemplate = Get-CAInvRoleTemplateId -Name 'globalAdministrator' -Fallback '62e90394-69f5-4237-9190-012177145e10'

    $result = @(@($Principal) | Where-Object {
            $null -ne $_ -and (
                (Get-CAInvProp $_ 'roleTemplate' '') -eq $gaTemplate -or
                (Get-CAInvProp $_ 'roleName' '') -eq 'Global Administrator'
            )
        })

    if ($UsersOnly) {
        $result = @($result | Where-Object { (Get-CAInvProp $_ 'principalType' '') -like '*user*' })
    }

    return $result
}
