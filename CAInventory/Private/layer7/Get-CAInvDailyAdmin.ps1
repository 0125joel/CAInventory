function Get-CAInvDailyAdmin {
    <#
    .SYNOPSIS
        Identity-19 — how many of the permanent Global Admins are day-to-day admins.
    .DESCRIPTION
        Cross-check. Identity-09 counts the permanent Global Administrators and its recommendation
        assumes two of them are emergency accounts. It has no way to verify that assumption:
        Get-CAInvPrivilegedAccess runs in layer 1 before Get-CAInvEmergencyAccess, because the
        latter needs precisely the role assignments. At the moment Identity-09 writes its record,
        the confirmed emergency account set therefore doesn't exist yet.

        By layer 7, both datasets exist. This function subtracts the confirmed emergency accounts
        from the permanent Global Admins and reports what's left: the admins who work day in, day
        out with a standing Global Admin role. That's the number the PIM trade-off is actually
        about.

        Deliberately no norm of its own. Microsoft draws its line at the total number of GA
        assignments, not at this derived number; a self-invented threshold would be a guess. The
        verdict therefore stays with Identity-09, this check only makes visible how the five are
        composed.

        Without confirmed emergency accounts, the subtraction can't be made. That produces
        'Not assessed' with a reason, not the full number silently: an unconfirmed set is different
        from an empty set, and Emergency-01 already reports that gap as a Gap.

        Exception: if there are zero permanent assignments, the outcome is simply zero and the
        subtraction is moot. In that case 'Not assessed' would claim we don't know something we
        actually do.
    .OUTPUTS
        None. Writes one record via New-CAInvRecord.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $domain = '6.13'
    $src    = 'Aggregation: PrivilegedPrincipals x confirmed emergency accounts'

    $ctx = $script:CAInvContext

    $hasPrivileged = $ctx.PSObject.Properties.Name -contains 'PrivilegedPrincipals'
    $hasEmergency  = $ctx.PSObject.Properties.Name -contains 'EmergencyAccountsConfirmed'

    if (-not $hasPrivileged -or -not $hasEmergency) {
        $missing = @()
        if (-not $hasPrivileged) { $missing += 'the role assignments from layer 1 (Identity-09)' }
        if (-not $hasEmergency)  { $missing += 'the emergency account determination from layer 1 (Emergency-01)' }
        New-CAInvRecord -Domain $domain -CheckId 'Identity-19' -ObjectType 'DirectoryRole' `
            -ObjectName 'Global Administrator' -Property 'dailyGlobalAdminCount' -Status 'Not assessed' `
            -NotAssessedReason ('Cannot be determined without {0}.' -f @($missing -join ' and ')) `
            -ApiVersion 'n/a' -GraphSource $src | Out-Null
        return
    }

    $permanent = @(Get-CAInvGlobalAdminPrincipal -Principal $ctx.PrivilegedPrincipals -UsersOnly |
            Where-Object { Test-CAInvPermanentAssignment $_ })
    $confirmed = @($ctx.EmergencyAccountsConfirmed)

    if ($permanent.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-19' -ObjectType 'DirectoryRole' `
            -ObjectName 'Global Administrator' -Property 'dailyGlobalAdminCount' `
            -ObservedValue 0 -Status 'Ready' -ApiVersion 'n/a' -GraphSource $src `
            -Recommendation ('No user has a permanent Global Admin role; everything runs via PIM eligibility or temporary activation. For day-to-day admins that''s exactly the intent. The flip side is covered by Emergency-08: your emergency accounts should have that role permanently, or your emergency access depends on the very system you can''t reach during an outage.') | Out-Null

        Write-CAInvLog -Level 'INFO' -Domain $domain -Message 'No permanent GA assignments; zero daily admins with permanent GA.'
        return
    }

    if ($confirmed.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-19' -ObjectType 'DirectoryRole' `
            -ObjectName 'Global Administrator' -Property 'dailyGlobalAdminCount' -Status 'Not assessed' `
            -NotAssessedReason ('No confirmed emergency accounts, so of the {0} permanent Global Admins, it cannot be determined how many are day-to-day admins. Confirm the set with -EmergencyAccountUpn.' -f @($permanent.Count)) `
            -ApiVersion 'n/a' -GraphSource $src | Out-Null
        return
    }

    $confirmedIds = @($confirmed | ForEach-Object { [string](Get-CAInvProp $_ 'id') })
    $breakGlassMetGa = @($permanent | Where-Object { $confirmedIds -contains [string]$_.principalId })
    $daily = @($permanent | Where-Object { $confirmedIds -notcontains [string]$_.principalId })

    $namen = if ($daily.Count -gt 0) { (@($daily | ForEach-Object { $_.principalName }) -join ', ') } else { 'none' }
    $observed = "$($daily.Count) of $($permanent.Count) permanent Global Admins are day-to-day admins; $($breakGlassMetGa.Count) confirmed emergency account. Day-to-day: $namen."

    $rec = if ($breakGlassMetGa.Count -lt $confirmed.Count) {
        'Note: {0} confirmed emergency account(s), of which {1} has a permanent Global Admin role. An emergency account without a permanent role cannot do what it''s meant for during an outage.' -f @($confirmed.Count, $breakGlassMetGa.Count)
    } else {
        'These are the admins working with a standing Global Admin role. Consider making them eligible via PIM; the emergency accounts, on the other hand, should stay permanent.'
    }

    New-CAInvRecord -Domain $domain -CheckId 'Identity-19' -ObjectType 'DirectoryRole' `
        -ObjectName 'Global Administrator' -Property 'dailyGlobalAdminCount' `
        -ObservedValue $daily.Count -Status 'Ready' `
        -ApiVersion 'n/a' -GraphSource $src -Recommendation "$observed $rec" | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($daily.Count) daily admins with permanent GA (of $($permanent.Count), $($breakGlassMetGa.Count) emergency account(s))."
}
