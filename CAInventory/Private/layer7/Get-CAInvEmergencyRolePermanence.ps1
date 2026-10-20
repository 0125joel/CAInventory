function Get-CAInvEmergencyRolePermanence {
    <#
    .SYNOPSIS
        Emergency-08 — is there emergency access that doesn't depend on PIM?
    .DESCRIPTION
        Cross-check in layer 7, for the same reason as Identity-19: it needs both the role
        assignments (layer 1, Identity-09) and the confirmed emergency accounts (layer 1,
        Emergency-01), and the second doesn't exist until the first has run.

        Microsoft is explicit about the requirement (Manage emergency access admin accounts,
        accessed 26-08-2026): "In Privileged Identity Management, assign the Global Administrator
        role as permanent active (not eligible) for emergency accounts." That same page literally
        names the opposite situation as a lockout scenario: every GA assignment eligible,
        activation requires approval, and no approver available, after which nobody can activate
        anymore and tenant administration is effectively locked.

        Why this is its own check and not a sentence in Emergency-02: that one judges PER confirmed
        emergency account, so it stays silent precisely when there is no confirmed emergency
        account. That's exactly when the question "does anyone here still have a role that works
        without PIM?" is most urgent.

        The verdict deliberately covers the whole tenant, not individual accounts:
          - Not a single permanent Global Admin -> Gap. There's no way in that doesn't go through
            PIM activation.
          - Permanent Global Admins exist, confirmed emergency accounts exist, but none of those
            emergency accounts has one -> Gap. The permanent roles then sit with day-to-day admins,
            not with the accounts meant for an outage.
          - Otherwise -> Ready.

        Without confirmed emergency accounts and WITH permanent Global Admins, it stays at Ready
        with an explanation: that emergency accounts are missing is Emergency-01's message, and
        reporting that twice doesn't sharpen the report.
    .OUTPUTS
        None. Writes one record via New-CAInvRecord.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $domain = '6.4'
    $src    = 'Aggregation: PrivilegedPrincipals x confirmed emergency accounts'

    $ctx = $script:CAInvContext

    $hasPrivileged = $ctx.PSObject.Properties.Name -contains 'PrivilegedPrincipals'
    $hasEmergency  = $ctx.PSObject.Properties.Name -contains 'EmergencyAccountsConfirmed'

    if (-not $hasPrivileged -or -not $hasEmergency) {
        $missing = @()
        if (-not $hasPrivileged) { $missing += 'the role assignments from layer 1 (Identity-09)' }
        if (-not $hasEmergency)  { $missing += 'the emergency account determination from layer 1 (Emergency-01)' }
        New-CAInvRecord -Domain $domain -CheckId 'Emergency-08' -ObjectType 'EmergencyAccess' `
            -ObjectName 'Global Administrator' -Property 'permanentEmergencyAccess' -Status 'Not assessed' `
            -NotAssessedReason ('Cannot be determined without {0}.' -f @($missing -join ' and ')) `
            -ApiVersion 'n/a' -GraphSource $src | Out-Null
        return
    }

    $permanent = @(Get-CAInvGlobalAdminPrincipal -Principal $ctx.PrivilegedPrincipals -UsersOnly |
            Where-Object { Test-CAInvPermanentAssignment $_ })
    $confirmed = @($ctx.EmergencyAccountsConfirmed)
    $confirmedIds = @($confirmed | ForEach-Object { [string](Get-CAInvProp $_ 'id') })
    $permanentBreakGlass = @($permanent | Where-Object { $confirmedIds -contains [string]$_.principalId })

    $learn = 'Microsoft: assign the Global Administrator role to emergency accounts as permanently active, not eligible. A tenant where every GA assignment is eligible can lock itself out the moment activation fails.'

    if ($permanent.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Emergency-08' -ObjectType 'EmergencyAccess' `
            -ObjectName 'Global Administrator' -Property 'permanentEmergencyAccess' `
            -ObservedValue 'No user at all has a permanent Global Admin role; every assignment runs via PIM eligibility or a temporary activation.' `
            -Status 'Gap' -ApiVersion 'n/a' -GraphSource $src `
            -Recommendation ('There is no way in that doesn''t depend on PIM. If activation fails (outage, no approver, MFA unreachable), nobody can reach tenant administration anymore. Give at least two cloud-only emergency accounts a permanent Global Admin role. {0}' -f @($learn)) | Out-Null

        Write-CAInvLog -Level 'INFO' -Domain $domain -Message 'Emergency-08: no permanent GA assignment at all; emergency access depends entirely on PIM.'
        return
    }

    if ($confirmed.Count -gt 0 -and $permanentBreakGlass.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Emergency-08' -ObjectType 'EmergencyAccess' `
            -ObjectName 'Global Administrator' -Property 'permanentEmergencyAccess' `
            -ObservedValue "$($permanent.Count) permanent Global Admin(s), but none of the $($confirmed.Count) confirmed emergency account(s) is among them." `
            -Status 'Gap' -ApiVersion 'n/a' -GraphSource $src `
            -Recommendation ('The permanent roles sit with day-to-day admins instead of with the accounts meant for an outage. Make the emergency accounts'' Global Admin assignment permanently active. {0}' -f @($learn)) | Out-Null

        Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Emergency-08: $($permanent.Count) permanent GAs, none of them a confirmed emergency account."
        return
    }

    $observed = if ($permanentBreakGlass.Count -gt 0) {
        "$($permanentBreakGlass.Count) confirmed emergency account(s) with a permanent Global Admin role."
    }
    else {
        "$($permanent.Count) permanent Global Admin(s) present; no confirmed emergency accounts to compare against."
    }
    $rec = if ($permanentBreakGlass.Count -gt 0) {
        'There is emergency access that doesn''t depend on PIM activation. Keep that assignment permanent, even if you do move the day-to-day admins to eligible.'
    }
    else {
        'There is at least one permanent Global Admin, so tenant administration cannot be locked out by a failed PIM activation. Which accounts are emergency accounts hasn''t been confirmed; Emergency-01 reports that separately. Confirm the set with -EmergencyAccountUpn for a definitive verdict.'
    }

    New-CAInvRecord -Domain $domain -CheckId 'Emergency-08' -ObjectType 'EmergencyAccess' `
        -ObjectName 'Global Administrator' -Property 'permanentEmergencyAccess' `
        -ObservedValue $observed -Status 'Ready' `
        -ApiVersion 'n/a' -GraphSource $src -Recommendation $rec | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Emergency-08: $($permanentBreakGlass.Count) emergency account(s) with permanent GA, out of $($permanent.Count) permanent GA assignment(s)."
}
