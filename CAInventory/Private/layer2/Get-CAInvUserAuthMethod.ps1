function Get-CAInvUserAuthMethod {
    <#
    .SYNOPSIS
        Domain 6.9 — Individual authentication methods per user (sensitive).
    .DESCRIPTION
        Layer 2 collector. Reads /users/{id}/authentication/methods per user and counts the
        registered method types. This function is sensitive by nature: phone numbers are ALWAYS
        masked, and the per-user details are only processed when the run was explicitly started
        with -IncludeSensitiveMethodDetails (context flag IncludeSensitive). Without that flag the
        collector only produces a Not assessed record with the reason, so readiness from
        userRegistrationDetails (6.8) stays authoritative and no sensitive data is recorded that
        wasn't requested.

        Auth-14 (2026-08-20, verification round): Microsoft's own authentication methods API
        overview advises against this per-user call for tenant-wide audit/reporting purposes
        (intended for user-management scenarios); userRegistrationDetails is the recommended route
        for reporting. This is exactly why this collector is opt-in and secondary to URD — only
        explicitly documented here, no behavior change.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.9'
    $src    = 'GET /users/{id}/authentication/methods'

    $ctx = $script:CAInvContext
    $includeSensitive = [bool](Get-CAInvProp $ctx 'IncludeSensitive' $false)

    if (-not $includeSensitive) {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-14' -ObjectType 'User' `
            -Property 'authenticationMethods' -Status 'Not assessed' `
            -NotAssessedReason ('Sensitive per-user method details not fetched: run without -IncludeSensitiveMethodDetails. Readiness comes from userRegistrationDetails (6.8).') `
            -GraphSource $src | Out-Null
        return
    }

    $users = @(if ($ctx.PSObject.Properties.Name -contains 'Users') { @($ctx.Users) } else { @() })
    if ($users.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-14' -ObjectType 'User' `
            -Property 'authenticationMethods' -Status 'Not assessed' `
            -NotAssessedReason ('User population not available (layer 1/Identity not run in this run).') `
            -GraphSource $src | Out-Null
        return
    }

    $processed = 0
    foreach ($u in $users) {
        if ($u.userType -ne 'Member') { continue }
        $mResp = Invoke-CAInvGraphOrNotAssessed -Uri "users/$($u.id)/authentication/methods" -ApiVersion 'v1.0' `
            -Domain $domain -CheckId 'Auth-14' -ObjectType 'User' `
            -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'authenticationMethods' `
            -GraphSource $src -NotAssessedReasonPrefix ('Could not read methods')
        if ($mResp.Failed) { continue }

        $methods = @($mResp.Value)

        $masked = foreach ($m in $methods) {
            $type = (Get-CAInvProp $m '@odata.type' '') -replace '#microsoft\.graph\.', '' -replace 'AuthenticationMethod', ''
            $phone = Get-CAInvProp $m 'phoneNumber'
            if ($phone) {
                $tail = if ($phone.Length -ge 4) { $phone.Substring($phone.Length - 4) } else { $phone }
                $phone = "***$tail"
            }
            [PSCustomObject]@{ Type = $type; PhoneNumber = $phone }
        }
        Write-CAInvRaw -Domain $domain -Endpoint "methods_$($u.id)" -Data $masked | Out-Null

        $types = @($masked | ForEach-Object { $_.Type } | Where-Object { $_ } | Select-Object -Unique)
        New-CAInvRecord -Domain $domain -CheckId 'Auth-14' -ObjectType 'User' `
            -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'methodTypes' `
            -ObservedValue ($(if ($types.Count) { $types -join ', ' } else { 'no methods registered' })) `
            -Status 'Ready' -GraphSource $src | Out-Null
        $processed++
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Methods processed for $processed users (sensitive mode; phone numbers masked)."
}
