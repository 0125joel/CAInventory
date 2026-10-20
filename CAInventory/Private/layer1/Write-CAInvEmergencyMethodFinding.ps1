function Write-CAInvEmergencyMethodFinding {
    <#
    .SYNOPSIS
        Emergency-07 — does every confirmed emergency account have a phishing-resistant method registered?
    .DESCRIPTION
        This is the point where Microsoft's guidance changed most sharply. A break-glass account is
        no longer an account you exempt from verification: since MFA became mandatory for the admin
        portals, it must be able to sign in itself with a strong method. From the mandatory-MFA
        article: "Break glass or emergency access accounts are also required to sign in with MFA
        once enforcement begins. We recommend that you update these accounts to use passkey (FIDO2)
        or ... certificate-based authentication." The emergency-access article names passkey
        (FIDO2) as the recommended choice and certificate-based authentication as an alternative
        when a PKI is already in place.

        That same article also asks for a DIFFERENT method than regular admins use: "make sure it
        doesn't use the same authentication methods as your other administrative accounts." Hence
        the extra cross-comparison at the end.

        Note the connection to Auth-13: a Temporary Access Pass does not count as phishing-resistant
        and is therefore not a valid end state for an emergency account, only a bootstrap aid.

        What counts as phishing-resistant is NOT hardcoded here but derived from
        config/method-strength-map.json: weight 5 (the strongest tier) AND mfaStrength true. Those
        two conditions together exclude exactly the right things. A single-factor certificate does
        have weight 5 but mfaStrength false; certificateBasedAuthentication has mfaStrength null
        because the registration doesn't show whether it's set up as single- or multifactor, and
        therefore yields a Review instead of a Ready. One source for method strength, shared with
        Auth-12 and the method matrix.

        Runs only on the set CONFIRMED by Get-CAInvEmergencyAccess. Without a confirmed set, no
        record: the rollout plan then shows that condition as unmeasured, which is more honest than
        a verdict on accounts we don't know are emergency accounts.

        The registration details are fetched here per account instead of from
        $ctx.UserRegistrationDetails: that collection is only built in layer 2, and this check runs
        in layer 1. It's a handful of accounts, so a targeted call per account is cheaper than
        reordering the layers.
    .PARAMETER Layer
        The layer name under which the records are written.
    .PARAMETER Domain
        The domain number (6.4).
    .PARAMETER Account
        The confirmed emergency accounts (Graph user objects).
    .PARAMETER RawPath
        Path to the written raw evidence.
    .OUTPUTS
        None. Writes records via New-CAInvRecord.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][string] $Domain,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Account,
        [string] $RawPath
    )

    $accounts = @($Account)
    if ($accounts.Count -eq 0) { return }

    $src = 'GET /reports/authenticationMethods/userRegistrationDetails/{id}'

    $ctx = $script:CAInvContext
    $map = if ($ctx.PSObject.Properties.Name -contains 'Config' -and $ctx.Config -and $ctx.Config.MethodStrengthMap) {
        $ctx.Config.MethodStrengthMap
    }
    else {
        (Get-CAInvConfig).MethodStrengthMap
    }

    if (-not $map) {
        foreach ($u in $accounts) {
            New-CAInvRecord -Domain $Domain -CheckId 'Emergency-07' -ObjectType 'User' `
                -ObjectId $u.id -ObjectName $u.userPrincipalName -Property 'phishingResistantMethod' `
                -Status 'Not assessed' -NotAssessedReason ('config/method-strength-map.json could not be loaded; method strength cannot be determined.') `
                -GraphSource $src | Out-Null
        }
        return
    }

    $resistant = [System.Collections.Generic.List[string]]::new()
    $ambiguous = [System.Collections.Generic.List[string]]::new()
    foreach ($prop in $map.methods.PSObject.Properties) {
        $weight = Get-CAInvProp $prop.Value 'weight' 0
        $mfa = Get-CAInvProp $prop.Value 'mfaStrength' $null
        if ([int]$weight -ne 5) { continue }
        if ($mfa -eq $true) { [void]$resistant.Add($prop.Name) }
        elseif ($null -eq $mfa) { [void]$ambiguous.Add($prop.Name) }
    }

    $seenMethods = @{}

    foreach ($u in $accounts) {
        $uid = [string]$u.id
        $upn = [string]$u.userPrincipalName

        $resp = Invoke-CAInvGraph -Uri "reports/authenticationMethods/userRegistrationDetails/$uid" -ApiVersion 'v1.0'
        if ($resp.Failed) {
            New-CAInvRecord -Domain $Domain -CheckId 'Emergency-07' -ObjectType 'User' `
                -ObjectId $uid -ObjectName $upn -Property 'phishingResistantMethod' `
                -Status 'Not assessed' `
                -NotAssessedReason ('Could not read this emergency account''s registration details: {0}' -f @($resp.ErrorMessage)) `
                -GraphSource $src -RawPath $RawPath | Out-Null
            continue
        }

        $detail = @($resp.Value) | Select-Object -First 1
        $methods = @(Get-CAInvProp $detail 'methodsRegistered' @())

        $strong = @($methods | Where-Object { $resistant -contains $_ })
        $unclear = @($methods | Where-Object { $ambiguous -contains $_ })
        $methodText = if ($methods.Count -gt 0) { ($methods -join ', ') } else { 'no methods registered' }

        $delayNote = 'Note: the registration report has reporting latency, so a method just registered may still be missing here.'

        if ($strong.Count -gt 0) {
            [void]($seenMethods[$upn] = ($strong | Sort-Object))
            New-CAInvRecord -Domain $Domain -CheckId 'Emergency-07' -ObjectType 'User' `
                -ObjectId $uid -ObjectName $upn -Property 'phishingResistantMethod' `
                -ObservedValue "Phishing-resistant method registered: $($strong -join ', '). All registered methods: $methodText." `
                -Status 'Ready' -GraphSource $src -RawPath $RawPath | Out-Null
        }
        elseif ($unclear.Count -gt 0) {
            New-CAInvRecord -Domain $Domain -CheckId 'Emergency-07' -ObjectType 'User' `
                -ObjectId $uid -ObjectName $upn -Property 'phishingResistantMethod' `
                -ObservedValue "Certificate-based method registered ($($unclear -join ', ')), but the registration doesn't show whether it's set up as single- or multifactor. All registered methods: $methodText." `
                -Status 'Review required' -ManualReview -GraphSource $src -RawPath $RawPath `
                -Recommendation ('Check in the CBA configuration whether this certificate counts as multifactor. Only then does it satisfy the requirement for an emergency account. {0}' -f @($delayNote)) | Out-Null
        }
        else {
            $hasTap = ($methods -contains 'temporaryAccessPass')
            $tapNote = if ($hasTap) { ' A Temporary Access Pass is registered, but that does not count as phishing-resistant and is only a bootstrap aid.' } else { '' }
            New-CAInvRecord -Domain $Domain -CheckId 'Emergency-07' -ObjectType 'User' `
                -ObjectId $uid -ObjectName $upn -Property 'phishingResistantMethod' `
                -ObservedValue "No phishing-resistant method registered. Registered: $methodText.$tapNote" `
                -Status 'Gap' -GraphSource $src -RawPath $RawPath `
                -Recommendation ('Register a passkey (FIDO2) on this emergency account, or certificate-based authentication if a PKI is already in place. Since MFA became mandatory for the admin portals, an emergency account must also be able to sign in itself; exempting it is no longer an option. {0}' -f @($delayNote)) | Out-Null
        }
    }

    if ($seenMethods.Count -gt 1) {
        $grouped = $seenMethods.GetEnumerator() | Group-Object { ($_.Value -join '|') }
        foreach ($g in @($grouped | Where-Object { $_.Count -gt 1 })) {
            $upns = @($g.Group | ForEach-Object { $_.Key }) -join ', '
            New-CAInvRecord -Domain $Domain -CheckId 'Emergency-07' -ObjectType 'EmergencyAccess' `
                -Property 'methodDiversity' `
                -ObservedValue "These emergency accounts share the exact same phishing-resistant method set ($($g.Name -replace '\|', ', ')): $upns." `
                -Status 'Review required' -ManualReview -GraphSource $src `
                -Recommendation ('Microsoft recommends giving emergency accounts a different method than regular admin accounts, and diversifying across the accounts themselves. If they share the same method, an outage or revocation in that one method locks out all emergency access at once. Consider, for example, two FIDO2 keys from different vendors, or a second account on certificate-based authentication.') | Out-Null
        }
    }
}
