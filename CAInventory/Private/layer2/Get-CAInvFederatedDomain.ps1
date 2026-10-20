function Get-CAInvFederatedDomain {
    <#
    .SYNOPSIS
        Domain 6.3 — Federation behavior for MFA (federatedIdpMfaBehavior).
    .DESCRIPTION
        Layer 2 collector. Finds the tenant's federated domains and reads, per domain, how Entra
        handles an MFA claim from the federation partner.

        Why this belongs in a pre-implementation assessment: for a federated domain, the question
        "does my CA policy enforce MFA?" cannot be answered with yes without this setting. The
        three states mean something fundamentally different (Microsoft Learn,
        internalDomainFederation, verified 25-08-2026):

          acceptIfMfaDoneByFederatedIdp  Entra accepts the partner's MFA. If the partner didn't do
                                         MFA, Entra does it after all.
          enforceMfaByFederatedIdp       Entra accepts the partner's MFA and otherwise sends the
                                         request back to the partner.
          rejectMfaByFederatedIdp        Entra always performs MFA itself and rejects the partner's
                                         claim.

        The crux is in the default: "If neither federatedIdpMfaBehavior nor SupportsMfa is set,
        Microsoft Entra ID will default to acceptIfMfaDoneByFederatedIdp behavior." For a hybrid
        customer who never looked at it, the MFA requirement is thus silently filled in by an
        external party. That's rarely a deliberate choice and almost never documented.

        The status is Review required, not Gap: Microsoft documents the behavior but nowhere
        prescribes which value you should choose. Whether you trust your federation partner's MFA
        is an architectural choice; that's exactly the criterion on which Device-07 and Identity-16
        deliberately stayed at Review.

        Source choice: the federation state is determined via /domains, not via
        organization.verifiedDomains. That latter object does have a type field, but Microsoft
        doesn't document its possible values there ("For example, Managed"), while
        domain.authenticationType does have a documented enum. Measuring on an undocumented value
        would be guessing here.

        Microsoft also notes that switching between federatedIdpMfaBehavior and the legacy
        SupportsMfa is not supported, and that federating is optional: it recommends its own
        methods.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.3'
    $src    = 'GET /domains; GET /domains/{id}/federationConfiguration'

    $domResp = Invoke-CAInvGraphOrNotAssessed -Uri 'domains?$select=id,authenticationType,isVerified' -ApiVersion 'v1.0' `
        -Domain $domain -CheckId 'Auth-18' -ObjectType 'Domain' -Property 'federatedIdpMfaBehavior' `
        -GraphSource $src -NotAssessedReasonPrefix ('Could not read /domains')
    if ($domResp.Failed) { return }

    $domains = @($domResp.Value)
    $raw = Write-CAInvRaw -Domain $domain -Endpoint 'domains' -Data $domains

    $federated = @($domains | Where-Object { [string](Get-CAInvProp $_ 'authenticationType' '') -ieq 'Federated' })

    if ($federated.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-18' -ObjectType 'Tenant' `
            -Property 'federatedIdpMfaBehavior' `
            -ObservedValue "No federated domains ($($domains.Count) domain(s), all managed); federation behavior at MFA does not apply." `
            -Status 'Ready' -GraphSource 'GET /domains' -RawPath $raw | Out-Null
        Write-CAInvLog -Level 'INFO' -Domain $domain -Message "No federated domains found ($($domains.Count) domains)."
        return
    }

    foreach ($d in $federated) {
        $domainId = [string](Get-CAInvProp $d 'id' '')
        if ([string]::IsNullOrWhiteSpace($domainId)) { continue }

        $fedResp = Invoke-CAInvGraph -Uri "domains/$domainId/federationConfiguration" -ApiVersion 'v1.0'
        if ($fedResp.Failed) {
            New-CAInvRecord -Domain $domain -CheckId 'Auth-18' -ObjectType 'Domain' `
                -ObjectId $domainId -ObjectName $domainId -Property 'federatedIdpMfaBehavior' `
                -Status 'Not assessed' `
                -NotAssessedReason ('Could not read the federation configuration of {0}: {1}' -f @($domainId, $fedResp.ErrorMessage)) `
                -GraphSource $src -RawPath $raw | Out-Null
            continue
        }

        $conf = @($fedResp.Value) | Select-Object -First 1
        $behavior = [string](Get-CAInvProp $conf 'federatedIdpMfaBehavior' '')
        $idpName = [string](Get-CAInvProp $conf 'displayName' '')
        $objName = if ([string]::IsNullOrWhiteSpace($idpName)) { $domainId } else { "$domainId ($idpName)" }

        switch -Regex ($behavior) {
            '^rejectMfaByFederatedIdp$' {
                New-CAInvRecord -Domain $domain -CheckId 'Auth-18' -ObjectType 'Domain' `
                    -ObjectId $domainId -ObjectName $objName -Property 'federatedIdpMfaBehavior' `
                    -ObservedValue 'rejectMfaByFederatedIdp' -Status 'Ready' `
                    -GraphSource $src -RawPath $raw `
                    -Recommendation ('Entra always performs MFA itself and rejects the federation partner''s claim. The CA MFA requirement is thus enforced entirely within Entra; this is the most predictable setting for a CA design.') | Out-Null
            }
            '^enforceMfaByFederatedIdp$' {
                New-CAInvRecord -Domain $domain -CheckId 'Auth-18' -ObjectType 'Domain' `
                    -ObjectId $domainId -ObjectName $objName -Property 'federatedIdpMfaBehavior' `
                    -ObservedValue 'enforceMfaByFederatedIdp' -Status 'Review required' `
                    -GraphSource $src -RawPath $raw `
                    -Recommendation ('MFA sits with the federation partner: Entra accepts their claim and otherwise sends the request back to them. This is a valid setup, but then record which methods that partner enforces and whether they''re phishing-resistant. A CA policy that requires an authentication strength cannot impose that requirement on the partner.') | Out-Null
            }
            '^acceptIfMfaDoneByFederatedIdp$' {
                New-CAInvRecord -Domain $domain -CheckId 'Auth-18' -ObjectType 'Domain' `
                    -ObjectId $domainId -ObjectName $objName -Property 'federatedIdpMfaBehavior' `
                    -ObservedValue 'acceptIfMfaDoneByFederatedIdp' -Status 'Review required' `
                    -GraphSource $src -RawPath $raw `
                    -Recommendation ('Entra trusts the federation partner''s MFA claim and only performs MFA itself when that claim is missing. This is also the setting Entra falls back to when nobody has made a choice, so first verify whether this is a deliberate setup. If so, record which methods the partner enforces. If not, consider rejectMfaByFederatedIdp, which makes Entra enforce MFA itself. Note: switching between federatedIdpMfaBehavior and the legacy SupportsMfa is not supported.') | Out-Null
            }
            '^\s*$' {

                New-CAInvRecord -Domain $domain -CheckId 'Auth-18' -ObjectType 'Domain' `
                    -ObjectId $domainId -ObjectName $objName -Property 'federatedIdpMfaBehavior' `
                    -ObservedValue 'not set; Entra falls back to acceptIfMfaDoneByFederatedIdp' `
                    -Status 'Review required' -GraphSource $src -RawPath $raw `
                    -Recommendation ('No value is set. Microsoft then falls back to acceptIfMfaDoneByFederatedIdp: Entra trusts the federation partner''s MFA claim. This has almost never been a deliberate choice, and it means your CA MFA requirement is in practice fulfilled by an external party. Decide which setting you want and set it explicitly; if you want Entra to be the enforcer, that''s rejectMfaByFederatedIdp. Also check whether the legacy SupportsMfa is still set, since switching between the two is not supported.') | Out-Null
            }
            default {
                New-CAInvRecord -Domain $domain -CheckId 'Auth-18' -ObjectType 'Domain' `
                    -ObjectId $domainId -ObjectName $objName -Property 'federatedIdpMfaBehavior' `
                    -Status 'Not assessed' `
                    -NotAssessedReason ('Unknown value ''{0}''; this module recognizes acceptIfMfaDoneByFederatedIdp, enforceMfaByFederatedIdp, and rejectMfaByFederatedIdp. Check whether Microsoft has added a new value.' -f @($behavior)) `
                    -GraphSource $src -RawPath $raw | Out-Null
            }
        }
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($federated.Count) federated domain(s) assessed for federatedIdpMfaBehavior."
}
