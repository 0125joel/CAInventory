function Resolve-CAInvUserStrengthCoverage {
    <#
    .SYNOPSIS
        Determines which authentication strengths a user satisfies based on their registered
        methods.
    .DESCRIPTION
        Translates `methodsRegistered` (registration vocabulary) to `authenticationMethodModes`
        (strength vocabulary) via `modes` in config/method-strength-map.json, then checks that set
        against each strength's `allowedCombinations`.

        The rule is literally Microsoft's, not a rule of thumb: a user satisfies a strength as
        soon as they fully cover AT LEAST ONE allowedCombination, where a combination has AND
        semantics across its comma-separated atoms. That's exactly why the built-in MFA strength
        contains both standalone passwordless combinations ('fido2', 'windowsHelloForBusiness',
        'x509CertificateMultiFactor', 'deviceBasedPush', both TAP variants) and password pairs
        ('password,sms', 'password,voice', ...).

        Two assumptions are baked into the config and apply here:
          - 'password' is present for every user (Microsoft itself describes the strength as
            "such as a password + SMS").
          - 'federatedSingleFactor'/'federatedMultiFactor' are NEVER present: federation cannot be
            derived from userRegistrationDetails. That deliberately underestimates in a federated
            tenant.

        Tri-state instead of boolean, and the direction of the uncertainty differs per cause:
          1. The strength has `combinationConfigurations` (AAGUID restriction on passkeys, or
             issuer/policy OID restriction on certificates). Which key or certificate a user has
             isn't in the registration data, so COVERED becomes 'Uncertain' here.
          2. The user has a method that can't be resolved (unknown/future type, or generic
             'certificateBasedAuthentication'). Such a method produces no modes and can therefore
             never create coverage, only hide it: found coverage stays a hard fact, and it's
             precisely NOT-COVERED that becomes 'Uncertain'. Same safety-net thinking as the
             automatic floor (v0.17.0): a gap in the table must never silently produce a hard
             verdict.

        An unresolvable method is added to the UnknownTracker so the caller can include it in the
        same WARN line as the existing unknown-method logging.
    .OUTPUTS
        Hashtable with Satisfied and Uncertain: both arrays of strength IDs. Without strengths or
        without a map, both stay empty (not measured is not "does not satisfy").
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string[]] $MethodsRegistered,

        $Strengths,

        $StrengthMap,

        [System.Collections.Generic.HashSet[string]] $UnknownTracker
    )

    $result = @{ Satisfied = @(); Uncertain = @() }
    $strengthList = @($Strengths)
    if ($strengthList.Count -eq 0 -or -not $StrengthMap) { return $result }

    $userModes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void]$userModes.Add('password')
    $hasUnresolvedMethod = $false

    foreach ($m in @($MethodsRegistered)) {
        if ([string]::IsNullOrWhiteSpace($m)) { continue }
        $entry = if ($StrengthMap.methods) { $StrengthMap.methods.PSObject.Properties[$m] } else { $null }
        if (-not $entry) {
            $hasUnresolvedMethod = $true
            if ($UnknownTracker) { [void]$UnknownTracker.Add($m) }
            continue
        }

        $modesProp = $entry.Value.PSObject.Properties['modes']
        $modesValue = if ($modesProp) { $modesProp.Value } else { $null }
        if ($null -eq $modesValue) { $hasUnresolvedMethod = $true; continue }
        $modes = @($modesValue | Where-Object { $null -ne $_ -and "$_" -ne '' })
        if ($modes.Count -eq 0) { $hasUnresolvedMethod = $true; continue }
        foreach ($mode in $modes) { [void]$userModes.Add([string]$mode) }
    }

    foreach ($s in $strengthList) {
        $id = Get-CAInvProp $s 'id'
        if (-not $id) { continue }

        $restricted = @(Get-CAInvProp $s 'combinationConfigurations' @()).Count -gt 0

        $covered = $false
        foreach ($combo in @(Get-CAInvProp $s 'allowedCombinations' @())) {
            $atoms = @("$combo".Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($atoms.Count -eq 0) { continue }
            $allPresent = $true
            foreach ($atom in $atoms) {
                if (-not $userModes.Contains($atom)) { $allPresent = $false; break }
            }
            if ($allPresent) { $covered = $true; break }
        }

        if ($covered) {
            if ($restricted) { $result.Uncertain += $id } else { $result.Satisfied += $id }
        }
        elseif ($hasUnresolvedMethod) {
            $result.Uncertain += $id
        }
    }

    return $result
}
