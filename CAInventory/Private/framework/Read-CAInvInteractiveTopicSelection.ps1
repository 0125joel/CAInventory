function Read-CAInvInteractiveTopicSelection {
    <#
    .SYNOPSIS
        Interactive console menu for picking which subject-matter topics Invoke-CAInventory
        covers, used when -Layer is omitted on a Delegated call.
    .DESCRIPTION
        The menu presents topics (Conditional Access, Break the glass, MFA, ...), not the seven
        raw collector layers: a topic is a curated, cross-cutting subset of the check catalog. A topic can span multiple layers (e.g. 'Legacy authentication' needs
        Authentication, Application and NetworkSession) or share layers with another topic (e.g.
        'Break the glass' and 'Governance and process' both need Identity and Governance) —
        there is no CheckId-level toggle in the collector engine, so a topic still resolves to
        "the layers needed to produce it," and picking it can pull in some unrelated checks that
        happen to live in the same layer. Nothing is filtered from the report afterwards: every
        check produced by a selected layer appears, whether or not it was the topic's own reason
        for selecting that layer.

        Layer 0 (Foundation) always runs regardless of this selection. Pressing Enter or typing
        'A' selects the 'Everything' topic (all seven optional layers), matching the
        non-interactive default (-Layer All). Typing '0' or 'none' selects zero optional layers
        (equivalent to today's -Layer Foundation). Multiple topic numbers union their layers,
        deduplicated, and the result always comes back in canonical layer order regardless of the
        order typed or how many topics contributed a given layer.

        Every topic carries a priority color, read against the
        rollout dependency chain in CA_Voorwaardenketen_...md (policy -> registration possible ->
        registration demonstrated -> enforce; emergency accounts -> admins -> end users), not
        against how many checks a topic happens to contain:
          - Green, with a leading '*' (not color alone): Everything, Conditional Access, Break the
            glass — the most complete picture, the module's core subject, and the
            highest-priority section in config/sections.json.
          - Yellow: MFA and authentication methods, Legacy authentication, Identity and privileged
            access, Devices and endpoint compliance, Network and session — direct preconditions
            for a safe rollout (can people authenticate, is legacy auth gone, who is in scope, are
            the CA conditions this policy actually leans on measured).
          - Red: Governance and process, Identity Protection and risk, Applications and workload
            identities, Usage and log evidence — valuable, but about ongoing hygiene and
            evidence/monitoring rather than "can this tenant turn CA on safely right now." Yellow
            and Red carry no marker beyond color; only Green
            keeps the '*' from the first round.
    .OUTPUTS
        String[]: the resolved layer names, from the same set as -Layer's ValidateSet (excluding
        'All' and 'Foundation'). An empty array is a valid result.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $canonicalLayerOrder = @('Identity', 'Authentication', 'Application', 'Device', 'NetworkSession', 'Evidence', 'Governance')

    $topics = @(
        [PSCustomObject]@{ Name = 'Conditional Access'; Description = 'CA policies themselves, plus what they directly depend on: locations, Terms of Use, authentication strength.'; Layers = @('Identity', 'Authentication', 'Application', 'NetworkSession', 'Evidence', 'Governance'); Color = 'Green' }
        [PSCustomObject]@{ Name = 'Break the glass'; Description = 'Only the emergency-access accounts and their safeguards.'; Layers = @('Identity', 'Governance'); Color = 'Green' }
        [PSCustomObject]@{ Name = 'MFA and authentication methods'; Description = 'Method policy, registration campaign, password protection, federation, Security Defaults.'; Layers = @('Authentication'); Color = 'Yellow' }
        [PSCustomObject]@{ Name = 'Legacy authentication'; Description = 'Phasing out legacy protocols and per-user MFA.'; Layers = @('Authentication', 'Application', 'NetworkSession'); Color = 'Yellow' }
        [PSCustomObject]@{ Name = 'Identity Protection and risk'; Description = 'Risky users, risky service principals, risk detections, risk-based CA.'; Layers = @('Application', 'Evidence'); Color = 'Red' }
        [PSCustomObject]@{ Name = 'Identity and privileged access'; Description = 'Users, groups, roles, PIM activation, cross-tenant, guests.'; Layers = @('Identity'); Color = 'Yellow' }
        [PSCustomObject]@{ Name = 'Governance and process'; Description = 'Access reviews, protected actions, exclusion surface, lifecycle.'; Layers = @('Identity', 'Governance'); Color = 'Red' }
        [PSCustomObject]@{ Name = 'Devices and endpoint compliance'; Description = 'Device population, Intune compliance, app protection, Defender connector.'; Layers = @('Device'); Color = 'Yellow' }
        [PSCustomObject]@{ Name = 'Applications and workload identities'; Description = 'App and service principal population.'; Layers = @('Application'); Color = 'Red' }
        [PSCustomObject]@{ Name = 'Network and session'; Description = 'Named locations, session controls, Token Protection, CAE, GSA.'; Layers = @('NetworkSession'); Color = 'Yellow' }
        [PSCustomObject]@{ Name = 'Usage and log evidence'; Description = 'Sign-in/audit logs, diagnostic settings, log window.'; Layers = @('Evidence'); Color = 'Red' }
        [PSCustomObject]@{ Name = 'Everything'; Description = 'The full eight-layer inventory.'; Layers = $canonicalLayerOrder; Color = 'Green' }
    )

    Write-Host ''
    Write-Host 'Which topics should this run cover? (Foundation / layer 0 always runs)'
    Write-Host '* + green = preferred (most complete picture). Yellow = direct rollout precondition. Red = ongoing hygiene/monitoring, not rollout-blocking.' -ForegroundColor DarkGray
    for ($i = 0; $i -lt $topics.Count; $i++) {
        $topic = $topics[$i]
        $marker = if ($topic.Color -eq 'Green') { '*' } else { ' ' }
        $line = '  {0,2}) {1} {2} - {3}' -f ($i + 1), $marker, $topic.Name, $topic.Description
        Write-Host $line -ForegroundColor $topic.Color
    }
    Write-Host ''

    while ($true) {
        $raw = Read-Host 'Topic numbers, comma-separated, A for everything, or 0 for none [A]'
        $trimmed = $raw.Trim()

        if ($trimmed -eq '' -or $trimmed -ieq 'a') { return [string[]] @($canonicalLayerOrder) }
        if ($trimmed -eq '0' -or $trimmed -ieq 'none') { return [string[]] @() }

        $tokens = @($trimmed -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        $invalid = @($tokens | Where-Object { $_ -notmatch '^(?:[1-9]|1[0-2])$' })
        if ($tokens.Count -eq 0 -or $invalid.Count -gt 0) {
            Write-Host "Not a valid entry: '$raw'. Enter topic numbers 1-$($topics.Count) separated by commas, A, or 0." -ForegroundColor Yellow
            continue
        }

        $chosenLayers = @($tokens | ForEach-Object { $topics[[int]$_ - 1].Layers } | Select-Object -Unique)
        return [string[]] @($canonicalLayerOrder | Where-Object { $chosenLayers -contains $_ })
    }
}
