function Get-CAInvConfig {
    <#
    .SYNOPSIS
        Loads externally maintainable configuration (CheckId catalog, SKU map).
    .DESCRIPTION
        Reads the JSON files from the module's config/ directory. These are deliberately kept
        external so SKU/servicePlan mappings can be updated without changing the code.
    .OUTPUTS
        Hashtable with CheckIds, Layers, Sections, Categories, SkuMap, RolloutWaves,
        MethodStrengthMap, PolicyMethodModeMap, KqlAuthMethodMap, GoLiveGate, AdminRoles,
        LifecycleDates, and CaPolicyKnownProperties.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $configRoot = Join-Path $script:ModuleRoot 'config'

    function Read-Json([string] $name) {
        $path = Join-Path $configRoot $name
        if (-not (Test-Path -LiteralPath $path)) {
            Write-CAInvLog -Level 'WARN' -Message "Config file missing: $name"
            return $null
        }
        return Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json
    }

    return @{
        CheckIds            = Read-Json 'checkids.json'
        Layers              = Read-Json 'layers.json'
        Sections            = Read-Json 'sections.json'
        Categories          = Read-Json 'categories.json'
        SkuMap              = Read-Json 'sku-license-map.json'
        RolloutWaves        = Read-Json 'rollout-waves.json'
        MethodStrengthMap   = Read-Json 'method-strength-map.json'
        PolicyMethodModeMap = Read-Json 'policy-method-mode-map.json'
        KqlAuthMethodMap    = Read-Json 'kql-auth-method-map.json'
        GoLiveGate          = Read-Json 'go-live-gate.json'
        AdminRoles          = Read-Json 'admin-roles.json'
        LifecycleDates      = Read-Json 'lifecycle-dates.json'
        CaPolicyKnownProperties = Read-Json 'ca-policy-known-properties.json'
    }
}
