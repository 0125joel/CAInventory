@{
    RootModule        = 'CAInventory.psm1'
    ModuleVersion     = '0.108.1'
    GUID              = 'a1f7c3e2-9b64-4d18-8e2a-1c6f0b5d7e40'
    Author            = 'Joel Prins'
    CompanyName       = 'IntoTheCloud'
    Copyright         = '(c) 2026 Joel Prins. Licensed under the MIT License.'
    Description       = 'Read-only pre-implementation readiness inventory for Microsoft Entra ID & Conditional Access. Eight collector layers (0 Foundation through 7 Governance) yield normalized records, a readiness scorecard and a findings register.'
    PowerShellVersion = '7.2'

    RequiredModules   = @()

    FunctionsToExport = @(
        'Invoke-CAInventory',
        'Connect-CAInv'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('Entra', 'ConditionalAccess', 'Assessment', 'Graph', 'Inventory')
            ProjectUri = ''
        }

        OptionalModules = @{
            Graph       = @('Microsoft.Graph', 'Microsoft.Graph.Beta')
            Exchange    = @('ExchangeOnlineManagement')
            Azure       = @('Az.Accounts', 'Az.Monitor', 'Az.OperationalInsights')
            Reporting   = @('ImportExcel')
        }
    }
}
