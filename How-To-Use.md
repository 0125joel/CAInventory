# How to use

This is the reference for CAInventory. It covers the two exported functions, `Connect-CAInv` and
`Invoke-CAInventory`, and every parameter they take. Those are the only two entry points. The rest of
the module is internal. For the short version, see [README.md](README.md).

## Install and import

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module Az.Accounts -Scope CurrentUser   # for the log window and the usage axis

# From the repository root:
Import-Module ./CAInventory/CAInventory.psd1 -Force
```

Install `Microsoft.Graph`, which includes `Microsoft.Graph.Authentication`. That is the only submodule
the module loads at runtime. The other Graph calls run as raw REST requests through
`Invoke-MgGraphRequest`, so no other Graph submodule is needed. Installing
`Microsoft.Graph.Authentication` on its own with `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`
also works.

## Connect-CAInv

`Connect-CAInv` sets up the sessions. It runs first, or it runs for you inside `Invoke-CAInventory`.
Delegated sign-in is the default. An interactive user with Global Reader and Security Reader is enough
for a read-only assessment.

A missing module or context is not fatal. The module logs a warning, and the checks that depend on it
become `Not assessed` with a reason. The rest of the run continues.

| Parameter | Type | Values | Default | Meaning |
|---|---|---|---|---|
| `-TenantId` | string | GUID or verified domain | required | The tenant to connect to. |
| `-AuthMode` | string | `Delegated`, `AppOnly` | `Delegated` | `Delegated` signs in interactively. `AppOnly` runs unattended with a certificate and requires `-ClientId` and `-CertificateThumbprint`. |
| `-ClientId` | string | app registration GUID | none | Only with `-AuthMode AppOnly`. |
| `-CertificateThumbprint` | string | 40-character thumbprint | none | Only with `-AuthMode AppOnly`. The certificate must be in the certificate store of the machine that runs the script. |
| `-Scopes` | string[] | Graph delegated scopes | see below | Override only if you want to narrow the scopes on purpose. Missing scopes do not break the run. They push the affected checks to `Not assessed`. |
| `-SkipAzure` | switch | on/off | off | Skips the Azure context. By default the module signs in to Azure as soon as `Az.Accounts` is available. That context feeds the Log Analytics retention (the log window, see `Evidence-04` and `Evidence-05`) and the usage axis of the method matrix (`Auth-05`, `Auth-06`, `Auth-07`, `Condition-11`). The Azure sign-in requests the Log Analytics scope itself, so one login covers both the Log Analytics data plane and ARM. You also need **Log Analytics Reader** or **Monitoring Reader** on the workspace. Graph scopes alone are not enough. |
| `-IncludeExchange` | switch | on/off | off | Also connects Exchange Online, for the SMTP AUTH and mailbox CAS checks. |
| `-Environment` | string | `Global`, `USGov`, `USGovDoD`, `China` | `Global` | The Microsoft cloud to connect to. Use a sovereign value only for a sovereign tenant. |

Default `-Scopes`: `Organization.Read.All`, `Directory.Read.All`, `Policy.Read.All`,
`Policy.Read.AuthenticationMethod`, `User.Read.All`, `Group.Read.All`,
`RoleManagement.Read.Directory`, `Application.Read.All`, `AuditLog.Read.All`,
`Reports.Read.All`, `Agreement.Read.All`, `UserAuthenticationMethod.Read.All`,
`Device.Read.All`, `DeviceManagementManagedDevices.Read.All`,
`DeviceManagementConfiguration.Read.All`, `IdentityRiskyUser.Read.All`,
`IdentityRiskEvent.Read.All`, `IdentityRiskyServicePrincipal.Read.All`,
`IdentityProvider.Read.All`, `AccessReview.Read.All`, `Domain.Read.All`,
`DeviceManagementApps.Read.All`.

```powershell
# Delegated, Graph only.
Connect-CAInv -TenantId 'contoso.onmicrosoft.com' -SkipAzure

# Delegated, with the Azure context for the log window.
Connect-CAInv -TenantId 'contoso.onmicrosoft.com'

# Unattended (scheduled task or CI), with a certificate.
Connect-CAInv -TenantId $tenantId -AuthMode AppOnly -ClientId $appId -CertificateThumbprint $thumb
```

## Invoke-CAInventory

This is the main entry point. It builds the run context, runs the preflight, runs the layers you
picked, runs the referential integrity checks and writes the reports. Layer 0 always runs, whatever
`-Layer` says. License and tenant context decide which later checks can say anything meaningful, so
that layer is never skipped.

If you do not call `Connect-CAInv` first, `Invoke-CAInventory` connects for you. Pass `-SkipConnect`
when a session already exists.

### Interactive menu

On a Delegated call without `-Layer`, `Invoke-CAInventory` opens a console menu. The menu shows topics,
not layer names. Each topic is a content-based subset of the check catalog. Under the hood it maps to
whichever layers produce it. Layers are the unit of collection, so a topic can pull in checks you did
not ask for from the same layer. Nothing is filtered afterwards. Whatever the chosen layers produce
ends up in the report.

The color tells you how a topic relates to the rollout order (policy, then registration possible,
then registration proven, then enforce; break-glass accounts, then admins, then end users). It does
not tell you how many checks a topic has:

- **Green and `*`**: the most complete picture, or the core topic. The star is the recommendation, so
  you can still see it in a terminal without color.
- **Yellow**: a direct precondition for a safe rollout.
- **Red**: valuable, but ongoing maintenance and monitoring, not a rollout blocker. No `*`.

| # | Topic | Priority | Layers |
|---|---|---|---|
| 1 | * Conditional Access: CA policies plus direct dependencies (locations, Terms of Use, authentication strength) | Green | Identity, Authentication, Application, NetworkSession, Evidence, Governance |
| 2 | * Break the glass: the emergency accounts and their safeguards | Green | Identity, Governance |
| 3 | MFA and authentication methods: method policy, registration campaign, password policy, federation, Security Defaults | Yellow | Authentication |
| 4 | Legacy authentication: phasing out legacy protocols and per-user MFA | Yellow | Authentication, Application, NetworkSession |
| 5 | Identity Protection and risk: risky users and service principals, risk detections, risk-based CA | Red | Application, Evidence |
| 6 | Identity and privileged access: users, groups, roles, PIM activation, cross-tenant, guests | Yellow | Identity |
| 7 | Governance and process: access reviews, protected actions, exclusion surface, lifecycle | Red | Identity, Governance |
| 8 | Devices and endpoint compliance: device population, Intune compliance, app protection, Defender connector | Yellow | Device |
| 9 | Applications and workload identities: app and service principal population | Red | Application |
| 10 | Network and session: named locations, session controls, Token Protection, CAE, GSA | Yellow | NetworkSession |
| 11 | Usage and log evidence: sign-in and audit logs, diagnostic settings, log window | Red | Evidence |
| 12 | * Everything: the full eight-layer inventory | Green | all seven optional layers, plus layer 0 |

Combine topic numbers with commas. The layers are merged and deduplicated. Enter `A` or `12` for
everything. Enter `0` or `none` for no topic, which is the same as `-Layer Foundation`.

After the topics, the menu asks the questions for everything you did not pass explicitly: break-glass
UPNs or object IDs, whether to use the Azure context, the log window, the output path. It asks
whether to sign in with sensitive method details only when Authentication is in scope. That option
costs one extra Graph call per user. Phone numbers stay masked to the last four digits. The extra
detail is optional, because readiness already comes from a lighter, tenant-wide source.

`-BrandFile` and `-PrimaryWorkspaceId` stay out of the menu. Pass `-BrandFile` yourself when the
report is a deliverable for a client. Whether more than one workspace exists is only known after the
preflight, so that case goes through the normal `Review required` path. The menu never appears when
you set `-Layer`, and never with `-AuthMode AppOnly`. An unattended run always continues without
waiting for input.

### Parameters by category

| Category | Parameters |
|---|---|
| Target | `-TenantId` |
| Scope of the run | `-Layer`, and the interactive topic menu when `-Layer` is omitted |
| Log window | `-LookbackDays`, `-MaxLookbackDays`, `-PrimaryWorkspaceId`, `-SkipAzure` |
| Break-glass accounts | `-EmergencyAccountUpn`, `-EmergencyAccountId` |
| Authentication and connection | `-AuthMode`, `-ClientId`, `-CertificateThumbprint`, `-SkipConnect`, `-IncludeExchange`, `-Environment` |
| Output and branding | `-OutputPath`, `-BrandFile` |
| Sensitive data | `-IncludeSensitiveMethodDetails` |

### Parameter reference

| Parameter | Type | Values | Default | Meaning |
|---|---|---|---|---|
| `-TenantId` | string | GUID or verified domain | required | The tenant to inventory. |
| `-Layer` | string[] | `All`, `Foundation`, `Identity`, `Authentication`, `Application`, `Device`, `NetworkSession`, `Evidence`, `Governance` | `All` | Run one or more layers, for a targeted and faster run, for example `-Layer Identity,Governance`. Layer 0 runs regardless. Omitting this on a Delegated call opens the interactive menu instead of the `All` default. |
| `-LookbackDays` | int | positive whole number | `90` | The log window you want. It extends automatically to the Log Analytics retention if that is detected (unless `-SkipAzure`), up to `-MaxLookbackDays`. Without Log Analytics the Graph `signInLogs` retention, roughly 30 days, is the real ceiling. The report states that instead of suggesting 90 days that are not there. |
| `-MaxLookbackDays` | int | positive whole number | `90` | The ceiling for the extended window. |
| `-PrimaryWorkspaceId` | string | ARM resource ID, `properties.workspaceId` form | none | Pins the Log Analytics workspace for the usage axis of the method matrix and the legacy-auth drill-down. If the Entra diagnostic settings point to one workspace, the module uses it automatically. If they point to several, the module does not guess: `Evidence-04` becomes `Review required` and lists every workspace it found (name, retention, categories). Run again with this parameter to pin one. |
| `-EmergencyAccountUpn` | string[] | UPNs | none | The actual break-glass accounts. Only these get the full break-glass verdict. Without this list the report shows candidates for you to confirm. |
| `-EmergencyAccountId` | string[] | object IDs (GUIDs) | none | The same as `-EmergencyAccountUpn`, by object ID. |
| `-BrandFile` | string | path to a JSON file | none | Branding for the report UI. Without it, the report uses CAInventory's own plain identity. To brand it, copy `brand.example.json`, edit the copy, and pass that. |
| `-OutputPath` | string | path | `./output`, relative to the current location | The base folder. Each run gets a timestamped subfolder. |
| `-IncludeSensitiveMethodDetails` | switch | on/off | off | Adds sensitive method details, such as phone numbers, always masked. Without it, readiness comes from `userRegistrationDetails`, which is enough for most decisions. |
| `-AuthMode` | string | `Delegated`, `AppOnly` | `Delegated` | See [Connect-CAInv](#connect-cainv). |
| `-ClientId` | string | app registration GUID | none | Only with `-AuthMode AppOnly`. Passed to `Connect-CAInv`. |
| `-CertificateThumbprint` | string | 40-character thumbprint | none | Only with `-AuthMode AppOnly`. Passed to `Connect-CAInv`. |
| `-SkipConnect` | switch | on/off | off | Skips connecting when a session already exists, for example after a separate `Connect-CAInv` call. |
| `-IncludeExchange` | switch | on/off | off | Also connects Exchange Online. Passed to `Connect-CAInv`. With `-SkipConnect` this has no effect. In that case, connect Exchange yourself with `Connect-CAInv -IncludeExchange`. |
| `-Environment` | string | `Global`, `USGov`, `USGovDoD`, `China` | `Global` | See [Connect-CAInv](#connect-cainv). |

### Examples

```powershell
# Full inventory, all eight layers, with your own brand file.
Connect-CAInv -TenantId 'contoso.onmicrosoft.com'
Invoke-CAInventory -TenantId 'contoso.onmicrosoft.com' -Layer All -OutputPath ./output `
    -BrandFile ./your-brand.json

# Unattended run (scheduled task or CI) with a certificate. No prompts, all layers.
Invoke-CAInventory -TenantId $tenantId -AuthMode AppOnly -ClientId $appId `
    -CertificateThumbprint $thumb -OutputPath ./output -BrandFile ./your-brand.json

# One layer, with the real break-glass accounts named for the full verdict.
Invoke-CAInventory -TenantId $tenantId -Layer Identity `
    -EmergencyAccountUpn 'breakglass1@contoso.com','breakglass2@contoso.com' -BrandFile ./your-brand.json
```

## Output

Every run writes to `<OutputPath>/<yyyyMMdd-HHmmss>/`. The raw files come first, because every
finding has to trace back to one of them.

| Path | Contents |
|---|---|
| `raw/{domain}/*.json` (with `.sha256`) | The raw Graph response per domain, as evidence. |
| `normalized/findings.csv` | All records, flattened. |
| `normalized/findings.json` | The same records as the versioned interop contract. Hand this file to other tooling. |
| `reports/report.html` | One self-contained file: Scorecard, Needs review, MFA methods, Rollout order, Open work and Reference, behind tabs. The tabs share the same decisions (Confirmed, Accepted, Resolved), so a click on one shows up on the others. It works offline, with a double-click, and needs nothing next to it. |
| `reports/report-print.html` | The full report as one printable document, with a cover page, the scorecard, the decisions made, all findings, the rollout order and two appendices. Pick the depth at the top, then print to PDF. It reads the checkbox decisions from the browser you open it in and never writes them. If the decisions were made elsewhere, export them there and import the file here. It is a separate file on purpose: a hidden tab does not print. |
| `reports/findings-register.xlsx` (or `findings-register/*.csv` without `ImportExcel`) | The work list, with Findings, Review, Exceptions, NotAssessed and RunInfo tabs. |
| `reports/api-drift.json` | The endpoints called, which ran on beta, and which failed. An early warning for Graph changes. |
| `logs/collector.log` | The full, structured run log. |

The return value of `Invoke-CAInventory` gives you the same paths: `.NormalizedCsv`,
`.NormalizedJson`, `.Report`, `.PrintReport`, `.FindingsRegister`, `.ApiDriftReport` and
`.WorkbookFacts`. It also gives you `.Records` (in memory), `.RunId`, `.RecordCount` and `.OutputRoot`.
The six pages inside `report.html` are not separate files, so they have no path of their own.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Microsoft.Graph is not installed` | Run `Install-Module Microsoft.Graph -Scope CurrentUser`. |
| `AppOnly requires -ClientId and -CertificateThumbprint` | Pass both with `-AuthMode AppOnly`. Unattended runs never use delegated sign-in. |
| `'CertificateThumbprint' must have a length of 40` | The value is not a SHA-1 thumbprint. Copy it from the certificate properties, without spaces. |
| Checks show `Not assessed` with a missing-scope or missing-module reason | The session lacks a permission or module. The run continues. Install the module or grant the permission, and run again. |
| The log window stays at about 30 days | No Log Analytics workspace is readable. Give the account **Log Analytics Reader** or **Monitoring Reader** on the workspace, or accept the Graph ceiling. |
| `Evidence-04` is `Review required` | Several workspaces receive the Entra diagnostic logs. Pin one with `-PrimaryWorkspaceId`. |

## Status model

Every record gets exactly one of four statuses.

| Status | Meaning | Counts toward ready? |
|---|---|---|
| `Ready` | Compliant, and provable through Graph. | Yes |
| `Gap` | Not compliant, and provable through Graph. | No |
| `Review required` | Cannot be determined with certainty from technical data. A person has to confirm it. | No, not even partially. |
| `Not assessed` | Not measured, because a scope, license, module or context is missing. Always carries a `NotAssessedReason`. | No. It does not count toward the coverage percentage either. |

Why `Review required` and `Not assessed` do not count as ready: a control you could not verify is not
evidence that it is fine. The checks with `reliability: manual` in `config/checkids.json` (`Emergency-06`,
`Auth-15`, `Govern-02`) never become `Ready` on their own. A person confirms them outside the script.
`Foundation-04` used to be in that list too, until 0.20.0. It now measures per-user MFA status through
a beta endpoint. `RSK-004` has been removed.
