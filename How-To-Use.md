# How to use

The full parameter reference for CAInventory: the two exported functions
`Connect-CAInv` and `Invoke-CAInventory`. Those are the only two entry points; everything else in
this folder is internal. For the short version, see `README.md`.

## Install and import

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module Az.Accounts -Scope CurrentUser   # for the log window and the usage axis

# From this folder:
Import-Module ./CAInventory/CAInventory.psd1 -Force
```

`Microsoft.Graph.Authentication` is required. The rest of the Graph calls run over raw REST
(`Invoke-MgGraphRequest`), not the per-cmdlet SDK, so further Graph submodules aren't needed.

## Connect-CAInv

Sets up the session. Delegated is the default path: an interactive user with at least Global
Reader + Security Reader is enough for a read-only assessment. Missing a module or context? The
module logs it as a warning and the affected checks fall back to `Not assessed` later, instead of
tripping up the whole run.

| Parameter | Type | Values | Default | Meaning |
|---|---|---|---|---|
| `-TenantId` | string | GUID or verified domain | required | The tenant to connect to. |
| `-AuthMode` | string | `Delegated`, `AppOnly` | `Delegated` | `AppOnly` is for unattended/scheduled runs and requires `-ClientId` + `-CertificateThumbprint`. |
| `-ClientId` | string | app registration GUID | — | Only with `-AuthMode AppOnly`. |
| `-CertificateThumbprint` | string | certificate thumbprint | — | Only with `-AuthMode AppOnly`. |
| `-Scopes` | string[] | Graph delegated scopes | see below | Only override this if you deliberately want to narrow scopes; missing scopes don't break the run, they just push the affected checks to `Not assessed`. |
| `-SkipAzure` | switch | on/off | off | Skips the Azure context. **By default the module does connect to Az** as soon as `Az.Accounts` is available, because that context feeds Log Analytics retention detection (the log window, see `Evidence-04`/`Evidence-05`) and the usage axis of the methods matrix (`Auth-05`, `Auth-06`, `Auth-07`, `Condition-11`). The sign-in uses `-AuthScope https://api.loganalytics.io/`, so one login covers both the Log Analytics data plane and ARM. Also requires **Log Analytics Reader** or **Monitoring Reader** on the workspace — Graph scopes alone aren't enough here; missing that RBAC leaves the affected checks at `Not assessed` or `Review required`. |
| `-IncludeExchange` | switch | on/off | off | Also connects Exchange Online, for the SMTP AUTH/mailbox CAS checks in layer 3. |
| `-Environment` | string | `Global`, `USGov`, `USGovDoD`, `China` | `Global` | National/sovereign cloud. |

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
Connect-CAInv -TenantId 'contoso.onmicrosoft.com'

# Unattended (CI/scheduled run), with Azure context for the log window.
Connect-CAInv -TenantId $tenantId -AuthMode AppOnly -ClientId $appId -CertificateThumbprint $thumb
```

## Invoke-CAInventory

The main entry point, where everything comes together. Builds the run context, runs preflight,
executes the chosen layer(s), runs the referential integrity checks and writes the reports. Layer
0 always runs, whatever `-Layer` value you pass, because license and tenant context determine
which checks downstream can still say anything meaningful.

**Interactive menu when `-Layer` is omitted.** On a Delegated call (the default `-AuthMode`), a
bare `Invoke-CAInventory -TenantId ...` without `-Layer` opens a console menu. That menu shows no
layer names, only **topics**: each topic is a coherent, content-based subset of the check
catalog, translated under the hood into whichever layer or layers are needed to produce it. A
topic can need multiple layers, and two topics can share the same layer; there is no CheckId-level
on/off switch in the collectors, so picking a topic can drag along unrelated checks from the same
layer. Nothing gets filtered out afterwards: whatever a chosen layer produces just ends up in the
report.

Every topic gets a priority color in the menu, weighed against the rollout order (policy →
registration possible → registration proven → enforce; break-glass accounts → admins → end
users), not against how many checks a topic happens to contain:

- **Green + `*`** (the recommendation, not just the color — not every terminal shows color): the
  most complete picture, or the core topic.
- **Yellow**: a direct precondition for a safe rollout.
- **Red**: valuable, but ongoing maintenance and monitoring, not a rollout blocker. Deliberately
  carries no `*`.

| # | Topic | Priority | Layers |
|---|---|---|---|
| 1 | * Conditional Access — CA policies themselves plus direct dependencies (locations, Terms of Use, authentication strength) | Green | Identity, Authentication, Application, NetworkSession, Evidence, Governance |
| 2 | * Break the glass — just the emergency accounts and their safeguards | Green | Identity, Governance |
| 3 | MFA and authentication methods — method policy, registration campaign, password policy, federation, Security Defaults | Yellow | Authentication |
| 4 | Legacy authentication — phasing out legacy protocols and per-user MFA | Yellow | Authentication, Application, NetworkSession |
| 5 | Identity Protection and risk — risky users/service principals, risk detections, risk-based CA | Red | Application, Evidence |
| 6 | Identity and privileged access — users, groups, roles, PIM activation, cross-tenant, guests | Yellow | Identity |
| 7 | Governance and process — access reviews, protected actions, exclusion surface, lifecycle | Red | Identity, Governance |
| 8 | Devices and endpoint compliance — device population, Intune compliance, app protection, Defender connector | Yellow | Device |
| 9 | Applications and workload identities — app/service principal population | Red | Application |
| 10 | Network and session — named locations, session controls, Token Protection, CAE, GSA | Yellow | NetworkSession |
| 11 | Usage and log evidence — sign-in/audit logs, diagnostic settings, log window | Red | Evidence |
| 12 | * Everything — the full eight-layer inventory | Green | all 7 optional + layer 0 |

Combine multiple topic numbers with commas (union of their layers, deduplicated). Enter or `A`
picks topic 12 (everything); `0` or `none` picks no topic at all (equivalent to the existing
`-Layer Foundation`). Follow-up questions then cover every parameter you haven't already given
explicitly: break-glass UPNs/object IDs, whether to use Azure context, the log window, the output
path, and — only when Authentication is in scope — whether to look up every user individually for
their registered MFA method. That costs one extra Graph call per user (phone numbers stay masked
down to the last four digits) and is purely extra detail: readiness itself already comes from a
lighter, tenant-wide source.

`-BrandFile` deliberately stays out of this menu: pass it explicitly when the run is a polished
deliverable for a client, in your own house style. `-PrimaryWorkspaceId` also stays out of
view here: whether multiple workspaces exist is only known after preflight, so that just runs
through the existing `Review required` mechanism. This menu never appears when `-Layer` is set
explicitly, and never with `-AuthMode AppOnly` either — an unattended or scheduled run always
keeps running without waiting on input.

### Parameters by category

| Category | Parameters |
|---|---|
| Target | `-TenantId` |
| Scope of the run | `-Layer`, the interactive topic menu (when `-Layer` is omitted) |
| Log window | `-LookbackDays`, `-MaxLookbackDays`, `-PrimaryWorkspaceId`, `-SkipAzure` |
| Break-glass accounts | `-EmergencyAccountUpn`, `-EmergencyAccountId` |
| Authentication and connection | `-AuthMode`, `-ClientId`, `-CertificateThumbprint`, `-SkipConnect`, `-IncludeExchange`, `-Environment` |
| Output and branding | `-OutputPath`, `-BrandFile` |
| Sensitive data | `-IncludeSensitiveMethodDetails` |

| Parameter | Type | Values | Default | Meaning |
|---|---|---|---|---|
| `-TenantId` | string | GUID or verified domain | required | The tenant to inventory. |
| `-Layer` | string[] | `All`, `Foundation`, `Identity`, `Authentication`, `Application`, `Device`, `NetworkSession`, `Evidence`, `Governance` | `All` | Run one or more layers for a targeted/fast run (e.g. `-Layer Identity,Governance`); layer 0 always runs regardless. Omitting this on a Delegated call starts the interactive menu above instead of the `All` default. |
| `-LookbackDays` | int | any positive number | `90` | Desired log window. Automatically extends to the detected Log Analytics retention (unless `-SkipAzure`), capped by `-MaxLookbackDays`. Without Log Analytics, the Graph `signInLogs` retention (roughly 30 days) is the real ceiling, and the window reports that honestly instead of suggesting 90 days that aren't there. |
| `-MaxLookbackDays` | int | any positive number | `90` | Ceiling for the extended window. |
| `-SkipAzure` | switch | on/off | off | Passed through to `Connect-CAInv`. Only set this if you deliberately want a Graph-only run: without Azure context the window can't extend, and the usage axis of the methods matrix stays unmeasured. |
| `-PrimaryWorkspaceId` | string | ARM resource ID (`properties.workspaceId` form) | — | Pins the Log Analytics workspace for the methods-matrix usage axis and the legacy-auth drill-down. If the Entra ID diagnostic settings point to exactly one workspace, that one is used automatically and this isn't needed. If they point to several, the module doesn't guess: `Evidence-04` becomes `Review required` with every workspace found (name, retention, categories); re-run with this parameter to pin one. |
| `-EmergencyAccountUpn` | string[] | UPNs | — | The actual break-glass accounts. Only these get the full break-glass verdict; without this list the script shows candidates for confirmation at best. |
| `-EmergencyAccountId` | string[] | object IDs (GUIDs) | — | Alternative to `-EmergencyAccountUpn`. |
| `-BrandFile` | string | path to JSON | — | Branding for the report UI. Without this parameter, the module runs with CAInventory's own, plain identity. To brand the report, copy `brand.example.json` (next to this file), edit the copy, and pass it. |
| `-OutputPath` | string | path | `./output` (relative to the current location) | Base under which the timestamped run folder lands. |
| `-IncludeSensitiveMethodDetails` | switch | on/off | off | Includes sensitive authentication method details (phone numbers etc., always masked). Without this switch, readiness from `userRegistrationDetails` stays the leading source. |
| `-AuthMode` | string | `Delegated`, `AppOnly` | `Delegated` | `Delegated`: interactive sign-in. `AppOnly`: unattended (scheduled/CI) run with a certificate; the run never prompts for input. Requires `-ClientId` and `-CertificateThumbprint`. |
| `-ClientId` | string | app registration GUID | — | Only with `-AuthMode AppOnly`. Passed to `Connect-CAInv`. |
| `-CertificateThumbprint` | string | 40-character thumbprint | — | Only with `-AuthMode AppOnly`. The certificate must be in the certificate store of the machine running the script. Passed to `Connect-CAInv`. |
| `-SkipConnect` | switch | on/off | off | Skips reconnecting if a session already exists, for instance after a separate `Connect-CAInv` call. |
| `-IncludeExchange` | switch | on/off | off | Also connects Exchange Online for the SMTP AUTH and mailbox CAS checks. Passed to `Connect-CAInv`. Has no effect with `-SkipConnect`; connect Exchange yourself with `Connect-CAInv -IncludeExchange` in that case. |
| `-Environment` | string | `Global`, `USGov`, `USGovDoD`, `China` | `Global` | See `Connect-CAInv`. |

```powershell
# Full inventory, all eight layers, against an already-connected tenant, with your own brand file
# (copied from brand.example.json, so a relative path from the module root).
Connect-CAInv -TenantId 'contoso.onmicrosoft.com'
Invoke-CAInventory -TenantId 'contoso.onmicrosoft.com' -Layer All -OutputPath ./output `
    -BrandFile ./your-brand.json

# Unattended run (scheduled task / CI) with a certificate. No prompts, all layers.
Invoke-CAInventory -TenantId $tenantId -AuthMode AppOnly -ClientId $appId `\
    -CertificateThumbprint $thumb -OutputPath ./output -BrandFile ./your-brand.json

# A single layer, with the real break-glass accounts named for the full verdict.
Invoke-CAInventory -TenantId $tenantId -Layer Identity `
    -EmergencyAccountUpn 'breakglass1@contoso.com','breakglass2@contoso.com' -BrandFile ./your-brand.json
```

### Output

Every run writes to `<OutputPath>/<yyyyMMdd-HHmmss>/`:

| Path | Contents |
|---|---|
| `raw/{domain}/*.json` (+ `.sha256`) | Raw Graph response per domain, as evidence. |
| `normalized/findings.csv` | All records, flattened. |
| `normalized/findings.json` | The same records, as the versioned interop contract. This is the file to hand off to other tooling. |
| `reports/report.html` | One self-contained report file: Scorecard, Needs review, MFA methods, Rollout order, Open work, and Reference all live here, behind tabs, in the order of the guided flow. Scorecard, Needs review, Rollout order, and Open work share the same decisions live within this file (Confirmed/Accepted/Resolved) — a click on one is instantly visible on the others, even offline, even in Firefox. Works with a double-click on the file; no local server needed, and nothing needed alongside it — the file stands on its own. |
| `reports/report-print.html` | The full report as one printable document: cover page, scorecard, the decisions made, all findings, the rollout order, and two appendices. Open it in the browser, pick the depth at the top (**everything that needs attention** or **everything, including what's fine**) and print to PDF. The page reads the checkbox decisions from the browser you open it in and never writes to them; if the decisions were made elsewhere, export them there and import the file here. Deliberately stays a separate file: a hidden tab doesn't print, and this report puts its entire content statically into the HTML instead of via JavaScript, with its own A4 page flow. |
| `reports/findings-register.xlsx` (or `findings-register/*.csv` without `ImportExcel`) | Work list with Findings/Review/Exceptions/NotAssessed/RunInfo tabs. |
| `reports/api-drift.json` | Which endpoints were called, which ran on beta, which failed — a signal for a Graph change before it hits production. |
| `logs/collector.log` | The full, structured run log. |

The return value of `Invoke-CAInventory` carries the same paths (`.NormalizedCsv`,
`.NormalizedJson`, `.Report`, `.PrintReport`, `.FindingsRegister`, `.ApiDriftReport`,
`.WorkbookFacts`), plus `.Records` (the records themselves, in memory) and
`.RunId`/`.RecordCount`/`.OutputRoot`. The six pages that together make up `report.html`
(Scorecard, Needs review, MFA methods, Rollout order, Open work, Reference) don't exist as
separate files, so they don't get their own path on the return value either.

### Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Microsoft.Graph is not installed` | Run `Install-Module Microsoft.Graph -Scope CurrentUser`. |
| `AppOnly requires -ClientId and -CertificateThumbprint` | Pass both parameters with `-AuthMode AppOnly`. Delegated sign-in is not allowed for unattended runs. |
| `'CertificateThumbprint' must have a length of 40` | The thumbprint is not a 40-character SHA-1 value. Copy it from the certificate properties, without spaces. |
| Checks show `Not assessed` with a missing-scope or missing-module reason | The session lacks a permission or module. The run continues; install the module or grant the permission and run again. |
| Log window stays at about 30 days | No Log Analytics workspace is readable. Use `Log Analytics Reader` or `Monitoring Reader` on the workspace, or accept the Graph `signInLogs` ceiling. |
| `Evidence-04` is `Review required` | Several workspaces receive the Entra diagnostic logs. Pin one with `-PrimaryWorkspaceId`. |

### Status model

Every record gets exactly one of four statuses:

| Status | Meaning | Counts toward ready? |
|---|---|---|
| `Ready` | Compliant, provable via Graph. | Yes |
| `Gap` | Not compliant, provable via Graph. | No |
| `Review required` | Not technically determinable with certainty; a human must confirm. | No, not even partially. |
| `Not assessed` | Not measured (missing scope, license, module, or context). Always carries a `NotAssessedReason`. | No, and doesn't count toward the coverage percentage either. |

A check with `reliability: manual` in `config/checkids.json` (`Emergency-06`, `Auth-15`,
`Govern-02`) never becomes `Ready` automatically: it always requires human confirmation outside
the script. `Foundation-04` used to be in this list too, until 0.20.0, and is now actually
measurable (per-user MFA status via a beta endpoint); `RSK-004` has been removed.
