# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: go to the **Security** tab of this repository and choose
**Report a vulnerability**. That opens a private advisory that only you and the maintainer can see.

Include the module version, the steps to reproduce, and what you expected to happen. I aim to respond
within a week.

## What counts

- A way for CAInventory to write to a tenant. It is designed to be read-only, so any write is a bug.
- A way to leak tenant data, tokens or certificate material from the module or its output.
- A weakness in how the module handles credentials or the output folder.

## Tenant data in issues

Never paste output from a real run into an issue, a discussion or a pull request. The output folder
contains users, policies and raw Graph responses. Redact it first, or describe the problem without it.
