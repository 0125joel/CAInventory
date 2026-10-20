# Contributing

Thanks for looking at CAInventory. Bug reports, questions and pull requests are welcome.

## Before you start

- For anything bigger than a small fix, open an issue first so we can agree on the approach.
- CAInventory is read-only by design. A change that writes to a tenant will not be accepted.

## Pull requests

- Keep the change focused. One problem per pull request.
- Run the module and check that it imports:

  ```powershell
  Import-Module ./CAInventory/CAInventory.psd1 -Force
  ```

- If you change a check, update its entry in `CAInventory/config/checkids.json` and keep the CheckId
  stable. Never reuse an ID.
- If you change behavior that users see, update `How-To-Use.md` in the same pull request.
- Do not include tenant data, real tenant IDs, user names or output folders in a pull request.

## Code style

Match the code around your change: comment density, naming and structure. Comments explain the why,
not the what.
