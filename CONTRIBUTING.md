<!--
SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
SPDX-License-Identifier: Apache-2.0
-->

# Contributing

Thanks for your interest in `@wdl-dev/aws-sigv4`. This repository uses the
Apache License, Version 2.0. Unless you explicitly say otherwise, contributions
intentionally submitted for this project are licensed under Apache-2.0 without
extra terms or conditions.

No copyright assignment, CLA, or DCO sign-off is required for ordinary
contributions.

This package intentionally keeps a narrow SigV4 surface. Changes should avoid
adding credential providers, AWS SDK command abstractions, endpoint discovery,
presigned URLs, waiters, or paginators.

Use Node.js 24 or newer.

Before opening a pull request, run:

```sh
npm test
npm pack --dry-run
git diff --cached --check
```

## Releases

Releases are tag-driven and cut by maintainers. Pushing `v<package-version>`
runs the release workflow, verifies the package, publishes to npmjs and GitHub
Packages, and creates a GitHub Release. Never run `npm publish` by hand.
If one registry publish job succeeds and the other fails, rerun only failed
jobs in GitHub Actions; do not rerun the entire workflow, because package
versions are immutable once accepted by a registry.

This repository follows the same first-release bootstrap as `@wdl-dev/cli`:
publish an RC first, then promote to the final release after the real package
artifact and registry wiring have been tested.

For the first release, keep `version` on a prerelease such as `1.0.0-rc.1`,
commit, and push tag `v1.0.0-rc.1`. Prerelease versions publish under the
`next` dist-tag, so stable installs stay on the last final release while the
candidate can be tested as a real package.

The first npmjs publish uses `NPM_TOKEN` because npmjs trusted publishing cannot
be configured until the package exists. After the RC lands, configure trusted
publishing for this repository and `.github/workflows/release.yml`, switch the
npmjs publish job to OIDC-only, remove `NODE_AUTH_TOKEN`, bump `version` to
`1.0.0`, and tag `v1.0.0`.
