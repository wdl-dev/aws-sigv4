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
npm run lint
npm run format:check
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

npmjs publishing uses trusted publishing with GitHub Actions OIDC. GitHub
Packages publishing uses the workflow `GITHUB_TOKEN`; no repository package
token is required. Prerelease versions publish under the `next` dist-tag, and
final versions publish under `latest`.
