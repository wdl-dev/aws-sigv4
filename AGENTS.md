<!--
SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
SPDX-License-Identifier: Apache-2.0
-->

# AGENTS.md

This repository contains `@wdl-dev/aws-sigv4`, a small zero-dependency AWS
Signature Version 4 signer for web-standard runtimes, with focused coverage for
JSON AWS APIs and S3-compatible object storage. Keep the package narrow: HTTP
request signing only, with no credential providers, AWS SDK command wrappers,
endpoint discovery, presigned URLs, waiters, or paginators.

Use Node.js 24 or newer. The TypeScript target is ES2025.

Before handing off or committing staged changes, run:

```sh
npm run lint
npm run format:check
npm test
npm pack --dry-run
git diff --cached --check
```

`npm test` runs `tsc --project tsconfig.json` before the Node test suite. The
published package is intentionally small; `npm pack --dry-run` should keep the
tarball limited to `LICENSE`, `NOTICE`, `README.md`, `package.json`, and
`dist/`.

Release tags are handled by `.github/workflows/release.yml`. npmjs publishing
uses trusted publishing with GitHub Actions OIDC, and GitHub Packages publishing
uses the workflow `GITHUB_TOKEN`. Do not run `npm publish` by hand.
