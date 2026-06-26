<!--
SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

## Supported Versions

Only the latest `@wdl-dev/aws-sigv4` release receives security fixes.

## Reporting A Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Use GitHub's private vulnerability reporting instead: open the repository's
**Security** tab and choose **Report a vulnerability**
(<https://github.com/wdl-dev/aws-sigv4/security/advisories/new>).

Include reproduction steps, the affected package version or commit, the signed
request shape, and any relevant logs with credentials and signatures removed.
Please allow the maintainers a reasonable window to ship a fix before any
public disclosure.

If the reporting form is unavailable, email <security@wdl.dev> instead.

## Scope

Reports about canonical request construction, query encoding, header selection,
payload hashing, credential handling, retry behavior, or AWS service-specific
SigV4 compatibility are particularly welcome.
