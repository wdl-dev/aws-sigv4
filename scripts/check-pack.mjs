// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { publicTypeExports, publicValueExports } from "./public-api.mjs";

const rootDir = resolve(import.meta.dirname, "..");
const npmExecPath = process.env.npm_execpath;
const expectedFiles = ["LICENSE", "NOTICE", "README.md", "dist/index.d.ts", "dist/index.js", "package.json"].sort();
const outputArgument = process.argv[2];
const publicImport = [...publicValueExports, ...publicTypeExports.map((name) => `type ${name}`)].join(", ");

if (process.argv.length > 3) {
  throw new TypeError("check-pack.mjs accepts at most one output tarball path");
}

if (!npmExecPath) {
  throw new Error("check-pack.mjs must be run through npm run check:pack");
}

const directory = mkdtempSync(join(tmpdir(), "aws-sigv4-package-"));
try {
  const result = run(
    process.execPath,
    [npmExecPath, "pack", "--json", "--ignore-scripts", "--pack-destination", directory],
    rootDir
  );

  let reports;
  try {
    reports = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error("npm pack returned invalid JSON", { cause: error });
  }

  if (
    !Array.isArray(reports) ||
    reports.length !== 1 ||
    !Array.isArray(reports[0]?.files) ||
    typeof reports[0]?.filename !== "string"
  ) {
    throw new Error("npm pack returned an unexpected report shape");
  }
  if (!reports[0].files.every((file) => file && typeof file.path === "string")) {
    throw new Error("npm pack returned an invalid file entry");
  }

  const actualFiles = reports[0].files.map((file) => file.path).sort();
  const missing = expectedFiles.filter((file) => !actualFiles.includes(file));
  const unexpected = actualFiles.filter((file) => !expectedFiles.includes(file));
  const duplicates = actualFiles.filter((file, index) => actualFiles.indexOf(file) !== index);

  if (missing.length > 0 || unexpected.length > 0 || duplicates.length > 0) {
    const details = [
      missing.length === 0 ? undefined : `missing: ${missing.join(", ")}`,
      unexpected.length === 0 ? undefined : `unexpected: ${unexpected.join(", ")}`,
      duplicates.length === 0 ? undefined : `duplicated: ${[...new Set(duplicates)].join(", ")}`,
    ].filter(Boolean);
    throw new Error(`published file allowlist mismatch (${details.join("; ")})`);
  }

  const tarball = join(directory, reports[0].filename);
  verifyTarballConsumer(directory, tarball);
  if (outputArgument !== undefined) {
    copyFileSync(tarball, resolve(rootDir, outputArgument));
  }
  process.stdout.write(`Verified ${actualFiles.length} published files: ${actualFiles.join(", ")}\n`);
} finally {
  rmSync(directory, { force: true, recursive: true });
}

function verifyTarballConsumer(directory, tarball) {
  const consumerDirectory = join(directory, "consumer");
  mkdirSync(consumerDirectory);
  writeFileSync(
    join(consumerDirectory, "package.json"),
    `${JSON.stringify({ private: true, type: "module" }, null, 2)}\n`
  );
  run(
    process.execPath,
    [npmExecPath, "install", tarball, "--ignore-scripts", "--offline", "--no-audit", "--no-fund"],
    consumerDirectory
  );
  writeFileSync(
    join(consumerDirectory, "consumer.ts"),
    [
      `import { ${publicImport} } from "@wdl-dev/aws-sigv4";`,
      "",
      "const requestOnlyFetch = async (request: Request): Promise<Response> => new Response(request.url);",
      "const nullMissCache: SigningKeyCache = {",
      "  get: () => null,",
      "  set: () => undefined,",
      "};",
      "const minimalOptions: SigV4ClientOptions = {",
      '  accessKeyId: "AKID",',
      '  secretAccessKey: "secret",',
      '  service: "s3",',
      '  region: "us-east-1",',
      "};",
      "const client = new SigV4Client(minimalOptions);",
      "declare const compatibleInit: SigV4RequestInit;",
      "const nativeInit: RequestInit = compatibleInit;",
      'void fetch("https://example.com/", compatibleInit);',
      'void new Request("https://example.com/", compatibleInit);',
      "void nativeInit;",
      "class CompatibleClient extends SigV4Client {",
      "  override async sign(input: Request | string | URL, init?: SigV4RequestInit): Promise<Request> {",
      "    return super.sign(input, init);",
      "  }",
      "  override async fetch(input: Request | string | URL, init?: SigV4RequestInit): Promise<Response> {",
      "    return super.fetch(input, init);",
      "  }",
      "}",
      "new CompatibleClient(minimalOptions);",
      "const requestSigningOptions: SigV4RequestSigningOptions = {};",
      "void requestSigningOptions;",
      "const signingOptions: SignAwsRequestOptions = {",
      "  ...minimalOptions,",
      '  url: "https://s3.us-east-1.amazonaws.com/bucket/key",',
      '  method: "PUT",',
      "};",
      "const signedRequest: Promise<SignedAwsRequest> = signAwsRequest(signingOptions);",
      "void signedRequest;",
      "const extendedOptions: SigV4ClientOptions = {",
      "  ...minimalOptions,",
      "  cache: nullMissCache,",
      "  fetch: requestOnlyFetch,",
      "};",
      "new SigV4Client(extendedOptions);",
      "",
    ].join("\n")
  );
  const tscBin = join(rootDir, "node_modules", "typescript", "bin", "tsc");
  run(
    process.execPath,
    [
      tscBin,
      "--ignoreConfig",
      "--target",
      "ES2025",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      "--lib",
      "ES2025,DOM,DOM.Iterable",
      "--strict",
      "--exactOptionalPropertyTypes",
      "--skipLibCheck",
      "false",
      "--noEmit",
      "consumer.ts",
    ],
    consumerDirectory
  );
  writeFileSync(
    join(consumerDirectory, "consumer.mjs"),
    [
      'import { SigV4Client } from "@wdl-dev/aws-sigv4";',
      "",
      "new SigV4Client({",
      '  accessKeyId: "AKID",',
      '  secretAccessKey: "secret",',
      '  service: "s3",',
      '  region: "us-east-1",',
      "  fetch: async () => new Response(),",
      "});",
      "",
    ].join("\n")
  );
  run(process.execPath, ["consumer.mjs"], consumerDirectory);
}

function run(command, args, cwd) {
  const commandResult = spawnSync(command, args, { cwd, encoding: "utf8" });
  if (commandResult.error) {
    throw commandResult.error;
  }
  if (commandResult.status !== 0) {
    process.stdout.write(commandResult.stdout);
    process.stderr.write(commandResult.stderr);
    throw new Error(`${commandLabel(command, args)} failed with exit code ${commandResult.status ?? "unknown"}`);
  }
  return commandResult;
}

function commandLabel(command, args) {
  if (command !== process.execPath || args.length === 0) {
    return command;
  }
  const subcommand = args[1] && !args[1].startsWith("-") ? ` ${args[1]}` : "";
  return `${args[0]}${subcommand}`;
}
