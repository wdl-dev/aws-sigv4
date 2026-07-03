// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(rootDir, "dist");
const workDir = mkdtempSync(join(tmpdir(), "aws-sigv4-build-"));
const tscBin = join(rootDir, "node_modules", "typescript", "bin", "tsc");

// This is a package-specific bundler for this repo's TypeScript output, not a general-purpose bundler.
try {
  rmSync(outDir, { force: true, recursive: true });
  mkdirSync(outDir, { recursive: true });
  runTypeScript(["--project", "tsconfig.json", "--outDir", workDir, "--declaration", "true"]);

  const outputJavaScript = join(outDir, "index.js");
  const outputDeclarations = join(outDir, "index.d.ts");
  writeFileSync(outputJavaScript, bundleJavaScript(workDir));
  writeFileSync(outputDeclarations, bundleDeclarations(workDir));

  execFileSync(process.execPath, ["--check", outputJavaScript], { cwd: rootDir, stdio: "inherit" });
  checkDeclarations(outputDeclarations);
} finally {
  rmSync(workDir, { force: true, recursive: true });
}

function runTypeScript(args) {
  execFileSync(process.execPath, [tscBin, ...args], { cwd: rootDir, stdio: "inherit" });
}

function checkDeclarations(file) {
  runTypeScript([
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
    "--skipLibCheck",
    "false",
    "--noEmit",
    file,
  ]);
}

function bundleJavaScript(moduleDir) {
  const chunks = sortedModules(moduleDir, "index.js", false)
    .map((file) => stripJavaScriptModuleSyntax(readModule(moduleDir, file)).trim())
    .filter(Boolean);
  return `${chunks.join("\n\n")}\n\n${entryExports(readModule(moduleDir, "index.js"), false).join("\n")}\n`;
}

function bundleDeclarations(moduleDir) {
  const chunks = sortedModules(moduleDir, "index.d.ts", true)
    .map((file) => stripDeclarationModuleSyntax(readModule(moduleDir, file)).trim())
    .filter(Boolean);
  return `${chunks.join("\n\n")}\n\n${entryExports(readModule(moduleDir, "index.d.ts"), true).join("\n")}\n`;
}

function sortedModules(moduleDir, entry, declarations) {
  const seen = new Set();
  const out = [];

  function visit(file) {
    if (seen.has(file)) {
      return;
    }
    seen.add(file);
    for (const dependency of moduleDependencies(readModule(moduleDir, file), file, declarations)) {
      visit(dependency);
    }
    out.push(file);
  }

  visit(entry);
  return out;
}

function moduleDependencies(code, file, declarations) {
  const dependencies = [];
  for (const line of code.split("\n")) {
    const match =
      /^\s*import\s+"([^"]+)";$/u.exec(line) || /^\s*(?:import|export)\s+.*\sfrom\s+"([^"]+)";$/u.exec(line);
    if (match) {
      dependencies.push(resolveModuleSpecifier(file, match[1], declarations));
    }
  }
  return dependencies;
}

function resolveModuleSpecifier(file, specifier, declarations) {
  if (!specifier.startsWith("./") && !specifier.startsWith("../")) {
    throw new Error(`Cannot bundle external module ${specifier}`);
  }
  const resolved = join(dirname(file), specifier);
  return declarations && resolved.endsWith(".js") ? `${resolved.slice(0, -3)}.d.ts` : resolved;
}

function stripJavaScriptModuleSyntax(code) {
  return code
    .split("\n")
    .filter((line) => !/^\s*import\s/u.test(line))
    .filter((line) => !/^\s*export\s+\{.*\}\s+from\s/u.test(line))
    .filter((line) => !/^\s*export\s+\{.*\};?\s*$/u.test(line))
    .filter((line) => !/^\s*export\s*\{\s*\};?\s*$/u.test(line))
    .map((line) => line.replace(/^export\s+(?=(?:async\s+)?function|class|const|let|var)\b/u, ""))
    .join("\n");
}

function stripDeclarationModuleSyntax(code) {
  return code
    .split("\n")
    .filter((line) => !/^\s*import\s/u.test(line))
    .filter((line) => !/^\s*export\s+(?:type\s+)?\{.*\}\s+from\s/u.test(line))
    .filter((line) => !/^\s*export\s+(?:type\s+)?\{.*\};?\s*$/u.test(line))
    .filter((line) => !/^\s*export\s*\{\s*\};?\s*$/u.test(line))
    .map((line) =>
      line.replace(/^export\s+(?=(?:declare\s+)?(?:class|function|const|let|var|interface|type|enum|namespace)\b)/u, "")
    )
    .join("\n");
}

function entryExports(code, typeSyntax) {
  const exports = [];
  const exportList = typeSyntax ? String.raw`(?:type\s+)?\{[^}]+\}` : String.raw`\{[^}]+\}`;
  for (const line of code.split("\n")) {
    const match = new RegExp(String.raw`^\s*export\s+(${exportList})(?:\s+from\s+"[^"]+")?;?\s*$`, "u").exec(line);
    if (match) {
      exports.push(`export ${match[1]};`);
    }
  }
  return exports;
}

function readModule(moduleDir, file) {
  return readFileSync(join(moduleDir, file), "utf8");
}
