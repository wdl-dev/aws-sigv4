// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import ts from "typescript";

const rootDir = resolve(import.meta.dirname, "..");
const outDir = join(rootDir, "dist");
const tscBin = join(rootDir, "node_modules", "typescript", "bin", "tsc");
const publicValueExports = ["SigV4Client", "signAwsRequest"].sort();
const publicTypeExports = [
  "SigV4ClientOptions",
  "SigV4RequestInit",
  "SigV4RequestSigningOptions",
  "SignAwsRequestOptions",
  "SigningKeyCache",
  "SignedAwsRequest",
];
const publicDeclarationNames = [...publicValueExports, ...publicTypeExports].sort();
const moduleTextCache = new Map();

// This is a package-specific, single-writer CI bundler for this repo, not a general-purpose bundler.
let workDir;
let stagedOutDir;
try {
  workDir = mkdtempSync(join(tmpdir(), "aws-sigv4-build-"));
  stagedOutDir = mkdtempSync(join(rootDir, ".aws-sigv4-dist-"));
  runTypeScript([
    "--project",
    "tsconfig.json",
    "--outDir",
    workDir,
    "--declaration",
    "true",
    "--stripInternal",
    "true",
  ]);

  const outputJavaScript = join(stagedOutDir, "index.js");
  const outputDeclarations = join(stagedOutDir, "index.d.ts");
  writeFileSync(outputJavaScript, bundleJavaScript(workDir));
  writeFileSync(outputDeclarations, bundleDeclarations(workDir));

  execFileSync(process.execPath, ["--check", outputJavaScript], { cwd: rootDir, stdio: "inherit" });
  checkBundleSurface(outputJavaScript, outputDeclarations);
  checkDeclarations(outputDeclarations);
  rmSync(outDir, { force: true, recursive: true });
  renameSync(stagedOutDir, outDir);
} finally {
  if (workDir !== undefined) {
    rmSync(workDir, { force: true, recursive: true });
  }
  if (stagedOutDir !== undefined) {
    rmSync(stagedOutDir, { force: true, recursive: true });
  }
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

function checkBundleSurface(javaScriptFile, declarationFile) {
  const javaScript = readFileSync(javaScriptFile, "utf8");
  const declarations = readFileSync(declarationFile, "utf8");
  assertSameList(exportedNames(javaScript), publicValueExports, "JavaScript exports");
  assertSameList(exportedNames(declarations), publicDeclarationNames, "declaration exports");
  assertSameList(topLevelDeclarationNames(declarations), publicDeclarationNames, "declaration top-level names");
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
  assertModuleLikeLinesAreSyntax(code, file, declarations);
  const dependencies = [];
  for (const [index, line] of code.split("\n").entries()) {
    const trimmed = line.trim();
    if (!/^(?:import|export)\b/u.test(trimmed)) {
      continue;
    }

    const importMatch = /^import\s+(?:type\s+)?\{([^}]+)\}\s+from\s+"([^"]+)";$/u.exec(trimmed);
    if (importMatch) {
      assertUnaliasedSpecifiers(file, index, importMatch[1]);
      dependencies.push(resolveModuleSpecifier(file, index, importMatch[2], declarations));
      continue;
    }

    const reexportMatch = /^export\s+(?:type\s+)?\{([^}]+)\}\s+from\s+"([^"]+)";?$/u.exec(trimmed);
    if (reexportMatch) {
      assertUnaliasedSpecifiers(file, index, reexportMatch[1]);
      dependencies.push(resolveModuleSpecifier(file, index, reexportMatch[2], declarations));
      continue;
    }

    if (/^export\s*\{\s*\};?$/u.test(trimmed)) {
      continue;
    }

    const namedExportMatch = /^export\s+(?:type\s+)?\{([^}]+)\};?$/u.exec(trimmed);
    if (namedExportMatch) {
      assertUnaliasedSpecifiers(file, index, namedExportMatch[1]);
      throwUnsupportedModuleSyntax(file, index, "local named export lists are not bundled");
    }

    const declaration = declarations
      ? /^export\s+(?=(?:declare\s+)?(?:class|function|const|let|var|interface|type|enum|namespace)\b)/u
      : /^export\s+(?=(?:async\s+)?(?:function|class|const|let|var)\b)/u;
    if (declaration.test(trimmed)) {
      continue;
    }

    throwUnsupportedModuleSyntax(
      file,
      index,
      "only named relative imports, named re-exports, and exported declarations are bundled"
    );
  }
  return dependencies;
}

function assertModuleLikeLinesAreSyntax(code, file, declarations) {
  const source = ts.createSourceFile(
    file,
    code,
    ts.ScriptTarget.Latest,
    true,
    declarations ? ts.ScriptKind.TS : ts.ScriptKind.JS
  );
  let lineStart = 0;
  for (const [index, line] of code.split("\n").entries()) {
    const match = /^(\s*)(import|export)\b/u.exec(line);
    if (match) {
      const keywordPosition = lineStart + match[1].length;
      const token = ts.getTokenAtPosition(source, keywordPosition);
      const expectedKind = match[2] === "import" ? ts.SyntaxKind.ImportKeyword : ts.SyntaxKind.ExportKeyword;
      if (token.kind !== expectedKind || token.getStart(source) !== keywordPosition) {
        throwUnsupportedModuleSyntax(file, index, "module-like text inside a string or comment cannot be line-bundled");
      }
    }
    lineStart += line.length + 1;
  }
}

function resolveModuleSpecifier(file, lineIndex, specifier, declarations) {
  if (!specifier.startsWith("./") && !specifier.startsWith("../")) {
    throwUnsupportedModuleSyntax(file, lineIndex, `external module ${specifier} is not bundled`);
  }
  const resolved = join(dirname(file), specifier);
  return declarations && resolved.endsWith(".js") ? `${resolved.slice(0, -3)}.d.ts` : resolved;
}

function assertUnaliasedSpecifiers(file, lineIndex, specifiers) {
  if (specifiers.split(",").some((name) => /\s+as\s+/u.test(name.trim()))) {
    throwUnsupportedModuleSyntax(file, lineIndex, "aliased import or export specifiers are not bundled");
  }
}

function throwUnsupportedModuleSyntax(file, lineIndex, reason) {
  throw new Error(`${file}:${lineIndex + 1}: unsupported module syntax: ${reason}`);
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

function exportedNames(code) {
  const out = [];
  for (const match of code.matchAll(/^export\s+(?:type\s+)?\{([^}]+)\};?$/gmu)) {
    for (const part of match[1].split(",")) {
      const name = part
        .trim()
        .replace(/^type\s+/u, "")
        .split(/\s+as\s+/u)
        .pop();
      if (name) {
        out.push(name);
      }
    }
  }
  return out.sort();
}

function topLevelDeclarationNames(code) {
  const out = [];
  const declaration =
    /^(?:declare\s+)?(?:class|function|interface|type|const|let|var|enum|namespace)\s+([A-Za-z_$][\w$]*)/u;
  for (const line of code.split("\n")) {
    const match = declaration.exec(line);
    if (match) {
      out.push(match[1]);
    }
  }
  return out.sort();
}

function assertSameList(actual, expected, label) {
  if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
    throw new Error(`${label} changed: expected ${expected.join(" | ")}, got ${actual.join(" | ")}`);
  }
}

function readModule(moduleDir, file) {
  const path = join(moduleDir, file);
  let code = moduleTextCache.get(path);
  if (code === undefined) {
    code = readFileSync(path, "utf8");
    moduleTextCache.set(path, code);
  }
  return code;
}
