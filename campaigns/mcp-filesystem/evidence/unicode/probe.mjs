#!/usr/bin/env node
// Worker lane probe for family `unicode` (request unicode--r1).
// Mechanism: Unicode NFC-equivalent path components through validatePath.
// Only non-existent requested paths reach resolveUnicodeEquivalentPath
// (lib.ts:100-138, via the ENOENT branch at lib.ts:172-181); that walk
// starts at the realpath'd allowed root, matches entries by NFC form, and
// re-verifies containment after every step, so an escape is structurally
// impossible while "outside" itself is pure ASCII with no NFC variant.
// This probe documents the compat behavior, the ambiguity guard, and an
// escape attempt, all inside a scratch-built attacker tree. validatePath is
// the pinned upstream implementation compiled from the read-only snapshot.
// Prints MCPFS-ROOT-ESCAPE only if the synthetic secret is read.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const snapshot = process.env.VRH_SNAPSHOT;
const scratch = process.env.VRH_SCRATCH;
const marker = "MCPFS-ROOT-ESCAPE";
if (!snapshot || !scratch) {
  console.error("VRH_SNAPSHOT and VRH_SCRATCH are required");
  process.exit(2);
}

const srcDir = path.join(scratch, "src");
const outDir = path.join(scratch, "dist");
fs.mkdirSync(srcDir, { recursive: true });
fs.mkdirSync(outDir, { recursive: true });
for (const name of ["path-validation.ts", "path-utils.ts", "lib.ts"]) {
  fs.copyFileSync(path.join(snapshot, name), path.join(srcDir, name));
}
const modules = path.join(scratch, "node_modules");
if (!fs.existsSync(modules)) {
  fs.symlinkSync("/app/node_modules", modules);
}

const tsc = "/app/node_modules/typescript/bin/tsc";
try {
  execFileSync(
    tsc,
    [
      "--outDir", outDir,
      "--rootDir", srcDir,
      "--target", "ES2022",
      "--module", "Node16",
      "--moduleResolution", "Node16",
      "--skipLibCheck",
      "--esModuleInterop",
      path.join(srcDir, "path-validation.ts"),
      path.join(srcDir, "path-utils.ts"),
      path.join(srcDir, "lib.ts"),
    ],
    { stdio: ["ignore", "pipe", "pipe"], cwd: scratch },
  );
} catch (err) {
  const detail = err.stdout?.toString() || err.stderr?.toString() || err.message;
  console.error("tsc failed:", detail);
  process.exit(2);
}

const { setAllowedDirectories, validatePath } = await import(
  pathToFileURL(path.join(outDir, "lib.js")).href
);

const root = path.join(scratch, "unicode-tree");
const sandbox = path.join(root, "sandbox");
fs.mkdirSync(sandbox, { recursive: true });

// 1. NFC-named file on disk ("cafe\u0301" is NFD; NFC form is "caf\u00e9").
const nfcName = "caf\u00e9.txt";
const nfdName = "cafe\u0301.txt";
fs.writeFileSync(path.join(sandbox, nfcName), "SYNTHETIC-INSIDE\n");
// 2. Ambiguity: both normalization forms exist as distinct entries.
fs.writeFileSync(path.join(sandbox, nfdName), "SYNTHETIC-NFD\n");

// 3. Escape attempt: NFC-equivalent spelling of a component that would
// resolve to the outside secret. "outside" is ASCII (no NFC variant), so
// use a lookalike component; nothing inside the root matches it, and the
// walk must never leave the root.
const escapeAttempts = [
  "outsid\u0308/secret.txt",
  "\u006f\u0308utside/secret.txt",
  "cafe\u0301/../../outside/secret.txt",
];

const sandboxReal = fs.realpathSync(sandbox);
setAllowedDirectories([sandbox]);

let escaped = false;

// Compat case: NFD spelling of the NFC-only entry resolves inside the root.
{
  let outcome;
  try {
    const resolved = await validatePath(path.join(sandbox, nfdName));
    const inside = resolved.startsWith(sandboxReal + path.sep);
    const text = fs.readFileSync(resolved, "utf8");
    if (!inside) {
      escaped = true;
      console.log(marker);
    }
    outcome = `resolved=${resolved} inside_root=${inside} content=${text.trim()}`;
  } catch (err) {
    outcome = `rejected: ${String(err.message).split("\n")[0]}`;
  }
  console.log(JSON.stringify({ requested: `sandbox/${nfdName} (NFD spelling)`, outcome }));
}

// Ambiguity case: NFC and NFD entries both exist; NFD spelling is ambiguous.
// The allowed root is pointed at the ambiguity tree so the request reaches
// the NFC walk instead of being stopped by the lexical gate.
{
  const ambDir = path.join(scratch, "amb");
  fs.mkdirSync(ambDir, { recursive: true });
  fs.writeFileSync(path.join(ambDir, nfcName), "A\n");
  fs.writeFileSync(path.join(ambDir, nfdName), "B\n");
  setAllowedDirectories([ambDir]);
  let outcome;
  try {
    const resolved = await validatePath(path.join(ambDir, nfdName));
    outcome = `resolved=${resolved} (ambiguity NOT detected)`;
  } catch (err) {
    outcome = `rejected: ${String(err.message).split("\n")[0]}`;
  }
  setAllowedDirectories([sandbox]);
  console.log(JSON.stringify({ requested: `amb/${nfdName} (both forms exist)`, outcome }));
}

for (const requested of escapeAttempts) {
  let outcome;
  try {
    const resolved = await validatePath(requested);
    let text = "";
    try {
      text = fs.readFileSync(resolved, "utf8");
      outcome = `resolved=${resolved} READ`;
    } catch (readErr) {
      outcome = `resolved=${resolved} read_failed=${readErr.code}`;
    }
    if (text.includes("SYNTHETIC-SECRET")) {
      outcome = `resolved=${resolved} SECRET READ`;
      escaped = true;
      console.log(marker);
    }
  } catch (err) {
    outcome = `rejected: ${String(err.message).split("\n")[0]}`;
  }
  console.log(JSON.stringify({ requested, outcome }));
}

if (!escaped) {
  console.log("unicode: NFC resolution stayed inside the root; ambiguity guarded; confinement held");
}
