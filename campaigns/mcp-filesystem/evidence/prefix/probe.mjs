#!/usr/bin/env node
// Worker lane probe for family `prefix` (request prefix--r1).
// Mechanism: allowed-directory string-prefix matching, i.e. an absolute
// sibling path that starts with the allowed root's text but is not inside it
// (/root/sandboxevil, /root/sandbox.evil). The snapshot is read-only, so the
// attacker tree is built in the scratch tmpfs and setAllowedDirectories is
// pointed at it; validatePath itself is the pinned upstream implementation
// compiled from the read-only snapshot. Source expectation: the containment
// check appends path.sep before startsWith (path-validation.ts:84), so the
// classic prefix bypass is guarded. Prints MCPFS-ROOT-ESCAPE only if the
// synthetic secret is read.
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

// Attacker-controlled sibling trees next to the allowed root.
const root = path.join(scratch, "prefix-tree");
const sandbox = path.join(root, "sandbox");
for (const dir of [sandbox, path.join(root, "sandboxevil"), path.join(root, "sandbox.evil")]) {
  fs.mkdirSync(dir, { recursive: true });
}
for (const dir of ["sandboxevil", "sandbox.evil"]) {
  fs.writeFileSync(path.join(root, dir, "secret.txt"), "SYNTHETIC-SECRET\n");
}
setAllowedDirectories([sandbox]);

const secretPaths = [
  path.join(root, "sandboxevil", "secret.txt"),
  path.join(root, "sandbox.evil", "secret.txt"),
];
// Boundary cases that must stay allowed (they ARE the root or inside it).
// A rejection here means the probe is misconfigured, not that the mechanism
// is refuted — fail closed with a nonzero exit so the run cannot be recorded
// as a valid non-reproduction.
const boundaryPaths = [sandbox, path.join(sandbox, "public.txt")];

let escaped = false;
for (const requested of secretPaths) {
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
for (const requested of boundaryPaths) {
  let outcome;
  try {
    const resolved = await validatePath(requested);
    outcome = `resolved=${resolved} (inside, expected)`;
  } catch (err) {
    outcome = `rejected unexpectedly: ${String(err.message).split("\n")[0]}`;
    console.log(JSON.stringify({ requested, outcome }));
    console.error("prefix: positive control rejected; probe invalid, refusing to record a non-reproduction");
    process.exit(3);
  }
  console.log(JSON.stringify({ requested, outcome }));
}

if (!escaped) {
  console.log("prefix: sibling-prefix paths rejected; containment held");
}
