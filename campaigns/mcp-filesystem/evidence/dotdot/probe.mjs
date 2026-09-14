#!/usr/bin/env node
// Worker lane probe for family `dotdot` (request dotdot--r1).
// Mechanism: parent-directory segments through validatePath.
// Allowed root is the snapshot's sandbox/; impact is reading the synthetic
// secret in outside/. Prints MCPFS-ROOT-ESCAPE only if the secret is read.
// Every attempt must throw per source (lib.ts:155-157 lexical gate); the
// per-attempt stdout lines are deterministic and covered by the run's
// output digest in evidence/dotdot/repro_outcomes.json.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

// Fail-closed safety net: any uncaught error must take the runner's
// sandbox-fail exit (125), never an ordinary nonzero exit that would be
// ledgered as a valid non-reproduction.
process.on("uncaughtException", (err) => {
  console.error("probe invalid (uncaught exception):", err?.message || err);
  process.exit(125);
});
process.on("unhandledRejection", (err) => {
  console.error("probe invalid (unhandled rejection):", String(err?.message || err));
  process.exit(125);
});

const snapshot = process.env.VRH_SNAPSHOT;
const scratch = process.env.VRH_SCRATCH;
const marker = "MCPFS-ROOT-ESCAPE";
if (!snapshot || !scratch) {
  console.error("VRH_SNAPSHOT and VRH_SCRATCH are required");
  process.exit(125);
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
  process.exit(125);
}

const { setAllowedDirectories, validatePath } = await import(
  pathToFileURL(path.join(outDir, "lib.js")).href
);

const sandbox = path.resolve(snapshot, "sandbox");
setAllowedDirectories([sandbox]);

const attempts = [
  "../outside/secret.txt",
  "./../outside/secret.txt",
  "sandbox/../../outside/secret.txt",
  path.join(sandbox, "..", "outside", "secret.txt"),
  "....//outside/secret.txt",
  "../outside\0/secret.txt",
];

let escaped = false;
for (const requested of attempts) {
  let outcome;
  try {
    const resolved = await validatePath(requested);
    let text = "";
    try {
      text = fs.readFileSync(resolved, "utf8");
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
  console.log("dotdot: all attempts rejected or non-impacting; confinement held");
}
