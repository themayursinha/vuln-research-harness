#!/usr/bin/env node
// Worker lane probe for family `symlink` (request symlink--r1).
// Mechanism: symlink inside the allowed root that resolves outside it.
// The attacker cannot plant symlinks through the tool surface (tools.json
// has no symlink primitive; write_file uses 'wx' and atomic rename, lib.ts:207-219),
// so this probe establishes the precondition directly in the scratch tmpfs
// and tests whether the realpath guard (lib.ts:160-168) stops the escape.
// validatePath is the pinned upstream implementation compiled from the
// read-only snapshot. Prints MCPFS-ROOT-ESCAPE only if the synthetic secret
// is read.
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

// Attacker tree: allowed root with two symlinks pointing outside it.
const root = path.join(scratch, "symlink-tree");
const sandbox = path.join(root, "sandbox");
const outside = path.join(root, "outside");
fs.mkdirSync(sandbox, { recursive: true });
fs.mkdirSync(outside, { recursive: true });
fs.writeFileSync(path.join(outside, "secret.txt"), "SYNTHETIC-SECRET\n");
fs.writeFileSync(path.join(sandbox, "public.txt"), "SYNTHETIC-PUBLIC\n");
fs.symlinkSync(path.join(outside, "secret.txt"), path.join(sandbox, "link"));
fs.symlinkSync(outside, path.join(sandbox, "dirlink"));
// Control: symlink that stays inside the root must keep working.
fs.symlinkSync(path.join(sandbox, "public.txt"), path.join(sandbox, "link-in"));
setAllowedDirectories([sandbox]);

const attempts = [
  path.join(sandbox, "link"),
  path.join(sandbox, "dirlink", "secret.txt"),
  path.join(sandbox, "link-in"),
];

let escaped = false;
for (const requested of attempts) {
  let outcome;
  try {
    const resolved = await validatePath(requested);
    let text = "";
    try {
      text = fs.readFileSync(resolved, "utf8");
      outcome = `resolved=${resolved} READ`;
    } catch (readErr) {
      outcome = `resolved=${resolved} read_failed=${readErr.code}`;
      // Positive control: the in-root symlink must keep resolving AND its
      // target must be readable. A read failure here means the probe is
      // misconfigured, not that the escape mechanism is refuted — fail
      // closed via the runner's sandbox-fail exit (125) so the run cannot
      // be recorded as a valid non-reproduction.
      if (requested === path.join(sandbox, "link-in")) {
        console.log(JSON.stringify({ requested, outcome }));
        console.error("symlink: positive control read failed; probe invalid, failing the run (exit 125)");
        process.exit(125);
      }
    }
    if (text.includes("SYNTHETIC-SECRET")) {
      outcome = `resolved=${resolved} SECRET READ`;
      escaped = true;
      console.log(marker);
    }
  } catch (err) {
    outcome = `rejected: ${String(err.message).split("\n")[0]}`;
    // Positive control: the in-root symlink must keep resolving. Its
    // rejection means the probe is misconfigured, not that the escape
    // mechanism is refuted — fail closed via the runner's sandbox-fail
    // exit (125) so the run cannot be recorded as a valid non-reproduction.
    if (requested === path.join(sandbox, "link-in")) {
      console.log(JSON.stringify({ requested, outcome }));
      // Exit 125 = the repro runner's sandbox-fail channel: the run fails
      // loudly with no export and no ledger event, instead of being
      // recorded as a valid non-reproduction.
      console.error("symlink: positive control rejected; probe invalid, failing the run (exit 125)");
      process.exit(125);
    }
  }
  console.log(JSON.stringify({ requested, outcome }));
}

if (!escaped) {
  console.log("symlink: escaping symlinks rejected by realpath guard; in-root symlink still resolves");
}
