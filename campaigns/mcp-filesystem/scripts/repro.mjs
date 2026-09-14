#!/usr/bin/env node
// Hypothesis probe: call upstream validatePath with a path outside the
// allowed MCP root. Print MCPFS-ROOT-ESCAPE only if the synthetic secret
// is readable. A quiet exit is a non-reproduction, not a finding.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const snapshot = process.env.VRH_SNAPSHOT;
const scratch = process.env.VRH_SCRATCH;
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
      "--outDir",
      outDir,
      "--rootDir",
      srcDir,
      "--target",
      "ES2022",
      "--module",
      "Node16",
      "--moduleResolution",
      "Node16",
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

// Positive control: an in-root fixture file must validate and read. Without
// it, a deny-all or otherwise broken validator would also exit quietly on
// the escape attempt below and be recorded as a valid baseline
// non-reproduction. Fail closed via the runner's sandbox-fail exit (125):
// vrh repro fails loudly, exports nothing, and appends no ledger event.
try {
  const control = await validatePath("public.txt");
  const controlText = fs.readFileSync(control, "utf8");
  if (!controlText.includes("public sandbox file")) {
    console.error("baseline: positive control read unexpected content; probe invalid (exit 125)");
    process.exit(125);
  }
} catch (err) {
  console.error("baseline: positive control failed; probe invalid (exit 125):", String(err?.message || err).split("\n")[0]);
  process.exit(125);
}

let resolved;
try {
  resolved = await validatePath("../outside/secret.txt");
} catch {
  process.exit(0);
}

let text = "";
try {
  text = fs.readFileSync(resolved, "utf8");
} catch {
  process.exit(0);
}
if (text.includes("SYNTHETIC-SECRET")) {
  console.log(marker);
}
