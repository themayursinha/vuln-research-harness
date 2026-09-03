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
  process.exit(2);
}

const { setAllowedDirectories, validatePath } = await import(
  pathToFileURL(path.join(outDir, "lib.js")).href
);

const sandbox = path.resolve(snapshot, "sandbox");
setAllowedDirectories([sandbox]);

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
