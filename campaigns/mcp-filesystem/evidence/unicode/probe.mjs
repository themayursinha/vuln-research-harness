#!/usr/bin/env node
// Worker lane probe for family `unicode` (request unicode--r1).
// Mechanism: Unicode NFC-equivalent path components through validatePath.
//
// Reachability: resolveUnicodeEquivalentPath (lib.ts:100-138) is entered
// only from the ENOENT branch (lib.ts:172-181) after the lexical gate
// (lib.ts:152-157) passed, i.e. only when the requested path is lexically
// inside the root AND fs.realpath finds no byte-identical entry. The walk
// starts at the realpath'd allowed root, matches directory entries by NFC
// form, and re-verifies containment after every step (lib.ts:131-133).
//
// The probe therefore uses spellings that byte-match no on-disk entry:
// U+01ED (ǭ, LATIN SMALL LETTER O WITH OGONEK AND MACRON) has three
// distinct canonically-equivalent spellings — the fully composed character,
// o+ogonek+macron (canonical mark order: ccc 202 < 230), and the reordered
// o+macron+ogonek (canonical ordering re-sorts it). The probe asserts these
// encoding facts at startup and fails closed (exit 3) if they do not hold
// on this runtime, rather than silently testing nothing.
//
// Trees (separate so the byte-absence preconditions cannot interfere):
//   compat tree:    only the composed entry exists; the decomposed request
//                   must resolve through the NFC fallback, inside the root.
//   ambiguity tree: composed + canonical-order entries exist; the reordered
//                   request byte-matches neither, so the ambiguity guard
//                   (lib.ts:120-122) must fire.
//   escape tree:    allowed root containing a symlink whose NAME is one
//                   byte-distinct NFC-equivalent spelling of ǭ and whose
//                   target is the readable outside secret; the request uses
//                   a different, byte-absent spelling. fs.realpath on the
//                   full request ENOENTs (byte lookup fails), so the NFC
//                   walk must resolve the equivalent prefix component — and
//                   the per-step containment re-check (lib.ts:131-133) must
//                   throw. If that check were removed, the walk would step
//                   through the symlink, resolve the secret outside, and
//                   the marker would fire, so a quiet exit is genuine
//                   evidence, not a dead oracle. (Precondition note: like
//                   the symlink lane, the escaping symlink is planted
//                   directly — the tool surface cannot create symlinks;
//                   this is a function-level mechanism probe.)
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

// Encoding preconditions: three byte-distinct spellings, one NFC form.
const composed = "\u01ED.txt";
const decompOrdered = "o\u0328\u0304.txt";
const decompReordered = "o\u0304\u0328.txt";
{
  const nfc = (s) => s.normalize("NFC");
  const sameForm =
    nfc(composed) === nfc(decompOrdered) && nfc(composed) === nfc(decompReordered);
  const distinct = new Set([composed, decompOrdered, decompReordered]).size === 3;
  if (!sameForm || !distinct) {
    console.error("unicode: Unicode encoding preconditions failed on this runtime; probe invalid (exit 125: fail the runner, do not record a non-reproduction)");
    process.exit(125);
  }
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

function failInvalid(detail) {
  console.log(JSON.stringify({ invalid: detail }));
  // Exit 125 = the repro runner's sandbox-fail channel: vrh repro fails
  // loudly, exports nothing, and appends no ledger event. Any other nonzero
  // exit would be ledgered as an ordinary non-reproduction, which would let
  // an invalid probe pass as a refutation.
  console.error("unicode: positive control failed; probe invalid, refusing to record a non-reproduction");
  process.exit(125);
}

let escaped = false;

// --- Compat tree: NFC fallback resolves a byte-absent equivalent spelling.
{
  const root = path.join(scratch, "unicode-compat");
  const sandbox = path.join(root, "sandbox");
  fs.mkdirSync(sandbox, { recursive: true });
  fs.writeFileSync(path.join(sandbox, composed), "SYNTHETIC-INSIDE\n");
  setAllowedDirectories([sandbox]);
  const sandboxReal = fs.realpathSync(sandbox);
  let outcome;
  try {
    const resolved = await validatePath(path.join(sandbox, decompOrdered));
    const text = fs.readFileSync(resolved, "utf8"); // must exist via fallback
    const inside = resolved.startsWith(sandboxReal + path.sep);
    if (!inside) {
      escaped = true;
      console.log(marker);
    }
    if (!inside || !text.includes("SYNTHETIC-INSIDE")) {
      failInvalid(`compat case did not resolve+read inside the root: resolved=${resolved} inside=${inside}`);
    }
    outcome = `resolved=${resolved} via_nfc_fallback inside_root=${inside} content=${text.trim()}`;
  } catch (err) {
    failInvalid(`compat case rejected unexpectedly: ${String(err.message).split("\n")[0]}`);
  }
  console.log(JSON.stringify({ requested: `sandbox/${decompOrdered} (byte-absent decomposed)`, outcome }));
}

// --- Ambiguity tree: two on-disk NFC-equivalent entries, byte-absent request.
{
  const root = path.join(scratch, "unicode-amb");
  const sandbox = path.join(root, "sandbox");
  fs.mkdirSync(sandbox, { recursive: true });
  fs.writeFileSync(path.join(sandbox, composed), "A\n");
  fs.writeFileSync(path.join(sandbox, decompOrdered), "B\n");
  setAllowedDirectories([sandbox]);
  let outcome;
  try {
    const resolved = await validatePath(path.join(sandbox, decompReordered));
    failInvalid(`ambiguity guard did not fire; request resolved to ${resolved}`);
  } catch (err) {
    const msg = String(err.message).split("\n")[0];
    if (!msg.includes("Ambiguous Unicode path component")) {
      failInvalid(`expected ambiguity error, got: ${msg}`);
    }
    outcome = `rejected: ${msg}`;
  }
  console.log(JSON.stringify({ requested: `sandbox/${decompReordered} (byte-absent reordered)`, outcome }));
}

// --- Escape tree: the per-step containment re-check in the NFC walk.
// sandbox contains a symlink named with the canonical-order spelling whose
// target is the outside secret directory; the request uses the reordered
// spelling (byte-absent, NFC-equivalent). fs.realpath on the full request
// ENOENTs, so only the walk's equivalent-match step can resolve it — and
// its per-step realpath containment check (lib.ts:131-133) must reject it.
// Both containment sites in lib.ts throw the same message, but the outer
// one (lib.ts:165-166) is unreachable here: it runs only after a SUCCESSFUL
// fs.realpath, and the byte-absent request makes realpath throw ENOENT.
// So observing that rejection text proves the per-step check fired. If the
// check were removed, the walk would return the outside secret path, the
// read would succeed, and the marker would fire.
{
  const root = path.join(scratch, "unicode-escape");
  const sandbox = path.join(root, "sandbox");
  const outside = path.join(root, "outside");
  fs.mkdirSync(sandbox, { recursive: true });
  fs.mkdirSync(outside, { recursive: true });
  fs.writeFileSync(path.join(outside, "secret.txt"), "SYNTHETIC-SECRET\n");
  // Link the equivalent-named entry to the outside DIRECTORY (not the file):
  // with the per-step check removed, the walk must be able to readdir the
  // escaped directory and resolve the secret inside it, otherwise removing
  // the check would still end in an unrelated ENOTDIR rejection and the
  // non-reproduction would not be falsifiable.
  fs.symlinkSync(outside, path.join(sandbox, decompOrdered));
  setAllowedDirectories([sandbox]);
  const sandboxReal = fs.realpathSync(sandbox);

  // Key attempt: byte-absent spelling of the escaping entry.
  {
    const requested = path.join(decompReordered, "secret.txt");
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
      if (!resolved.startsWith(sandboxReal + path.sep) || text.includes("SYNTHETIC-SECRET")) {
        escaped = true;
        console.log(marker);
        console.log(JSON.stringify({ requested, outcome }));
      } else {
        failInvalid(`escape attempt resolved inside but not via the expected rejection: ${resolved}`);
      }
    } catch (err) {
      const msg = String(err.message).split("\n")[0];
      if (!msg.includes("symlink target outside allowed directories")) {
        failInvalid(`expected the per-step symlink containment rejection, got: ${msg}`);
      }
      outcome = `rejected via NFC-equivalent step: ${msg}`;
    }
    console.log(JSON.stringify({ requested, outcome }));
  }

  // Documentation attempts: equivalent-tail requests stay inside the root.
  const tailAttempts = [
    decompReordered + "/../outside/secret.txt",
    composed + "/../../outside/secret.txt",
  ];
  for (const requested of tailAttempts) {
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
      if (!resolved.startsWith(sandboxReal + path.sep) || text.includes("SYNTHETIC-SECRET")) {
        escaped = true;
        console.log(marker);
      }
    } catch (err) {
      outcome = `rejected: ${String(err.message).split("\n")[0]}`;
    }
    console.log(JSON.stringify({ requested, outcome }));
  }
}

if (!escaped) {
  console.log("unicode: NFC fallback stayed inside the root; ambiguity guarded; escape oracle had a readable outside secret; confinement held");
}
