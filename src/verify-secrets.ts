// Self-check for the secretlint-based scanner. Run via `npm run check`.
//
// Writes a known-secret fixture and a clean fixture to a temp dir, runs the
// in-process secret scan on both, and asserts findings are reported for the
// dirty file and none for the clean one.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanFilesWithSecretScan } from "./trufflehog.ts";

// This 40-char base64 value reliably trips the AWS secret-access-key rule with
// the preset's default options (confirmed against the installed packages). Note
// a bare `AKIA...` access key id is NOT detected, so we use the full
// `AWS_SECRET_ACCESS_KEY=` env line and a random-looking (non-documented)
// value, since secretlint skips AWS's official example keys.
const AWS_SECRET_KEY = "s7n0XBe7bzlOKMBRRz3g3Je3D8QRj81hOism2u2x";
// Rotated test fixtures (generated then deleted) in the real key charset, for the
// providers the preset doesn't cover. Kept out of dist via tsconfig.build.json.
const OPENROUTER_KEY =
  "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";
const VENICE_INFERENCE_KEY =
  "VENICE_INFERENCE_KEY_9yO-hBS9yTPsPxpKZI5wodLA7knSMF4Y9_hi-evSFM";
const VENICE_ADMIN_KEY =
  "VENICE_ADMIN_KEY_BDMpTLm4RfgwrmseAsO91wm0DC00O8zHUIr-ziKHlEs";
const DIRTY_CONTENT = `# credentials
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_KEY}
OPENROUTER_API_KEY=${OPENROUTER_KEY}
VENICE_API_KEY=${VENICE_INFERENCE_KEY}
VENICE_ADMIN_KEY=${VENICE_ADMIN_KEY}
`;
const CLEAN_CONTENT =
  'export const email = "hello@example.com";\nconst t = (a: number, b: number) => a + b;\n';

async function scanOnce(content: string) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-share-verify-"));
  const redactedPath = path.join(dir, "fixture.txt");
  fs.writeFileSync(redactedPath, content);
  const report = (
    await scanFilesWithSecretScan([
      { file: "fixture.txt", redactedPath, redactedHash: "verify-fixture" },
    ])
  ).get("fixture.txt");
  fs.rmSync(dir, { recursive: true, force: true });
  return report;
}

async function main() {
  const dirty = await scanOnce(DIRTY_CONTENT);
  assert.ok(dirty, "expected a report for the dirty fixture");
  assert.ok(
    dirty.summary.findings > 0,
    `expected findings for the dirty fixture, got summary=${JSON.stringify(dirty.summary)}`,
  );
  const dirtyDetectors = dirty.findings.map((f) => f.detector);
  assert.ok(
    dirtyDetectors.some((d) => d.toLowerCase().includes("aws")),
    `expected an AWS detector in findings, got ${dirtyDetectors.join(", ")}`,
  );
  assert.ok(
    dirtyDetectors.some((d) => d.toLowerCase().includes("openrouter")),
    `expected an OpenRouter detector in findings, got ${dirtyDetectors.join(", ")}`,
  );
  assert.ok(
    dirtyDetectors.some((d) => d.toLowerCase().includes("venice")),
    `expected a Venice detector in findings, got ${dirtyDetectors.join(", ")}`,
  );

  const clean = await scanOnce(CLEAN_CONTENT);
  assert.ok(clean, "expected a report for the clean fixture");
  assert.equal(
    clean.summary.findings,
    0,
    `expected zero findings for the clean fixture, got ${JSON.stringify(clean.summary)}`,
  );

  console.log(
    `verify-secrets: ok (dirty found ${dirty.summary.findings} finding(s), clean found 0)`,
  );
}

main().catch((err) => {
  console.error("verify-secrets failed:", err);
  process.exit(1);
});
