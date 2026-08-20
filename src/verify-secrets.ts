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
const DIRTY_CONTENT = `# credentials
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_KEY}
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
  assert.ok(
    dirty.findings.some((f) => f.detector.toLowerCase().includes("aws")),
    `expected an AWS detector in findings, got ${dirty.findings.map((f) => f.detector).join(", ")}`,
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
