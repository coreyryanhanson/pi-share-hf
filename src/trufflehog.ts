import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { lintSource } from "@secretlint/core";
import { creator as presetRecommend } from "@secretlint/secretlint-rule-preset-recommend";
import type { SecretLintRuleCreator } from "@secretlint/types";
import type {
  SecretScanFinding,
  SecretScanReport,
  SecretScanSummary,
} from "./types.ts";
import { SECRET_SCAN_REPORT_SUFFIX } from "./types.ts";
import { isRecord, workspacePath } from "./workspace.ts";

// Custom rules for providers the preset doesn't cover (OpenRouter, Venice AI).
// `patternRule` builds a minimal scanner rule from a regex; the whole match is
// reported as the secret (data + range), so extractSecret/maskSecret handle it
// like any preset rule.
function patternRule(
  id: string,
  label: string,
  pattern: RegExp,
): SecretLintRuleCreator {
  const messages = {
    KEY: { en: (props: { key: string }) => `${label}: ${props.key}` },
  };
  return {
    messages,
    meta: {
      id,
      type: "scanner",
      recommended: true,
      supportedContentTypes: ["text"],
    },
    create(context) {
      const t = context.createTranslator(messages);
      return {
        file(source) {
          for (const match of source.content.matchAll(pattern)) {
            const index = match.index ?? 0;
            const value = match[0];
            context.report({
              message: t("KEY", { key: value }),
              range: [index, index + value.length],
            });
          }
        },
      };
    },
  };
}

const openRouterRule = patternRule(
  "@secretlint/secretlint-rule-openrouter",
  "OpenRouter API key",
  /\bsk-or-v1-[a-fA-F0-9]{64}(?![a-fA-F0-9])/g,
);

const veniceRule = patternRule(
  "@secretlint/secretlint-rule-venice",
  "Venice AI API key",
  /\bVENICE_(?:INFERENCE|ADMIN)_KEY_[A-Za-z0-9_-]{30,}(?![A-Za-z0-9_-])/g,
);

const secretlintConfig = {
  rules: [
    {
      id: "@secretlint/secretlint-rule-preset-recommend",
      rule: presetRecommend,
    },
    { id: "@secretlint/secretlint-rule-openrouter", rule: openRouterRule },
    { id: "@secretlint/secretlint-rule-venice", rule: veniceRule },
  ],
};

export function secretScanReportPath(workspace: string, file: string): string {
  return workspacePath(
    workspace,
    "reports",
    `${file}${SECRET_SCAN_REPORT_SUFFIX}`,
  );
}

export function loadSecretScanReport(
  filePath: string,
): SecretScanReport | undefined {
  if (!fs.existsSync(filePath)) return undefined;
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf-8")) as unknown;
    if (!isRecord(parsed)) return undefined;
    if (typeof parsed.file !== "string") return undefined;
    if (typeof parsed.redacted_hash !== "string") return undefined;
    if (!isRecord(parsed.summary)) return undefined;
    if (!Array.isArray(parsed.findings)) return undefined;
    return parsed as unknown as SecretScanReport;
  } catch {
    return undefined;
  }
}

export async function scanFilesWithSecretScan(
  files: Array<{ file: string; redactedPath: string; redactedHash: string }>,
): Promise<Map<string, SecretScanReport>> {
  const reports = new Map<string, SecretScanReport>();
  for (const entry of files) {
    const content = fs.readFileSync(entry.redactedPath, "utf-8");
    const result = await lintSource({
      source: {
        filePath: entry.redactedPath,
        content,
        ext: path.extname(entry.redactedPath),
        contentType: "text",
      },
      options: { config: secretlintConfig },
    });

    const deduped = new Map<string, SecretScanFinding>();
    for (const message of result.messages) {
      const secret = extractSecret(message.data, message.range, content);
      const finding: SecretScanFinding = {
        detector: message.ruleId,
        status: "unverified",
        line: message.loc.start.line,
        raw_sha256: digest(secret),
        masked: maskSecret(secret),
        verification_from_cache: false,
      };
      deduped.set(`${finding.detector}\u0000${finding.raw_sha256}`, finding);
    }

    const findings = [...deduped.values()].sort((a, b) => {
      const lineA = a.line ?? Number.MAX_SAFE_INTEGER;
      const lineB = b.line ?? Number.MAX_SAFE_INTEGER;
      if (lineA !== lineB) return lineA - lineB;
      return a.detector.localeCompare(b.detector);
    });

    reports.set(entry.file, {
      file: entry.file,
      redacted_hash: entry.redactedHash,
      findings,
      summary: summarizeFindings(findings),
    });
  }
  return reports;
}

export function saveSecretScanReport(
  filePath: string,
  report: SecretScanReport,
): void {
  fs.writeFileSync(filePath, `${JSON.stringify(report, null, 2)}\n`);
}

export function blockingSecretReason(
  report: SecretScanReport,
):
  | { reason: string; evidence: string; missedSensitiveData: "yes" | "maybe" }
  | undefined {
  if (report.summary.findings === 0) return undefined;
  return {
    reason: "secret-findings",
    evidence: formatSummaryEvidence(report),
    missedSensitiveData:
      report.summary.verified > 0 || report.summary.unknown > 0
        ? "yes"
        : "maybe",
  };
}

export function formatSecretScanFinding(finding: SecretScanFinding): string {
  const line = finding.line === undefined ? "L?" : `L${finding.line}`;
  return `${line} ${finding.status} ${finding.detector} ${finding.masked}`;
}

// secretlint's `range` is inconsistent across rules (the AWS rule reports the
// captured value's length from the full-match start), so prefer the structured
// `data` payload, which carries the raw secret value for every preset rule.
function extractSecret(
  data: unknown,
  range: readonly [number, number],
  content: string,
): string {
  if (isRecord(data)) {
    for (const value of Object.values(data)) {
      if (typeof value === "string" && value.length > 0) return value;
    }
  }
  return content.slice(range[0], range[1]);
}

function digest(text: string): string {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function summarizeFindings(findings: SecretScanFinding[]): SecretScanSummary {
  const detectorCounts = new Map<string, number>();
  const summary: SecretScanSummary = {
    findings: findings.length,
    verified: 0,
    unverified: 0,
    unknown: 0,
    top_detectors: [],
  };

  for (const finding of findings) {
    summary[finding.status]++;
    detectorCounts.set(
      finding.detector,
      (detectorCounts.get(finding.detector) ?? 0) + 1,
    );
  }

  summary.top_detectors = [...detectorCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 8)
    .map(([detector]) => detector);

  return summary;
}

function formatSummaryEvidence(report: SecretScanReport): string {
  const summary = report.summary;
  const detectors =
    summary.top_detectors.length > 0
      ? summary.top_detectors.join(", ")
      : "none";
  const examples = report.findings
    .slice(0, 5)
    .map((finding) => `${finding.detector}:${finding.masked}`)
    .join(", ");
  return `verified=${summary.verified}, unknown=${summary.unknown}, unverified=${summary.unverified}, detectors=${detectors}${examples ? `, examples=${examples}` : ""}`;
}

function maskSecret(raw: string): string {
  if (raw.length <= 8) return "***";

  const prefixLength = raw.startsWith("npm_")
    ? Math.min(8, raw.length - 4)
    : Math.min(4, raw.length - 4);
  const suffixLength = Math.min(4, raw.length - prefixLength);

  return `${raw.slice(0, prefixLength)}***${raw.slice(raw.length - suffixLength)}`;
}
