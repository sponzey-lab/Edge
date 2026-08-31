#!/usr/bin/env node
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { auditArtifact } from "./audit.mjs";
import { evaluateC8Gate } from "./summary.mjs";

function read(directory, name) {
  return JSON.parse(readFileSync(path.join(directory, name), "utf8"));
}

/** Audits two published baseline artifacts before applying the C8 relative metric policy. */
export function compareC8Artifacts(referenceDirectory, candidateDirectory) {
  const referenceAudit = auditArtifact(referenceDirectory);
  const candidateAudit = auditArtifact(candidateDirectory);
  if (referenceAudit.profile !== "baseline" || candidateAudit.profile !== "baseline") {
    throw new Error("C8 comparison requires baseline artifacts");
  }
  const referenceMetadata = read(referenceDirectory, "metadata.json");
  const candidateMetadata = read(candidateDirectory, "metadata.json");
  if (!referenceMetadata.host_identity || !candidateMetadata.host_identity
    || JSON.stringify(referenceMetadata.host_identity) !== JSON.stringify(candidateMetadata.host_identity)) {
    throw new Error("C8 comparison requires matching host identity");
  }
  const result = evaluateC8Gate(
    read(referenceDirectory, "summary.json").baseline_comparison,
    read(candidateDirectory, "summary.json").baseline_comparison,
  );
  return { reference_commit: referenceAudit.source_commit, candidate_commit: candidateAudit.source_commit, ...result };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = compareC8Artifacts(process.argv[2] ?? "", process.argv[3] ?? "");
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (!result.passed) process.exitCode = 2;
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
  }
}
