import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, statSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const artifactsRoot = path.join(repositoryRoot, "artifacts", "performance");
const generator = path.join(repositoryRoot, "tests/performance/bin/prepare-pki-runtime.mjs");

function mode(pathname) {
  return statSync(pathname).mode & 0o777;
}

test("test PKI generator keeps private material in an owner-only ignored runtime directory", () => {
  mkdirSync(artifactsRoot, { recursive: true });
  const output = mkdtempSync(path.join(artifactsRoot, "pki-contract-"));

  try {
    const generated = spawnSync(process.execPath, [generator, "--output", output], {
      encoding: "utf8",
    });
    assert.equal(generated.status, 0, generated.stderr);
    assert.match(generated.stdout, /"event":"pki.ready"/);
    assert.doesNotMatch(generated.stdout, /PRIVATE KEY/);
    assert.equal(mode(output), 0o700);
    assert.equal(mode(path.join(output, "server")), 0o700);
    assert.equal(mode(path.join(output, "server", "privkey.pem")), 0o600);
    assert.equal(mode(path.join(output, "edge-data", "certs", "edge-test-cert", "privkey.pem")), 0o600);
    assert.equal(mode(path.join(output, "root-cert.pem")), 0o644);
    assert.equal(mode(path.join(output, "server", "fullchain.pem")), 0o644);
    assert.equal(mode(path.join(output, "edge-data", "certs", "edge-test-cert", "metadata.toml")), 0o644);
    execFileSync("openssl", [
      "verify",
      "-CAfile",
      path.join(output, "root-cert.pem"),
      path.join(output, "server", "fullchain.pem"),
    ]);

    const cleaned = spawnSync(process.execPath, [generator, "--clean", "--output", output], {
      encoding: "utf8",
    });
    assert.equal(cleaned.status, 0, cleaned.stderr);
    assert.match(cleaned.stdout, /"event":"pki.cleaned"/);
    assert.throws(() => statSync(output));
  } finally {
    rmSync(output, { recursive: true, force: true });
  }
});
