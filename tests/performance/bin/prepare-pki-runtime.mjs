import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const artifactsRoot = path.join(repositoryRoot, "artifacts", "performance");
const markerName = ".sponzey-test-pki-runtime";

function parseArguments(arguments_) {
  let output;
  let clean = false;

  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--clean") {
      clean = true;
    } else if (argument === "--output") {
      output = arguments_[index + 1];
      index += 1;
    } else {
      throw new Error("unsupported argument");
    }
  }

  if (!output) {
    throw new Error("--output is required");
  }
  return { clean, output: runtimePath(output) };
}

function runtimePath(output) {
  const resolved = path.resolve(output);
  const relative = path.relative(artifactsRoot, resolved);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("output must be under artifacts/performance");
  }
  return resolved;
}

function runOpenSsl(arguments_) {
  execFileSync("openssl", arguments_, { stdio: "ignore" });
}

function ownerOnlyDirectory(directory) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
}

function ownerOnlyFile(filename) {
  chmodSync(filename, 0o600);
}

function publicFile(filename) {
  chmodSync(filename, 0o644);
}

function clean(output) {
  const marker = path.join(output, markerName);
  if (!existsSync(marker) || !lstatSync(marker).isFile()) {
    throw new Error("refusing to clean an unmarked directory");
  }
  rmSync(output, { recursive: true, force: false });
  process.stdout.write('{"event":"pki.cleaned"}\n');
}

function prepare(output) {
  if (existsSync(output)) {
    const metadata = lstatSync(output);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || readdirSync(output).length !== 0) {
      throw new Error("output directory must be an empty real directory");
    }
  } else {
    ownerOnlyDirectory(path.dirname(output));
    ownerOnlyDirectory(output);
  }
  ownerOnlyDirectory(output);
  writeFileSync(path.join(output, markerName), "test-pki-runtime-v1\n", { mode: 0o600 });
  writeFileSync(
    path.join(output, "admin-credential.secret"),
    randomBytes(32).toString("base64url"),
    { mode: 0o600 },
  );

  const work = path.join(output, "work");
  const server = path.join(output, "server");
  const rootKey = path.join(work, "root-key.pem");
  const rootCertificate = path.join(output, "root-cert.pem");
  const leafKey = path.join(work, "leaf-key.pem");
  const leafRequest = path.join(work, "leaf-request.pem");
  const leafCertificate = path.join(work, "leaf-cert.pem");
  const extensionFile = path.join(work, "leaf-extensions.cnf");
  const edgeCertificateDirectory = path.join(output, "edge-data", "certs", "edge-test-cert");

  ownerOnlyDirectory(work);
  ownerOnlyDirectory(server);
  ownerOnlyDirectory(edgeCertificateDirectory);
  try {
    runOpenSsl([
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
      "-subj", "/CN=Sponzey Edge Test Root", "-keyout", rootKey, "-out", rootCertificate,
    ]);
    runOpenSsl([
      "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
      "-subj", "/CN=edge.test", "-keyout", leafKey, "-out", leafRequest,
      "-addext", "subjectAltName=DNS:edge.test",
    ]);
    writeFileSync(
      extensionFile,
      "[v3_leaf]\nsubjectAltName=DNS:edge.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
      { mode: 0o600 },
    );
    runOpenSsl([
      "x509", "-req", "-sha256", "-days", "2", "-in", leafRequest,
      "-CA", rootCertificate, "-CAkey", rootKey, "-CAcreateserial", "-out", leafCertificate,
      "-extfile", extensionFile, "-extensions", "v3_leaf",
    ]);
    renameSync(leafKey, path.join(server, "privkey.pem"));
    renameSync(leafCertificate, path.join(server, "fullchain.pem"));
    copyFileSync(rootCertificate, path.join(output, "client-ca.pem"));
    copyFileSync(path.join(server, "privkey.pem"), path.join(edgeCertificateDirectory, "privkey.pem"));
    copyFileSync(path.join(server, "fullchain.pem"), path.join(edgeCertificateDirectory, "fullchain.pem"));
    writeFileSync(
      path.join(edgeCertificateDirectory, "metadata.toml"),
      "certificate_ref = \"edge-test-cert\"\ndomains = [\"edge.test\"]\nnot_after_epoch_seconds = 4102444800\nsource = \"test-private-pki\"\n",
      { mode: 0o644 },
    );
    ownerOnlyFile(path.join(server, "privkey.pem"));
    ownerOnlyFile(path.join(edgeCertificateDirectory, "privkey.pem"));
    publicFile(rootCertificate);
    publicFile(path.join(server, "fullchain.pem"));
    publicFile(path.join(edgeCertificateDirectory, "fullchain.pem"));
    publicFile(path.join(edgeCertificateDirectory, "metadata.toml"));
    publicFile(path.join(output, "client-ca.pem"));
  } finally {
    rmSync(work, { recursive: true, force: true });
  }

  process.stdout.write('{"event":"pki.ready","server_name":"edge.test"}\n');
}

try {
  const options = parseArguments(process.argv.slice(2));
  if (options.clean) {
    clean(options.output);
  } else {
    prepare(options.output);
  }
} catch {
  process.stderr.write("test PKI runtime preparation failed\n");
  process.exitCode = 1;
}
