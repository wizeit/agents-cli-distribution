#!/usr/bin/env node
import { constants, createHash, createPublicKey, verify } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { basename, join, resolve } from "node:path";

const repository = "wizeit/agents-cli-distribution";
const expectedArtifacts = new Map([
  ["agents-linux-x64", { platform: "linux", arch: "x64" }],
  ["agents-linux-arm64", { platform: "linux", arch: "arm64" }],
  ["agents-darwin-arm64", { platform: "darwin", arch: "arm64" }],
  ["agents-windows-x64.exe", { platform: "windows", arch: "x64" }],
]);
const maximumArtifactBytes = 256 * 1024 * 1024;
const directory = resolve(process.argv[2] || ".");
const versionOptionIndex = process.argv.indexOf("--version");
const expectedVersion = versionOptionIndex === -1 ? null : process.argv[versionOptionIndex + 1];
const trust = JSON.parse(readFileSync(new URL("../release-trust.json", import.meta.url), "utf8"));

function fail(message) {
  console.error(message);
  process.exit(1);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value, keys) {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

const publicKey = createPublicKey(trust.publicKeyPem);
const observedKeyId = createHash("sha256")
  .update(publicKey.export({ type: "spki", format: "der" }))
  .digest("hex")
  .slice(0, 16);
const jwk = publicKey.export({ format: "jwk" });
if (
  !hasExactKeys(trust, [
    "schemaVersion",
    "signatureAlgorithm",
    "keyId",
    "publicKeyPem",
    "rsaModulusBase64Url",
    "rsaExponentBase64Url",
  ]) ||
  trust.schemaVersion !== 2 ||
  trust.signatureAlgorithm !== "rsa-sha256" ||
  trust.keyId !== observedKeyId ||
  jwk.kty !== "RSA" ||
  jwk.n !== trust.rsaModulusBase64Url ||
  jwk.e !== trust.rsaExponentBase64Url
) {
  fail("Distribution trust anchor is invalid");
}

const manifestPath = join(directory, "manifest.json");
const signaturePath = join(directory, "manifest.sig");
const manifestBytes = readFileSync(manifestPath);
const signatureText = readFileSync(signaturePath, "utf8").trim();
if (
  manifestBytes.length > 1024 * 1024 ||
  signatureText.length > 8192 ||
  !/^[A-Za-z0-9+/]+={0,2}$/.test(signatureText)
) {
  fail("Release metadata is malformed");
}
const signature = Buffer.from(signatureText, "base64");
if (
  !verify(
    "sha256",
    manifestBytes,
    { key: trust.publicKeyPem, padding: constants.RSA_PKCS1_PADDING },
    signature,
  )
) {
  fail("Release manifest signature is invalid");
}

let manifest;
try {
  manifest = JSON.parse(manifestBytes.toString("utf8"));
} catch {
  fail("Release manifest is not valid JSON");
}
if (
  !isPlainObject(manifest) ||
  !hasExactKeys(manifest, [
    "schemaVersion",
    "channel",
    "signatureAlgorithm",
    "version",
    "tag",
    "sourceRevision",
    "publishedAt",
    "keyId",
    "artifacts",
  ]) ||
  manifest.schemaVersion !== trust.schemaVersion ||
  manifest.channel !== "stable" ||
  manifest.signatureAlgorithm !== trust.signatureAlgorithm ||
  manifest.keyId !== trust.keyId ||
  typeof manifest.version !== "string" ||
  !/^\d+\.\d+\.\d+$/.test(manifest.version) ||
  manifest.tag !== `v${manifest.version}` ||
  typeof manifest.sourceRevision !== "string" ||
  !/^[0-9a-f]{40}$/.test(manifest.sourceRevision) ||
  typeof manifest.publishedAt !== "string" ||
  !Number.isFinite(Date.parse(manifest.publishedAt)) ||
  !Array.isArray(manifest.artifacts) ||
  manifest.artifacts.length !== expectedArtifacts.size ||
  (expectedVersion !== null && manifest.version !== expectedVersion)
) {
  fail("Release manifest has an invalid shape");
}

const filenames = new Set();
for (const artifact of manifest.artifacts) {
  if (
    !isPlainObject(artifact) ||
    !hasExactKeys(artifact, ["filename", "platform", "arch", "url", "sha256", "size"]) ||
    typeof artifact.filename !== "string" ||
    filenames.has(artifact.filename) ||
    typeof artifact.sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(artifact.sha256) ||
    !Number.isSafeInteger(artifact.size) ||
    artifact.size <= 0 ||
    artifact.size > maximumArtifactBytes
  ) {
    fail("Release artifact metadata is invalid");
  }
  const descriptor = expectedArtifacts.get(artifact.filename);
  if (
    !descriptor ||
    artifact.platform !== descriptor.platform ||
    artifact.arch !== descriptor.arch ||
    artifact.url !==
      `https://github.com/${repository}/releases/download/v${manifest.version}/${artifact.filename}`
  ) {
    fail("Release artifact identity is invalid");
  }
  const artifactPath = join(directory, artifact.filename);
  const stat = lstatSync(artifactPath);
  const bytes = readFileSync(artifactPath);
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (!stat.isFile() || bytes.length !== artifact.size || digest !== artifact.sha256) {
    fail(`Release artifact verification failed: ${artifact.filename}`);
  }
  const checksum = readFileSync(join(directory, `${artifact.filename}.sha256`), "utf8");
  if (checksum !== `${artifact.sha256}  ${basename(artifact.filename)}\n`) {
    fail(`Release checksum file is invalid: ${artifact.filename}`);
  }
  filenames.add(artifact.filename);
}

if (readFileSync(join(directory, "version.txt"), "utf8") !== `${manifest.version}\n`) {
  fail("Release version file is invalid");
}
const shellInstaller = readFileSync(join(directory, "install.sh"), "utf8");
const powershellInstaller = readFileSync(join(directory, "install.ps1"), "utf8");
for (const value of [trust.publicKeyPem.trim(), trust.keyId, trust.signatureAlgorithm]) {
  if (!shellInstaller.includes(value)) fail("Shell installer trust anchor is invalid");
}
for (const value of [
  trust.rsaModulusBase64Url,
  trust.rsaExponentBase64Url,
  trust.keyId,
  trust.signatureAlgorithm,
]) {
  if (!powershellInstaller.includes(value)) fail("PowerShell installer trust anchor is invalid");
}

const expectedFiles = new Set([
  "install.ps1",
  "install.sh",
  "manifest.json",
  "manifest.sig",
  "version.txt",
  ...[...expectedArtifacts.keys()].flatMap((filename) => [filename, `${filename}.sha256`]),
]);
const observedFiles = readdirSync(directory);
if (
  observedFiles.length !== expectedFiles.size ||
  observedFiles.some((filename) => !expectedFiles.has(filename))
) {
  fail("Release bundle contains unexpected or missing files");
}

process.stdout.write(`${manifest.version}\n`);
