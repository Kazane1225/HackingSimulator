import { createHash, createHmac, randomBytes } from "node:crypto";
import type { AttackResult, LabInput, Level, RealLab } from "./runner.js";

/**
 * Real integrity target. Lv2 hashes with SHA-256 and Lv3/Lv4 sign with
 * HMAC-SHA256 (`node:crypto`). The Lv4 MAC covers only name and version.
 * Lv5 uses a process-local key that is never written into a response.
 */

const FLAG = "FLAG{uns1gn3d_upd4te}";
const KEY = "build";
const USER = '{"name":"app","version":"1","role":"user"}';
const ADMIN = '{"name":"app","version":"1","role":"admin"}';
const PARTIAL = "name=app\nversion=1";
const SERVER_KEY = randomBytes(32);

interface Manifest {
  name: string;
  version: string;
  role: string;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function hmac(value: string, key: string | Buffer): string {
  return createHmac("sha256", key).update(value, "utf8").digest("hex");
}

function parseManifest(raw: string): Manifest | null {
  try {
    const value = JSON.parse(raw) as unknown;
    if (!value || typeof value !== "object") return null;
    const rec = value as Record<string, unknown>;
    if (typeof rec.name !== "string" || typeof rec.version !== "string" || typeof rec.role !== "string") return null;
    return { name: rec.name, version: rec.version, role: rec.role };
  } catch {
    return null;
  }
}

function partial(manifest: Manifest): string {
  return `name=${manifest.name}\nversion=${manifest.version}`;
}

function full(manifest: Manifest): string {
  return `${partial(manifest)}\nrole=${manifest.role}`;
}

function publishedSig(level: Level): string | null {
  if (level === 1) return null;
  if (level === 2) return sha256(USER);
  if (level === 3) return hmac(USER, KEY);
  if (level === 4) return hmac(PARTIAL, KEY);
  return hmac(full({ name: "app", version: "1", role: "user" }), SERVER_KEY);
}

export const integrityExploits: Record<1 | 2 | 3 | 4, LabInput> = {
  1: { manifest: ADMIN, signature: "" },
  2: { manifest: ADMIN, signature: sha256(ADMIN) },
  3: { manifest: ADMIN, signature: hmac(ADMIN, KEY) },
  4: { manifest: ADMIN, signature: hmac(PARTIAL, KEY) },
};

function run(level: Level, input: LabInput): AttackResult {
  const raw = input.manifest ?? "";
  const signature = (input.signature ?? "").trim();
  const manifest = parseManifest(raw);
  const published = publishedSig(level);
  const lines = published ? [`published-sig=${published}`] : ["署名は検査していません。"];

  if (!manifest) return { solved: false, output: ["マニフェストを読めません。", ...lines] };

  let signed = false;
  if (level === 1) signed = true;
  else if (level === 2) signed = signature === sha256(raw);
  else if (level === 3) signed = signature === hmac(raw, KEY);
  else if (level === 4) signed = signature === hmac(partial(manifest), KEY);
  else signed = signature === hmac(full(manifest), SERVER_KEY);

  if (!signed) return { solved: false, output: ["署名が一致しません。", ...lines] };

  const solved = manifest.role === "admin";
  return {
    solved,
    benign: !solved,
    output: [`name=${manifest.name}`, `version=${manifest.version}`, `role=${manifest.role}`, ...(solved ? [FLAG] : lines)],
  };
}

export const integrityRealLab: RealLab = { id: "integrity", run };
