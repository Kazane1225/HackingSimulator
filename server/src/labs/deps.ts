import { readFile } from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import type { AttackResult, LabInput, Level, RealLab } from "./runner.js";

/**
 * Real outdated-component target. ThumbX's path check is the vulnerable
 * logic; the secret itself is one fixture file. The learner's `file` string
 * is never passed to the filesystem.
 */

const LAB_FILES = process.env.LAB_FILES_DIR ?? fileURLToPath(new URL("../../lab-files/", import.meta.url));
const SECRET_FILE = path.join(path.resolve(LAB_FILES, "deps"), "secret");
const SECRET = "etc/thumbx/secret";

function decodePct(value: string): string {
  return value.replace(/%([0-9a-fA-F]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
}

function hits(file: string): boolean {
  const norm = file.replace(/\\/g, "/");
  return norm === `/${SECRET}` || norm.endsWith(`/${SECRET}`) || norm.endsWith(SECRET);
}

function blocked(file: string): AttackResult {
  const benign = file === "logo.png";
  return {
    solved: false,
    benign,
    output: benign ? [`ThumbX file=${file}`, "PNG logo"] : [`ThumbX file=${file}`, "rejected"],
  };
}

async function leak(file: string): Promise<AttackResult> {
  const secret = (await readFile(SECRET_FILE, "utf8")).trim();
  return { solved: true, output: [`ThumbX file=${file}`, secret] };
}

async function run(level: Level, input: LabInput): Promise<AttackResult> {
  const file = input.file ?? "logo.png";
  const engine = input.engine ?? "current";

  if (level === 5) {
    if (engine === "legacy") return blocked(file);
    if (!/^[A-Za-z0-9._-]+$/.test(file)) return blocked(file);
    return blocked(file);
  }

  if (level === 4) {
    if (engine === "legacy") return hits(file) ? leak(file) : blocked(file);
    const decoded = decodePct(decodePct(file));
    if (decoded.includes("..") || decoded.startsWith("/")) return blocked(file);
    return blocked(file === "logo.png" ? file : decoded);
  }

  if (level === 1) return hits(file) ? leak(file) : blocked(file);

  if (level === 2) {
    if (file.includes("..")) return blocked(file);
    const decoded = decodePct(file);
    return hits(decoded) ? leak(file) : blocked(file);
  }

  const once = decodePct(file);
  if (once.includes("..")) return blocked(file);
  const twice = decodePct(once);
  return hits(twice) ? leak(file) : blocked(file);
}

export const depsRealLab: RealLab = { id: "deps", run };
