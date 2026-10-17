import { readFile } from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import type { AttackResult, LabInput, Level, RealLab } from "./runner.js";

/**
 * Real misconfiguration target. Debug output, the actuator dump and the
 * leftover env file are real files under lab-files/misconf. The request path
 * only chooses which of those fixtures to open — it is never joined onto the
 * filesystem.
 */

const LAB_FILES = process.env.LAB_FILES_DIR ?? fileURLToPath(new URL("../../lab-files/", import.meta.url));
const ROOT = path.resolve(LAB_FILES, "misconf");

const FILES = {
  debug: path.join(ROOT, "debug.txt"),
  actuator: path.join(ROOT, "actuator.txt"),
  env: path.join(ROOT, "dotenv"),
} as const;

async function fixture(name: keyof typeof FILES): Promise<string[]> {
  const text = await readFile(FILES[name], "utf8");
  return text.split(/\r?\n/).filter((line) => line.length > 0);
}

function miss(requestPath: string): AttackResult {
  const home = requestPath === "/" || requestPath === "/health";
  return {
    solved: false,
    benign: home,
    output: home ? [`GET ${requestPath}`, "Welcome"] : [`GET ${requestPath}`, "404"],
  };
}

async function hit(requestPath: string, file: keyof typeof FILES): Promise<AttackResult> {
  return {
    solved: true,
    output: [`GET ${requestPath}`, ...(await fixture(file)), "設定情報が見えています。"],
  };
}

async function run(level: Level, input: LabInput): Promise<AttackResult> {
  const requestPath = input.path ?? "/";
  if (level === 5) return miss(requestPath);
  if (level === 1) return requestPath === "/debug" ? hit(requestPath, "debug") : miss(requestPath);
  if (level === 2) {
    if (requestPath === "/debug") return miss(requestPath);
    if (requestPath === "/debug/") return hit(requestPath, "debug");
    return miss(requestPath);
  }
  if (level === 3) {
    const trimmed = requestPath.replace(/\/+$/, "") || "/";
    if (trimmed === "/debug") return miss(requestPath);
    if (requestPath === "/actuator/env") return hit(requestPath, "actuator");
    return miss(requestPath);
  }
  if (requestPath === "/debug" || requestPath === "/debug/" || requestPath === "/actuator/env") return miss(requestPath);
  if (requestPath === "/.env") return hit(requestPath, "env");
  return miss(requestPath);
}

export const misconfRealLab: RealLab = { id: "misconf", run };
