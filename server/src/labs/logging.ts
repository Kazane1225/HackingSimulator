import type { AttackResult, LabInput, Level, RealLab } from "./runner.js";

/**
 * Real logging target. The account is always guest. Lv1–3 forge a log line
 * the monitor reads as an admin export. Lv4 performs `op` while the log
 * records `action`. Nothing is written to disk (the container root is read-only).
 */

const FLAG = "FLAG{l0g_1nj3ct}";
const FORGED = "user=admin action=export";

function stripNl(value: string): string {
  return value.replace(/\n/g, "");
}

function stripCrLf(value: string): string {
  return value.replace(/[\r\n]/g, "");
}

/** A one-line field cannot hold a raw CR. `\n` and `\r` in the text become the control characters. */
function controls(value: string): string {
  return value.replace(/\\r/g, "\r").replace(/\\n/g, "\n");
}

function forgedLines(log: string, splitCr: boolean): boolean {
  const lines = splitCr ? log.split(/\r|\n/) : log.split("\n");
  return lines.some((line) => line === FORGED);
}

function result(solved: boolean, log: string): AttackResult {
  return {
    solved,
    benign: !solved && log.includes("action=view"),
    output: ["log:", log, ...(solved ? [FLAG] : [])],
  };
}

function run(level: Level, input: LabInput): AttackResult {
  const note = controls(input.user ?? "");
  const action = controls(input.action ?? "view");

  if (level === 1) {
    const log = `user=guest action=${action} note=${note}`;
    return result(forgedLines(log, false), log);
  }

  if (level === 2) {
    const log = `user=guest action=${stripNl(action)} note=${stripNl(note)}`;
    return result(forgedLines(log, true), log);
  }

  if (level === 3) {
    const log = `{"user":"guest","action":"${stripCrLf(action)}","note":"${stripCrLf(note)}"}`;
    let solved = false;
    try {
      const parsed = JSON.parse(log) as { user?: string; action?: string };
      solved = parsed.user === "admin" && parsed.action === "export";
    } catch {
      solved = false;
    }
    return result(solved, log);
  }

  if (level === 4) {
    const recorded = stripCrLf(action);
    const performed = stripCrLf(input.op ?? "") || recorded;
    const log = JSON.stringify({ user: "guest", action: recorded, note: stripCrLf(note) });
    return result(performed === "export" && recorded !== "export", log);
  }

  const recorded = /^[a-z]{1,16}$/.test(action) ? action : "view";
  const log = JSON.stringify({ user: "guest", action: recorded, note: stripCrLf(note), result: recorded === "export" ? "denied" : "ok" });
  return { solved: false, output: ["log:", log] };
}

export const loggingRealLab: RealLab = { id: "logging", run };
