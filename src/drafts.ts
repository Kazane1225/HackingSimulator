import type { LabInput, Level } from "./labs/types";

const DRAFT_PREFIX = "hacklab.draft.";
const HINTS_KEY = "hacklab.hints.v1";

export interface LabDraft {
  inputs: LabInput;
  revealed: string[];
  extraParams: string[];
}

function draftKey(labId: string, level: Level): string {
  return `${DRAFT_PREFIX}${labId}.${level}`;
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function readDraft(labId: string, level: Level): LabDraft | null {
  try {
    const raw = sessionStorage.getItem(draftKey(labId, level));
    if (!raw) return null;
    const value = JSON.parse(raw) as Partial<LabDraft>;
    if (!value.inputs || typeof value.inputs !== "object" || Array.isArray(value.inputs)) return null;
    return {
      inputs: value.inputs,
      revealed: stringList(value.revealed),
      extraParams: stringList(value.extraParams),
    };
  } catch {
    return null;
  }
}

export function removeDraft(labId: string, level: Level): void {
  try {
    sessionStorage.removeItem(draftKey(labId, level));
  } catch {
    // ignore
  }
}

export function writeDraft(labId: string, level: Level, draft: LabDraft): void {
  try {
    sessionStorage.setItem(draftKey(labId, level), JSON.stringify(draft));
  } catch {
    // Storage may be unavailable in private mode.
  }
}

export function clearDrafts(): void {
  try {
    for (let i = sessionStorage.length - 1; i >= 0; i--) {
      const key = sessionStorage.key(i);
      if (key?.startsWith(DRAFT_PREFIX)) sessionStorage.removeItem(key);
    }
  } catch {
    // ignore
  }
}

type HintMap = Record<string, Partial<Record<Level, number>>>;

function readAllHints(): HintMap {
  try {
    const raw = localStorage.getItem(HINTS_KEY);
    if (!raw) return {};
    const value = JSON.parse(raw) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) return {};
    return value as HintMap;
  } catch {
    return {};
  }
}

export function readHints(labId: string): Partial<Record<Level, number>> {
  const row = readAllHints()[labId];
  if (!row || typeof row !== "object") return {};
  const out: Partial<Record<Level, number>> = {};
  for (const [key, value] of Object.entries(row)) {
    const level = Number(key);
    if (level >= 1 && level <= 5 && typeof value === "number" && value >= 0) out[level as Level] = value;
  }
  return out;
}

export function writeHints(labId: string, shown: Partial<Record<Level, number>>): void {
  try {
    const all = readAllHints();
    all[labId] = shown;
    localStorage.setItem(HINTS_KEY, JSON.stringify(all));
  } catch {
    // ignore
  }
}

export function clearHints(): void {
  try {
    localStorage.removeItem(HINTS_KEY);
  } catch {
    // ignore
  }
}
