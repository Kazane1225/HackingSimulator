import { useCallback, useEffect, useState } from "react";
import type { Level } from "./labs/types";

const STORAGE_KEY = "hacklab.progress.v1";

/** Map of lab id -> list of solved levels. */
export type Progress = Record<string, Level[]>;

const VALID_LEVELS: readonly number[] = [1, 2, 3, 4, 5];

/** Keep only well-formed entries so corrupted or hand-edited storage cannot crash the UI. */
function sanitize(value: unknown): Progress {
  const out: Progress = {};
  if (typeof value !== "object" || value === null || Array.isArray(value)) return out;
  for (const [labId, levels] of Object.entries(value)) {
    if (!Array.isArray(levels)) continue;
    const valid = [...new Set(levels.filter((lv) => VALID_LEVELS.includes(lv)))].sort(
      (a, b) => a - b,
    ) as Level[];
    if (valid.length > 0) out[labId] = valid;
  }
  return out;
}

function load(): Progress {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? sanitize(JSON.parse(raw)) : {};
  } catch {
    return {};
  }
}

export function useProgress() {
  const [progress, setProgress] = useState<Progress>(load);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(progress));
    } catch {
      // Storage may be unavailable (private mode); progress stays in memory.
    }
  }, [progress]);

  const markSolved = useCallback((labId: string, level: Level) => {
    setProgress((prev) => {
      const solved = prev[labId] ?? [];
      if (solved.includes(level)) return prev;
      return { ...prev, [labId]: [...solved, level].sort((a, b) => a - b) as Level[] };
    });
  }, []);

  const isSolved = useCallback(
    (labId: string, level: Level) => (progress[labId] ?? []).includes(level),
    [progress],
  );

  const reset = useCallback(() => setProgress({}), []);

  return { progress, markSolved, isSolved, reset };
}
