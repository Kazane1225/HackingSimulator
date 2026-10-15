import { useCallback, useEffect, useState } from "react";
import type { Level } from "./labs/types";

const STORAGE_KEY = "hackme.progress.v1";

/** Map of lab id -> list of solved levels. */
export type Progress = Record<string, Level[]>;

function load(): Progress {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Progress) : {};
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
      return { ...prev, [labId]: [...solved, level].sort() as Level[] };
    });
  }, []);

  const isSolved = useCallback(
    (labId: string, level: Level) => (progress[labId] ?? []).includes(level),
    [progress],
  );

  const reset = useCallback(() => setProgress({}), []);

  return { progress, markSolved, isSolved, reset };
}
