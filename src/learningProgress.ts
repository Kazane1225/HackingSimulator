import { useCallback, useEffect, useState } from "react";

export const LEARNING_STORAGE_KEY = "hacklab.learning.v1";

export interface LearningProgress {
  remediatedLabIds: string[];
  completedMissionStepIds: string[];
}

const EMPTY: LearningProgress = { remediatedLabIds: [], completedMissionStepIds: [] };

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((item): item is string => typeof item === "string" && item.length > 0))];
}

export function sanitizeLearningProgress(value: unknown): LearningProgress {
  if (!value || typeof value !== "object" || Array.isArray(value)) return { ...EMPTY };
  const row = value as Record<string, unknown>;
  return {
    remediatedLabIds: stringList(row.remediatedLabIds),
    completedMissionStepIds: stringList(row.completedMissionStepIds),
  };
}

function load(): LearningProgress {
  try {
    const raw = localStorage.getItem(LEARNING_STORAGE_KEY);
    return raw ? sanitizeLearningProgress(JSON.parse(raw)) : { ...EMPTY };
  } catch {
    return { ...EMPTY };
  }
}

export function useLearningProgress() {
  const [learningProgress, setLearningProgress] = useState<LearningProgress>(load);

  useEffect(() => {
    try {
      localStorage.setItem(LEARNING_STORAGE_KEY, JSON.stringify(learningProgress));
    } catch {
      // Storage may be unavailable; keep progress in memory.
    }
  }, [learningProgress]);

  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key !== LEARNING_STORAGE_KEY) return;
      try {
        setLearningProgress(event.newValue ? sanitizeLearningProgress(JSON.parse(event.newValue)) : { ...EMPTY });
      } catch {
        setLearningProgress({ ...EMPTY });
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const markRemediated = useCallback((labId: string) => {
    setLearningProgress((prev) =>
      prev.remediatedLabIds.includes(labId)
        ? prev
        : { ...prev, remediatedLabIds: [...prev.remediatedLabIds, labId] },
    );
  }, []);

  const completeMissionStep = useCallback((stepId: string) => {
    setLearningProgress((prev) =>
      prev.completedMissionStepIds.includes(stepId)
        ? prev
        : { ...prev, completedMissionStepIds: [...prev.completedMissionStepIds, stepId] },
    );
  }, []);

  const resetLearning = useCallback(() => setLearningProgress({ ...EMPTY }), []);

  return { learningProgress, markRemediated, completeMissionStep, resetLearning };
}

