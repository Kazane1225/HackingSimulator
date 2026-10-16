import { useCallback, useEffect, useState } from "react";
import type { LootItem } from "./labs/types";

const STORAGE_KEY = "hacklab.loot.v2";

export interface StoredLoot extends LootItem {
  labId: string;
}

function sanitize(value: unknown): StoredLoot[] {
  if (!Array.isArray(value)) return [];
  const out: StoredLoot[] = [];
  for (const row of value) {
    if (!row || typeof row !== "object") continue;
    const { id, label, value: v, labId } = row as Record<string, unknown>;
    if (typeof id !== "string" || typeof label !== "string" || typeof v !== "string" || typeof labId !== "string") {
      continue;
    }
    if (!id || !v) continue;
    if (id.endsWith("-xss-alert") || id === "csrf-amount" || id === "upload-shell" || id === "auth-admin" || id === "idor-bob") {
      continue;
    }
    out.push({ id, label, value: v, labId });
  }
  return out;
}

function load(): StoredLoot[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? sanitize(JSON.parse(raw)) : [];
  } catch {
    return [];
  }
}

export function useLoot() {
  const [items, setItems] = useState<StoredLoot[]>(load);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
    } catch {
      // private mode
    }
  }, [items]);

  const ingest = useCallback((labId: string, found: LootItem[] | undefined) => {
    if (!found?.length) return;
    setItems((prev) => {
      const next = [...prev];
      for (const item of found) {
        const row: StoredLoot = { ...item, labId };
        const idx = next.findIndex((x) => x.id === item.id && x.labId === labId);
        if (idx >= 0) next[idx] = row;
        else next.push(row);
      }
      return next;
    });
  }, []);

  return { items, ingest };
}
