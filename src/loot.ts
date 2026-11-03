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

export function readLoot(): StoredLoot[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? sanitize(JSON.parse(raw)) : [];
  } catch {
    return [];
  }
}

const LOOT_EVENT = "hacklab-loot";

export function useLoot() {
  const [items, setItems] = useState<StoredLoot[]>(readLoot);

  useEffect(() => {
    try {
      const raw = JSON.stringify(items);
      if (localStorage.getItem(STORAGE_KEY) !== raw) {
        localStorage.setItem(STORAGE_KEY, raw);
        window.dispatchEvent(new Event(LOOT_EVENT));
      }
    } catch {
      // private mode
    }
  }, [items]);

  useEffect(() => {
    const sync = () => {
      const next = readLoot();
      setItems((prev) => (JSON.stringify(prev) === JSON.stringify(next) ? prev : next));
    };
    const onStorage = (event: StorageEvent) => {
      if (event.key !== STORAGE_KEY) return;
      sync();
    };
    window.addEventListener("storage", onStorage);
    window.addEventListener(LOOT_EVENT, sync);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener(LOOT_EVENT, sync);
    };
  }, []);

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

  const reset = useCallback(() => setItems([]), []);
  const replace = useCallback((value: unknown) => setItems(sanitize(value)), []);

  return { items, ingest, reset, replace };
}
