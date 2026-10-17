import { useEffect, useState } from "react";
import type { AttackResult, LabInput, Level } from "./labs/types";

// Relative on purpose: the app is served from sub-paths (GitHub Pages) as well
// as from the gateway, which proxies /api/ to the isolated lab server.
const API = "api";

let labsPromise: Promise<string[]> | null = null;

/** Ids of the labs the real lab server offers; empty when there is no server. */
async function loadRealLabs(): Promise<string[]> {
  try {
    const res = await fetch(`${API}/info`, { cache: "no-store" });
    if (!res.ok) return [];
    // Static hosting answers unknown paths with index.html, which fails to parse.
    const info = (await res.json()) as { name?: unknown; labs?: unknown };
    if (info.name !== "hacklab-server" || !Array.isArray(info.labs)) return [];
    return info.labs.filter((l): l is string => typeof l === "string").map((l) => l.replace(/^\//, ""));
  } catch {
    return [];
  }
}

export function useRealLabs(): string[] {
  const [labs, setLabs] = useState<string[]>([]);
  useEffect(() => {
    let alive = true;
    labsPromise ??= loadRealLabs();
    void labsPromise.then((ids) => {
      if (alive) setLabs(ids);
    });
    return () => {
      alive = false;
    };
  }, []);
  return labs;
}

/** Run one attack attempt against the real lab server. */
export async function runReal(labId: string, level: Level, input: LabInput): Promise<AttackResult> {
  const res = await fetch(`${API}/${labId}/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ level, input }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as AttackResult;
}
