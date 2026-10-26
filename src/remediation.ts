import type { Level } from "./labs/types";

export const PATCH_LEVELS: Level[] = [2, 3, 4, 5];
export const PATCH_LABELS = ["Patch A", "Patch B", "Patch C", "Patch D"];

function hash(text: string): number {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/** Stable per lab, so the secure patch is not always in the same slot. */
export function patchOrder(labId: string): Level[] {
  const order = [...PATCH_LEVELS];
  let seed = hash(labId);
  for (let i = order.length - 1; i > 0; i--) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const j = seed % (i + 1);
    [order[i], order[j]] = [order[j], order[i]];
  }
  return order;
}

/**
 * The attack-mode pseudo-code annotates its own holes ("role は連結のまま").
 * Patches are reviewed without those annotations. Only `// ` followed by a
 * space counts as a comment, so regexes like `/\.\.\//g` and URLs survive.
 */
export function reviewCode(code: string): string {
  return code
    .split("\n")
    .filter((line) => !/^\s*\/\/ /.test(line))
    .map((line) => line.replace(/\s+\/\/ .*$/, ""))
    .join("\n");
}
