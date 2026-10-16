import type { Level } from "../../src/labs/types";

/** Number of progressive hints per level (Lv5 is a write-up level with fewer). */
export const HINT_COUNTS: Record<Level, number> = { 1: 3, 2: 3, 3: 3, 4: 3, 5: 2 };

export const HINT_LAB = "xss";
