import { cmdiLab } from "./cmdi";
import { csrfLab } from "./csrf";
import { pathTraversalLab } from "./pathtraversal";
import { sqliLab } from "./sqli";
import type { Lab } from "./types";
import { xssLab } from "./xss";

export const LABS: Lab[] = [sqliLab, xssLab, cmdiLab, pathTraversalLab, csrfLab];

export function findLab(id: string): Lab | undefined {
  return LABS.find((l) => l.meta.id === id);
}
