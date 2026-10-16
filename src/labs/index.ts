import { authLab } from "./auth";
import { cmdiLab } from "./cmdi";
import { csrfLab } from "./csrf";
import { idorLab } from "./idor";
import { jwtLab } from "./jwt";
import { pathTraversalLab } from "./pathtraversal";
import { sqliLab } from "./sqli";
import { ssrfLab } from "./ssrf";
import type { Lab } from "./types";
import { uploadLab } from "./upload";
import { xssLab } from "./xss";

export const LABS: Lab[] = [
  sqliLab,
  xssLab,
  cmdiLab,
  pathTraversalLab,
  csrfLab,
  idorLab,
  authLab,
  jwtLab,
  ssrfLab,
  uploadLab,
];

export function findLab(id: string): Lab | undefined {
  return LABS.find((l) => l.meta.id === id);
}
