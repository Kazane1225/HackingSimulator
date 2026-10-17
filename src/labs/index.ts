import { authLab } from "./auth";
import { cmdiLab } from "./cmdi";
import { cryptoLab } from "./crypto";
import { csrfLab } from "./csrf";
import { depsLab } from "./deps";
import { idorLab } from "./idor";
import { integrityLab } from "./integrity";
import { jwtLab } from "./jwt";
import { loggingLab } from "./logging";
import { misconfLab } from "./misconf";
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
  cryptoLab,
  misconfLab,
  depsLab,
  integrityLab,
  loggingLab,
];

export function findLab(id: string): Lab | undefined {
  return LABS.find((l) => l.meta.id === id);
}
