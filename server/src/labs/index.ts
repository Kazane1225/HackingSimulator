import { registerRealLab } from "./runner.js";
import { authRealLab } from "./auth.js";
import { cmdiRealLab } from "./cmdi.js";
import { csrfRealLab } from "./csrf.js";
import { idorRealLab } from "./idor.js";
import { jwtRealLab } from "./jwt.js";
import { pathtraversalRealLab } from "./pathtraversal.js";
import { sqliRealLab } from "./sqli.js";
import { ssrfRealLab } from "./ssrf.js";
import { uploadRealLab } from "./upload.js";
import { xssRealLab } from "./xss.js";

export const REAL_LABS = [
  sqliRealLab,
  xssRealLab,
  cmdiRealLab,
  pathtraversalRealLab,
  csrfRealLab,
  idorRealLab,
  authRealLab,
  jwtRealLab,
  ssrfRealLab,
  uploadRealLab,
];

export function registerAllLabs(): void {
  for (const lab of REAL_LABS) registerRealLab(lab);
}
