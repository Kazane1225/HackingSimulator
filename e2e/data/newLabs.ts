import { authLab } from "../../src/labs/auth";
import { idorLab } from "../../src/labs/idor";
import { jwtLab } from "../../src/labs/jwt";
import { ssrfLab } from "../../src/labs/ssrf";
import { uploadLab } from "../../src/labs/upload";
import type { LabInput } from "../../src/labs/types";

/** New labs added in PR #14, with the same reference exploits as `test:labs`. */
export const NEW_LABS: { id: string; exploits: Record<1 | 2 | 3 | 4, LabInput> }[] = [
  { id: "idor", exploits: idorLab.exploits },
  { id: "auth", exploits: authLab.exploits },
  { id: "jwt", exploits: jwtLab.exploits },
  { id: "ssrf", exploits: ssrfLab.exploits },
  { id: "upload", exploits: uploadLab.exploits },
];
