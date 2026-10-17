import { registerRealLab } from "./runner.js";
import { cmdiRealLab } from "./cmdi.js";
import { sqliRealLab } from "./sqli.js";

export const REAL_LABS = [sqliRealLab, cmdiRealLab];

export function registerAllLabs(): void {
  for (const lab of REAL_LABS) registerRealLab(lab);
}
