import type { AttackResult, LootItem } from "./types";

/** Attach the constructed-server preview, optional recap, and loot. */
export function traced(
  result: AttackResult,
  assembled: string,
  extras?: { recap?: string[]; loot?: LootItem[] },
): AttackResult {
  return {
    ...result,
    assembled,
    recap: result.solved ? extras?.recap : undefined,
    loot: extras?.loot,
  };
}
