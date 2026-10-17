export type Level = 1 | 2 | 3 | 4 | 5;
export type LabInput = Record<string, string>;

export interface LootItem {
  id: string;
  label: string;
  value: string;
}

/** Same shape as the front end's AttackResult (src/labs/types.ts). */
export interface AttackResult {
  solved: boolean;
  output: string[];
  /** Sanitized markup the front end mounts in a sandboxed iframe (XSS lab). */
  renderHtml?: string;
  note?: string;
  benign?: boolean;
  progress?: boolean;
  assembled?: string;
  recap?: string[];
  loot?: LootItem[];
}

export interface RealLab {
  id: string;
  run(level: Level, input: LabInput): AttackResult | Promise<AttackResult>;
}
