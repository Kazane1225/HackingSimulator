export type Level = 1 | 2 | 3 | 4 | 5;

export const LEVELS: Level[] = [1, 2, 3, 4, 5];

/** A single input control rendered in a lab's attack form. */
export interface LabField {
  /** Key used in the {@link LabInput} map. */
  name: string;
  /** Human label shown above the control. */
  label: string;
  placeholder?: string;
  /** Render a <textarea> instead of an <input>. */
  multiline?: boolean;
  /** Pre-filled value when the lab (or level) is first opened. */
  default?: string;
  /** Monospace font for payload-ish fields. */
  mono?: boolean;
  /**
   * Omitted from the default Proxy list. The learner adds it while intercepting
   * (Burp-style extra parameter). The target app never shows these knobs.
   */
  hidden?: boolean;
}

/** Values entered by the learner, keyed by {@link LabField.name}. */
export type LabInput = Record<string, string>;

/** Result of running an attack attempt against a simulated backend. */
export interface AttackResult {
  /** Whether the attacker achieved the lab objective at this security level. */
  solved: boolean;
  /** Lines of output to render in the "response" / terminal pane. */
  output: string[];
  /** Short note explaining what the defense did (shown as a system message). */
  note?: string;
  /**
   * For labs that render attacker-controlled markup (XSS), the sanitized HTML
   * to mount inside a sandboxed iframe. When present, the UI uses the iframe's
   * real execution as the source of truth for {@link AttackResult.solved}.
   */
  renderHtml?: string;
  /**
   * The request succeeded as a normal user action (e.g. viewing your own
   * order). The workbench shows "通常応答" instead of treating it as a failed attack.
   */
  benign?: boolean;
  /**
   * The attempt did not clear the level, but revealed a useful next step
   * (correct password but MFA required, own order with a leaked related id, …).
   */
  progress?: boolean;
  /** Server-side statement / path / command that was actually built. */
  assembled?: string;
  /** Short replay of the attack, shown only when {@link solved} is true. */
  recap?: string[];
  /** Secrets discovered in this response (MFA codes, flags, related IDs, …). */
  loot?: LootItem[];
  /** Show {@link output} as the primary response (a multi-attempt log). */
  transcript?: boolean;
}

/** An item the learner can reuse in a later request. */
export interface LootItem {
  id: string;
  label: string;
  value: string;
}

/** Educational description of one security level of a lab. */
export interface LevelSpec {
  /** What the defense does, in one line. */
  defense: string;
  /**
   * Nudges that do not give the answer away, ordered from a general pointer to
   * a concrete technique. The UI reveals them one at a time (always available).
   */
  hints: string[];
  /** A working payload / approach (revealed only after the level is solved). */
  solution: string;
  /** Pseudo server-side code of the defense, shown for code-review practice. */
  code: string;
}

export interface Reference {
  title: string;
  url: string;
}

/** Where the vulnerability class sits in common taxonomies. */
export interface Standards {
  /** OWASP Top 10:2021 category. */
  owasp: { code: string; name: string; url: string };
  cwe: { id: number; name: string }[];
}

export interface LabMeta {
  id: string;
  title: string;
  shortTitle: string;
  category: string;
  /** What the attacker must achieve, shown as the mission brief. */
  objective: string;
  /** One-line summary shown on the dashboard. */
  summary: string;
  standards: Standards;
  /** Further reading shown in the 解説 tab. */
  references: Reference[];
}

/** A complete lab: metadata, input shape, per-level logic and teaching text. */
export interface Lab {
  meta: LabMeta;
  /** Input controls for the attack form. */
  fields: LabField[];
  /** Deep-dive on the vulnerability class and correct defenses (解説). */
  explanation: string;
  /** Per-level defense text, hints, solutions and pseudo-code. */
  levels: Record<Level, LevelSpec>;
  /** Simulate the vulnerable backend at `level` for the given `input`. */
  run(level: Level, input: LabInput): AttackResult;
  /**
   * A reference exploit for each beatable level (Lv1-4). Used by
   * `npm run test:labs` to verify the level design; never shown in the UI.
   */
  exploits: Record<1 | 2 | 3 | 4, LabInput>;
}
