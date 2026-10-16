import { xssLab } from "../../src/labs/xss";
import type { Level } from "../../src/labs/types";

/** Reference exploits (Lv1-4) are shared with the lab design tests. */
export const XSS_EXPLOITS = xssLab.exploits;

export const XSS_PARAM = "comment";

/**
 * Payloads that leave an "active vector" in the HTML but never execute in the
 * sandboxed preview. They must not be credited as a clear.
 */
export const XSS_NON_EXECUTING: { level: Level; payload: string; reason: string }[] = [
  { level: 2, payload: "<a onclick=alert(1)>x</a>", reason: "onclick needs a user click" },
  { level: 1, payload: "<b>bold</b>", reason: "plain markup, no script" },
];
