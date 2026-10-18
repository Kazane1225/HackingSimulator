import type { AttackResult, LabInput, Level } from "../labs/types";

export const TARGET_CHANNEL = "hacklab-target";
export const TARGET_WINDOW = "hacklab-target";

/** Snapshot of the lab the workbench is driving. */
export interface TargetState {
  type: "state";
  labId: string;
  level: Level;
  inputs: LabInput;
  result: AttackResult | null;
  runId: number;
  fired: string | null;
  browserTab: string;
  succeeded: boolean;
}

export type TargetToApp = TargetState;

export type AppToTarget =
  | { type: "hello" }
  | { type: "field"; name: string; value: string }
  | { type: "submit"; patch?: LabInput }
  | { type: "tab"; id: string }
  | { type: "fire"; message: string };

export function openTargetApp(): void {
  const url = `${location.pathname}${location.search}#/app`;
  window.open(url, TARGET_WINDOW);
}

export function targetChannel(): BroadcastChannel | null {
  if (typeof BroadcastChannel === "undefined") return null;
  return new BroadcastChannel(TARGET_CHANNEL);
}
