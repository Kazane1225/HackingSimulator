import type { IncomingMessage } from "node:http";
import { json, registerLab } from "../app.js";

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

const MAX_BODY_BYTES = 16 * 1024;
const MAX_FIELDS = 16;
const MAX_VALUE_LENGTH = 2000;

class BadRequest extends Error {}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new BadRequest("body too large");
    chunks.push(chunk as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new BadRequest("invalid json");
  }
}

function parseRequest(body: unknown): { level: Level; input: LabInput } {
  if (typeof body !== "object" || body === null) throw new BadRequest("invalid body");
  const { level, input } = body as { level?: unknown; input?: unknown };
  if (typeof level !== "number" || !Number.isInteger(level) || level < 1 || level > 5) {
    throw new BadRequest("level must be 1-5");
  }
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new BadRequest("input must be an object");
  }
  const entries = Object.entries(input);
  if (entries.length > MAX_FIELDS) throw new BadRequest("too many fields");
  const clean: LabInput = {};
  for (const [key, value] of entries) {
    if (typeof value !== "string" || value.length > MAX_VALUE_LENGTH) {
      throw new BadRequest("field values must be short strings");
    }
    clean[key] = value;
  }
  return { level: level as Level, input: clean };
}

/** Exposes `lab.run` as `POST /<id>/run` with body `{ level, input }`. */
export function registerRealLab(lab: RealLab): void {
  const path = `/${lab.id}/run`;
  registerLab(`/${lab.id}`, async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname !== path) {
      json(res, 404, { error: "not_found" });
      return;
    }
    if (req.method !== "POST") {
      json(res, 405, { error: "method_not_allowed" });
      return;
    }
    try {
      const { level, input } = parseRequest(await readJson(req));
      json(res, 200, await lab.run(level, input));
    } catch (err) {
      if (err instanceof BadRequest) json(res, 400, { error: err.message });
      else throw err;
    }
  });
}
