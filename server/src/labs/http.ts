import type { IncomingMessage, ServerResponse } from "node:http";
import { registerLab } from "../app.js";
import { authRealLab } from "./auth.js";
import { cmdiRealLab } from "./cmdi.js";
import { cryptoRealLab } from "./crypto.js";
import { csrfRealLab } from "./csrf.js";
import { depsRealLab } from "./deps.js";
import { idorRealLab } from "./idor.js";
import { integrityRealLab } from "./integrity.js";
import { jwtRealLab } from "./jwt.js";
import { loggingRealLab } from "./logging.js";
import { misconfRealLab } from "./misconf.js";
import { pathtraversalRealLab } from "./pathtraversal.js";
import type { AttackResult, LabInput, Level, RealLab } from "./runner.js";
import { sqliRealLab } from "./sqli.js";
import { ssrfRealLab } from "./ssrf.js";
import { uploadRealLab } from "./upload.js";
import { xssRealLab } from "./xss.js";

/**
 * Real target routes. Each handler calls the lab's existing `run()` (the
 * vulnerable engine) and returns the application response — status, headers
 * and body — without the scoring fields (`solved`, notes, recap).
 *
 *   POST /sqli/lvN/login
 *   POST /xss/lvN/comment
 *   POST /cmdi/lvN/ping
 *   GET  /path/lvN/files?path=
 *   POST /csrf/lvN/page
 *   GET  /idor/lvN/api/orders/:id
 *   GET  /idor/lvN/api/export?id=
 *   POST /idor/lvN/graphql
 *   POST /auth/lvN/login
 *   GET  /jwt/lvN/admin
 *   POST /ssrf/lvN/fetch
 *   POST /upload/lvN/avatar
 *   POST /crypto/lvN/open
 *   GET  /misconf/lvN/page?path=
 *   POST /deps/lvN/thumb
 *   POST /integrity/lvN/apply
 *   POST /logging/lvN/act
 */

const MAX_BODY_BYTES = 64 * 1024;
const MAX_FIELDS = 16;
const MAX_VALUE_LENGTH = 8000;

class BadRequest extends Error {}

export interface AppHttp {
  status: number;
  headers: Record<string, string>;
  contentType: string;
  body: string;
}

interface Hit {
  req: IncomingMessage;
  url: URL;
  level: Level;
  rest: string;
}

function text(status: number, body: string, headers: Record<string, string> = {}): AppHttp {
  return { status, headers, contentType: "text/plain; charset=utf-8", body };
}

function html(body: string): AppHttp {
  return { status: 200, headers: {}, contentType: "text/html; charset=utf-8", body };
}

/** Drop the one-line defense headline. Keep SQL bind lines and everything the app printed. */
function transcript(result: AttackResult): string {
  return result.output.filter((line) => !line.startsWith("-- ") || line.startsWith("-- bind")).join("\n");
}

function statusIn(body: string, fallback: number): number {
  const m = body.match(/\[(\d{3})\b/);
  return m ? Number(m[1]) : fallback;
}

async function readRaw(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new BadRequest("body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function takeFields(entries: Iterable<[string, string]>): LabInput {
  const input: LabInput = {};
  let count = 0;
  for (const [key, value] of entries) {
    count++;
    if (count > MAX_FIELDS) throw new BadRequest("too many fields");
    if (value.length > MAX_VALUE_LENGTH) throw new BadRequest("field values must be short strings");
    input[key] = value;
  }
  return input;
}

async function readForm(req: IncomingMessage): Promise<LabInput> {
  return takeFields(new URLSearchParams(await readRaw(req)));
}

function queryFields(url: URL, names: string[]): LabInput {
  const input: LabInput = {};
  for (const name of names) {
    const value = url.searchParams.get(name);
    if (value !== null) input[name] = value;
  }
  return input;
}

function parseMultipart(raw: string, boundary: string): LabInput {
  for (const part of raw.split(`--${boundary}`)) {
    const trimmed = part.replace(/^\r\n/, "");
    if (trimmed.startsWith("--") || trimmed.trim() === "") continue;
    const sep = trimmed.indexOf("\r\n\r\n");
    if (sep < 0) continue;
    const header = trimmed.slice(0, sep);
    let body = trimmed.slice(sep + 4);
    if (body.endsWith("\r\n")) body = body.slice(0, -2);
    const disp = /content-disposition:[^\r\n]*/i.exec(header)?.[0] ?? "";
    const filename = /filename="([^"]*)"/.exec(disp)?.[1] ?? /filename=([^;\s]+)/.exec(disp)?.[1];
    if (!filename) continue;
    if (body.length > MAX_VALUE_LENGTH) throw new BadRequest("field values must be short strings");
    const contentType = /content-type:\s*([^\r\n]+)/i.exec(header)?.[1]?.trim() ?? "";
    return { filename, contentType, content: body };
  }
  throw new BadRequest("file part missing");
}

async function readUpload(req: IncomingMessage): Promise<LabInput> {
  const ct = req.headers["content-type"];
  const header = Array.isArray(ct) ? ct[0] : (ct ?? "");
  const boundary = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(header)?.[1] ?? /boundary=(?:"([^"]+)"|([^;]+))/i.exec(header)?.[2];
  if (!boundary) throw new BadRequest("multipart required");
  return parseMultipart(await readRaw(req), boundary.trim());
}

function requireMethod(req: IncomingMessage, method: string): void {
  if (req.method !== method) throw new MethodNotAllowed();
}

class MethodNotAllowed extends Error {}

function present(id: string, result: AttackResult): AppHttp {
  if (id === "xss") return html(result.renderHtml ?? "");

  const body = transcript(result);

  if (id === "auth") {
    const headers: Record<string, string> = {};
    const mail = result.output.find((line) => line.startsWith("X-Debug-Mail:"));
    if (mail) headers["X-Debug-Mail"] = mail.slice("X-Debug-Mail: ".length);
    if (body.includes("管理コンソール / admin")) {
      headers["Set-Cookie"] = "session=admin; HttpOnly";
      return text(200, `${body}\nSet-Cookie: session=admin; HttpOnly`, headers);
    }
    return text(401, body, headers);
  }

  if (id === "jwt") return text(statusIn(body, 401), body);
  if (id === "csrf") return text(statusIn(body, 200), body);
  if (id === "idor") return text(statusIn(body, body.includes("FORBIDDEN") ? 403 : 200), body);
  if (id === "ssrf") return text(statusIn(body, 200), body);
  if (id === "upload") {
    const headers: Record<string, string> = {};
    const handler = /X-Handler: (\S+)/.exec(body)?.[1];
    if (handler) headers["X-Handler"] = handler;
    return text(statusIn(body, 400), body, headers);
  }
  if (id === "path") {
    if (body.includes("DENY")) return text(403, body);
    if (/not found|ENOENT/i.test(body)) return text(404, body);
    return text(200, body);
  }
  if (id === "misconf") return text(body.split("\n").includes("404") ? 404 : 200, body);
  if (id === "logging") {
    const headers: Record<string, string> = {};
    if (result.solved) headers["X-Export"] = "accepted";
    return text(200, body, headers);
  }
  return text(200, body);
}

async function dispatch(lab: RealLab, hit: Hit): Promise<AppHttp> {
  const { req, url, level, rest } = hit;
  const id = lab.id;

  if (id === "sqli") {
    requireMethod(req, "POST");
    if (rest !== "/login") return text(404, "not found");
    return present(id, await lab.run(level, await readForm(req)));
  }

  if (id === "xss") {
    requireMethod(req, "POST");
    if (rest !== "/comment") return text(404, "not found");
    return present(id, await lab.run(level, await readForm(req)));
  }

  if (id === "cmdi") {
    requireMethod(req, "POST");
    if (rest !== "/ping") return text(404, "not found");
    return present(id, await lab.run(level, await readForm(req)));
  }

  if (id === "path") {
    requireMethod(req, "GET");
    if (rest !== "/files") return text(404, "not found");
    return present(id, await lab.run(level, { name: url.searchParams.get("path") ?? "" }));
  }

  if (id === "csrf") {
    requireMethod(req, "POST");
    if (rest !== "/page") return text(404, "not found");
    return present(id, await lab.run(level, await readForm(req)));
  }

  if (id === "idor") {
    if (rest === "/graphql") {
      requireMethod(req, "POST");
      const form = await readForm(req);
      return present(id, await lab.run(level, { ...form, endpoint: "/graphql" }));
    }
    if (rest === "/api/export") {
      requireMethod(req, "GET");
      const q = queryFields(url, ["id", "owner", "role"]);
      return present(id, await lab.run(level, { endpoint: "/api/export", orderId: q.id ?? "", owner: q.owner ?? "alice", role: q.role ?? "user" }));
    }
    if (rest.startsWith("/api/orders/")) {
      requireMethod(req, "GET");
      const q = queryFields(url, ["owner", "role"]);
      return present(id, await lab.run(level, {
        endpoint: "/api/orders",
        orderId: decodeURIComponent(rest.slice("/api/orders/".length)),
        owner: q.owner ?? "alice",
        role: q.role ?? "user",
      }));
    }
    return text(404, "not found");
  }

  if (id === "auth") {
    requireMethod(req, "POST");
    if (rest !== "/login") return text(404, "not found");
    return present(id, await lab.run(level, await readForm(req)));
  }

  if (id === "jwt") {
    requireMethod(req, "GET");
    if (rest !== "/admin") return text(404, "not found");
    const authorization = req.headers.authorization ?? "";
    const token = authorization.replace(/^Bearer\s+/i, "").trim();
    return present(id, await lab.run(level, { token }));
  }

  if (id === "ssrf") {
    requireMethod(req, "POST");
    if (rest !== "/fetch") return text(404, "not found");
    return present(id, await lab.run(level, await readForm(req)));
  }

  if (id === "upload") {
    requireMethod(req, "POST");
    if (rest !== "/avatar") return text(404, "not found");
    return present(id, await lab.run(level, await readUpload(req)));
  }

  if (id === "crypto") {
    requireMethod(req, "POST");
    if (rest !== "/open") return text(404, "not found");
    return present(id, await lab.run(level, await readForm(req)));
  }

  if (id === "misconf") {
    requireMethod(req, "GET");
    if (rest !== "/page") return text(404, "not found");
    return present(id, await lab.run(level, { path: url.searchParams.get("path") ?? "/" }));
  }

  if (id === "deps") {
    requireMethod(req, "POST");
    if (rest !== "/thumb") return text(404, "not found");
    return present(id, await lab.run(level, await readForm(req)));
  }

  if (id === "integrity") {
    requireMethod(req, "POST");
    if (rest !== "/apply") return text(404, "not found");
    return present(id, await lab.run(level, await readForm(req)));
  }

  if (id === "logging") {
    requireMethod(req, "POST");
    if (rest !== "/act") return text(404, "not found");
    return present(id, await lab.run(level, await readForm(req)));
  }

  return text(404, "not found");
}

function writeApp(res: ServerResponse, app: AppHttp): void {
  const body = Buffer.from(app.body, "utf8");
  res.writeHead(app.status, {
    "Content-Type": app.contentType,
    "Content-Length": body.length,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...app.headers,
  });
  res.end(body);
}

function registerTarget(lab: RealLab): void {
  registerLab(`/${lab.id}`, async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const match = new RegExp(`^/${lab.id}/lv([1-5])(/.*)?$`).exec(url.pathname);
    if (!match) {
      writeApp(res, text(404, "not found"));
      return;
    }
    const level = Number(match[1]) as Level;
    const rest = match[2] ?? "/";
    try {
      writeApp(res, await dispatch(lab, { req, url, level, rest }));
    } catch (err) {
      if (err instanceof MethodNotAllowed) writeApp(res, text(405, "method not allowed"));
      else if (err instanceof BadRequest) writeApp(res, text(400, err.message));
      else throw err;
    }
  });
}

const TARGETS: RealLab[] = [
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
  cryptoRealLab,
  misconfRealLab,
  depsRealLab,
  integrityRealLab,
  loggingRealLab,
];

export function registerHttpLabs(): void {
  for (const lab of TARGETS) registerTarget(lab);
}
