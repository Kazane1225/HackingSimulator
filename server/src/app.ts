import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

export const SERVICE_NAME = "hacklab-server";
export const SERVICE_VERSION = "0.1.0";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
  });
  res.end(payload);
}

// Real vulnerable labs register themselves here (one route prefix per lab,
// e.g. "/sqli"). Keeping the registry explicit makes it obvious which
// intentionally vulnerable endpoints exist.
const labRoutes = new Map<string, Handler>();

export function registerLab(prefix: string, handler: Handler): void {
  labRoutes.set(prefix, handler);
}

function route(req: IncomingMessage, res: ServerResponse): void {
  const url = new URL(req.url ?? "/", "http://localhost");

  if (req.method === "GET" && url.pathname === "/healthz") {
    json(res, 200, { status: "ok" });
    return;
  }

  if (req.method === "GET" && url.pathname === "/info") {
    json(res, 200, {
      name: SERVICE_NAME,
      version: SERVICE_VERSION,
      labs: [...labRoutes.keys()].sort(),
    });
    return;
  }

  for (const [prefix, handler] of labRoutes) {
    if (url.pathname === prefix || url.pathname.startsWith(`${prefix}/`)) {
      handler(req, res);
      return;
    }
  }

  json(res, 404, { error: "not_found" });
}

export function createApp(): Server {
  return createServer((req, res) => {
    try {
      route(req, res);
    } catch {
      json(res, 500, { error: "internal_error" });
    }
  });
}
