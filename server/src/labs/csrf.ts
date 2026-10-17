import crypto from "node:crypto";
import http, { type IncomingHttpHeaders, type IncomingMessage } from "node:http";
import type { AttackResult, LabInput, Level, RealLab } from "./runner.js";

/**
 * Real CSRF lab: a genuine `node:http` "bank" server runs on an ephemeral
 * 127.0.0.1 port (lazily started, `unref`ed so it never keeps the process
 * alive). `run()` plays the victim's browser for real: it logs the victim in
 * (reading the actual `Set-Cookie` response), parses the attacker-authored
 * HTML to see which request it would auto-fire, and sends that request to
 * the real server with cookies attached per a real (if simplified) SameSite
 * decision. Header-injection (Lv1-4) is reproduced with an explicit raw HTTP
 * response builder that bypasses Node's own header validation; Lv5 uses
 * `res.setHeader`, whose genuine CRLF rejection (`ERR_INVALID_CHAR`) is the
 * real defense. CSRF tokens for Lv1-4 are the same well-known demo constants
 * the front end's hints teach; Lv5's token is a real per-session HMAC
 * (`node:crypto`) nobody outside the server can predict.
 */

const VICTIM_SESSION = "s-victim";
const ATTACKER_SESSION = "s-attacker";
/** Same constants as the simulated lab - the front-end hints literally teach these. */
const VICTIM_CSRF_TOKEN = "a9f3c1d7-7e21-4b8c-9f02-sErVeRsEcReT";
const ATTACKER_CSRF_TOKEN = "csrf-issued-attacker";
const ISSUED_TOKENS = new Set([VICTIM_CSRF_TOKEN, ATTACKER_CSRF_TOKEN]);
/** Random per-process secret backing the Lv5 (correct) session-bound token. */
const SECRET = crypto.randomBytes(32);

function tokenFor(level: Level, sessionId: string): string {
  if (level === 5) return crypto.createHmac("sha256", SECRET).update(sessionId).digest("hex");
  return sessionId === ATTACKER_SESSION ? ATTACKER_CSRF_TOKEN : VICTIM_CSRF_TOKEN;
}

function parseCookieHeader(header: string | undefined): Map<string, string> {
  const map = new Map<string, string>();
  for (const part of (header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    map.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
  }
  return map;
}

const MAX_BODY_BYTES = 16 * 1024;

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) break;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function respond(res: http.ServerResponse, status: number, text: string): void {
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8", "Content-Length": Buffer.byteLength(text) });
  res.end(text);
}

function handleLogin(res: http.ServerResponse, url: URL, level: Level): void {
  const sessionId = url.searchParams.get("as") === "attacker" ? ATTACKER_SESSION : VICTIM_SESSION;
  const cookieAttrs = [`session=${sessionId}`, "HttpOnly"];
  if (level === 5) cookieAttrs.push("SameSite=Strict");
  res.writeHead(200, {
    "Set-Cookie": cookieAttrs.join("; "),
    "X-Csrf-Token": tokenFor(level, sessionId),
    "Content-Type": "text/plain",
  });
  res.end("ok");
}

/** `l` is reflected into `Set-Cookie` without stripping CR/LF below Lv5 - a real raw-response builder lets that actually happen on the wire. */
function handleSetLang(res: http.ServerResponse, req: IncomingMessage, url: URL, level: Level): void {
  const l = url.searchParams.get("l") ?? "";
  if (level >= 5) {
    try {
      res.setHeader("Set-Cookie", `lang=${l}`);
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    } catch (err) {
      // Node's own header validation is the real Lv5 defense.
      respond(res, 400, `rejected: ${err instanceof Error ? err.message : String(err)}`);
    }
    return;
  }
  const body = "ok";
  const raw =
    `HTTP/1.1 200 OK\r\n` +
    `Content-Type: text/plain\r\n` +
    `Set-Cookie: lang=${l}\r\n` +
    `Content-Length: ${Buffer.byteLength(body)}\r\n` +
    `Connection: close\r\n\r\n${body}`;
  req.socket.end(raw);
}

async function handleTransfer(res: http.ServerResponse, req: IncomingMessage, url: URL, level: Level): Promise<void> {
  const cookies = parseCookieHeader(req.headers.cookie);
  const sessionId = cookies.get("session");
  if (sessionId !== VICTIM_SESSION && sessionId !== ATTACKER_SESSION) {
    respond(res, 403, "未認証のリクエストです。");
    return;
  }
  if (level >= 2 && req.method !== "POST") {
    respond(res, 403, "GET による状態変更は拒否されました（POST 必須）。");
    return;
  }

  const params = req.method === "POST" ? new URLSearchParams(await readBody(req)) : url.searchParams;

  if (level === 3 && !ISSUED_TOKENS.has(params.get("csrf_token") ?? "")) {
    respond(res, 403, "CSRF トークンが無効です。");
    return;
  }
  if (level >= 4 && params.get("csrf_token") !== tokenFor(level, sessionId)) {
    respond(
      res,
      403,
      level === 5 ? "CSRF トークンが一致しません。" : "CSRF トークンがこのセッションに紐づいていません。",
    );
    return;
  }

  const to = params.get("to");
  const amount = Number(params.get("amount"));
  if (!to || !(amount > 0)) {
    respond(res, 403, "送金先または金額が不正です。");
    return;
  }
  respond(res, 200, `${to} へ ${amount} 円を送金しました。`);
}

function handleBankRequest(req: IncomingMessage, res: http.ServerResponse): void {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  const levelHeader = Number(req.headers["x-lab-level"]);
  const level = (Number.isInteger(levelHeader) && levelHeader >= 1 && levelHeader <= 5 ? levelHeader : 1) as Level;
  if (url.pathname === "/login") {
    handleLogin(res, url, level);
  } else if (url.pathname === "/set-lang") {
    handleSetLang(res, req, url, level);
  } else if (url.pathname === "/transfer") {
    handleTransfer(res, req, url, level).catch(() => respond(res, 500, "internal error"));
  } else {
    respond(res, 404, "not found");
  }
}

let bankPromise: Promise<number> | undefined;

/** Lazily start the loopback-only bank server; `unref`ed so it never blocks process exit. */
function getBank(): Promise<number> {
  if (!bankPromise) {
    bankPromise = new Promise((resolve) => {
      const server = http.createServer(handleBankRequest);
      server.listen(0, "127.0.0.1", () => {
        server.unref();
        const addr = server.address();
        resolve(typeof addr === "object" && addr !== null ? addr.port : 0);
      });
    });
  }
  return bankPromise;
}

interface BankResponse {
  status: number;
  headers: IncomingHttpHeaders;
  bodyText: string;
}

function bankRequest(
  port: number,
  method: string,
  pathAndQuery: string,
  opts: { level: Level; cookie?: string; body?: string },
): Promise<BankResponse> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { "x-lab-level": String(opts.level) };
    if (opts.cookie) headers.cookie = opts.cookie;
    let bodyBuf: Buffer | undefined;
    if (opts.body !== undefined) {
      bodyBuf = Buffer.from(opts.body, "utf8");
      headers["content-type"] = "application/x-www-form-urlencoded";
      headers["content-length"] = String(bodyBuf.length);
    }
    const req = http.request(
      { host: "127.0.0.1", port, path: pathAndQuery, method, headers, timeout: 2000 },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, headers: res.headers, bodyText: Buffer.concat(chunks).toString("utf8") }),
        );
      },
    );
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("bank request timed out")));
    req.end(bodyBuf);
  });
}

function sessionCookieFrom(headers: IncomingHttpHeaders): { value?: string; sameSite?: string } {
  for (const line of headers["set-cookie"] ?? []) {
    const [nameValue, ...attrs] = line.split(";").map((p) => p.trim());
    const eq = nameValue.indexOf("=");
    if (eq === -1 || nameValue.slice(0, eq) !== "session") continue;
    const sameSiteAttr = attrs.find((a) => a.toLowerCase().startsWith("samesite="));
    return { value: nameValue.slice(eq + 1), sameSite: sameSiteAttr?.split("=")[1]?.toLowerCase() };
  }
  return {};
}

function attr(attrs: string, name: string): string | undefined {
  const m = attrs.match(new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
  return m ? (m[1] ?? m[2] ?? m[3] ?? "") : undefined;
}

/** First `src=` of an `<img>`/`<iframe>`/`<script>` whose URL matches `pattern` (victim browser auto-loading a resource). */
function findResourceUrl(html: string, pattern: RegExp): string | undefined {
  const re = /<(?:img|iframe|script)\b[^>]*\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    const url = m[1] ?? m[2] ?? m[3] ?? "";
    if (pattern.test(url)) return url;
  }
  return undefined;
}

interface Attack {
  method: "GET" | "POST";
  path: string;
  search: string;
  bodyText?: string;
  params: Record<string, string>;
}

/** Parse the attacker's HTML into the cross-site request it would auto-trigger. */
function parseAttack(html: string): Attack | null {
  const form = html.match(/<form\b([^>]*)>([\s\S]*?)<\/form>/i);
  if (form && /transfer/i.test(attr(form[1], "action") ?? "")) {
    const method = (attr(form[1], "method") ?? "get").toLowerCase() === "post" ? "POST" : "GET";
    const action = attr(form[1], "action") ?? "";
    const params: Record<string, string> = {};
    const inputRe = /<input\b([^>]*)>/gi;
    let m: RegExpExecArray | null;
    while ((m = inputRe.exec(form[2]))) {
      const name = attr(m[1], "name");
      if (name) params[name] = attr(m[1], "value") ?? "";
    }
    const u = new URL(action, "https://bank.example");
    if (method === "GET") {
      for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
      return { method: "GET", path: u.pathname, search: u.search, params };
    }
    return { method: "POST", path: u.pathname, search: "", bodyText: new URLSearchParams(params).toString(), params };
  }

  const url = findResourceUrl(html, /transfer/i);
  if (url) {
    const u = new URL(url, "https://bank.example");
    return { method: "GET", path: u.pathname, search: u.search, params: Object.fromEntries(u.searchParams) };
  }
  return null;
}

async function run(level: Level, input: LabInput): Promise<AttackResult> {
  const html = input.html ?? "";
  const port = await getBank();
  const output: string[] = ["// 被害者 (bank.example にログイン済み) が悪性ページを閲覧…"];

  const victimLogin = await bankRequest(port, "GET", "/login?as=victim", { level });
  const victimCookie = sessionCookieFrom(victimLogin.headers);

  let injectedSession: string | undefined;
  const setLangUrl = findResourceUrl(html, /set-lang/i);
  if (setLangUrl) {
    const u = new URL(setLangUrl, "https://bank.example");
    const setLangRes = await bankRequest(port, "GET", `${u.pathname}${u.search}`, { level });
    const swapped = sessionCookieFrom(setLangRes.headers);
    if (swapped.value) {
      injectedSession = swapped.value;
      output.push(`→ GET https://bank.example${u.pathname}${u.search}`);
      output.push(`   Set-Cookie: session=${injectedSession}  ← 注入された Cookie`);
    }
  }

  const attack = parseAttack(html);
  if (!attack) {
    output.push("→ /transfer への自動リクエストは発生しませんでした。");
    return {
      solved: false,
      output,
      note: "transfer エンドポイントへ自動で送られるリクエスト（img の GET か自動送信フォーム）を作りましょう。",
    };
  }

  const sameSiteBlocksCookie = victimCookie.sameSite === "strict";
  const sessionForRequest = injectedSession ?? victimCookie.value ?? VICTIM_SESSION;
  const cookieHeader = sameSiteBlocksCookie ? undefined : `session=${sessionForRequest}`;

  const transferRes = await bankRequest(port, attack.method, `${attack.path}${attack.search}`, {
    level,
    cookie: cookieHeader,
    body: attack.bodyText,
  });

  output.push(`→ ${attack.method} https://bank.example/transfer`);
  output.push(`   params : ${JSON.stringify(attack.params)}`);
  output.push(`   Cookie : ${cookieHeader ?? "(SameSite=Strict により送信されない)"}`);
  output.push("");
  const solved = transferRes.status === 200;
  output.push(`[${solved ? "200 OK" : `${transferRes.status} BLOCKED`}] ${transferRes.bodyText}`);

  return {
    solved,
    output,
    note: solved
      ? "被害者のブラウザ経由で不正送金が成立しました。"
      : "送金はブロックされました。防御を回避する手口を考えましょう。",
    assembled: [
      injectedSession ? `Set-Cookie: session=${injectedSession}` : null,
      `${attack.method} /transfer ${JSON.stringify(attack.params)}`,
      `Cookie: ${cookieHeader ?? "(none)"}`,
    ]
      .filter((x): x is string => x !== null)
      .join("\n"),
    recap: solved
      ? [
          "被害者ブラウザが罠ページを開いた",
          injectedSession ? "CRLF でセッション Cookie を差し替えた" : "クロスサイトで transfer が送られた",
          `${attack.params.to ?? "attacker"} へ ${attack.params.amount ?? "?"} 円が動いた`,
        ]
      : undefined,
  };
}

export const csrfRealLab: RealLab = { id: "csrf", run };
