import http, { type IncomingHttpHeaders } from "node:http";
import type { AttackResult, LabInput, Level, LootItem, RealLab } from "./runner.js";

/**
 * Real SSRF lab: a genuine `node:http` client with its own `new URL` parsing,
 * host/IP allow-list checks and redirect following talks to a genuine
 * loopback HTTP service. There is no outbound network in the lab container
 * and no real DNS, so hostnames are resolved through an explicit in-process
 * table instead of `dns.lookup` -- anything not in the table fails closed,
 * exactly like a real resolver would for a host that does not exist. Once a
 * hostname resolves, the *real* TCP connection always goes to the loopback
 * helper (the only thing reachable); the resolved address is only used to
 * decide which virtual host the helper answers as and to run the level's
 * real validation logic. Objective: reach the internal metadata service and
 * read its access key.
 */

const METADATA_SECRET = "AKIA-HACKLAB-4f91c2a7e8";
const PUBLIC_IMAGES_IP = "203.0.113.10"; // TEST-NET-3 (RFC 5737): a public-looking, non-routable stand-in.
const PUBLIC_EXAMPLE_IP = "203.0.113.1";
const INTERNAL_IPS = new Set(["127.0.0.1", "169.254.169.254", "::1"]);

/** The sandbox has no real DNS; this is the only resolver the fetcher uses. */
const DNS_TABLE: Record<string, string> = {
  localhost: "127.0.0.1",
  "127.0.0.1": "127.0.0.1",
  "169.254.169.254": "169.254.169.254",
  "[::1]": "::1",
  // Wildcard-DNS-style services (xip.io, nip.io, ...) resolve a hostname that
  // embeds an IP to that IP -- a real, well known SSRF allow-list bypass.
  "127.0.0.1.example.com": "127.0.0.1",
  "localhost.example.com": "127.0.0.1",
  "169.254.169.254.example.com": "169.254.169.254",
  "images.example.com": PUBLIC_IMAGES_IP,
  "example.com": PUBLIC_EXAMPLE_IP,
};

function resolveHost(hostname: string): string | undefined {
  return DNS_TABLE[hostname.toLowerCase()];
}

/** Real private/special-use IP classification (RFC 1918, loopback, link-local). */
function isPrivateOrSpecialIp(ip: string): boolean {
  const bare = ip.replace(/^\[|\]$/g, "");
  if (bare.includes(":")) {
    if (bare === "::1") return true;
    if (/^fe80:/i.test(bare)) return true;
    if (/^f[cd][0-9a-f]{2}:/i.test(bare)) return true;
    if (/^::ffff:/i.test(bare)) return isPrivateOrSpecialIp(bare.slice("::ffff:".length));
    return false;
  }
  const parts = bare.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  const [a, b] = parts;
  return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

function isAllowlistedHost(hostname: string): boolean {
  return hostname === "example.com" || hostname.endsWith(".example.com");
}

// ---------------------------------------------------------------------------
// Loopback "internet": a single real HTTP server bound to 127.0.0.1 answering
// as whichever virtual host the resolved IP maps to.
// ---------------------------------------------------------------------------

let helperPromise: Promise<{ port: number }> | undefined;

function startHelper(): Promise<{ port: number }> {
  const server = http.createServer((req, res) => {
    const resolvedIp = req.headers["x-hacklab-resolved-ip"];
    const url = new URL(req.url ?? "/", "http://helper.internal");
    if (typeof resolvedIp === "string" && INTERNAL_IPS.has(resolvedIp)) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ "instance-role": "hacklab-prod", "access-key": METADATA_SECRET }));
      return;
    }
    if (resolvedIp === PUBLIC_IMAGES_IP) {
      if (/^\/redirect\/?$/.test(url.pathname)) {
        const to = url.searchParams.get("to") ?? "";
        res.writeHead(302, { Location: to });
        res.end();
        return;
      }
      res.writeHead(200, {
        "Content-Type": "image/png",
        "X-Debug-Link": "https://images.example.com/redirect?to=",
      });
      res.end("(binary banner.png stand-in)");
      return;
    }
    if (resolvedIp === PUBLIC_EXAMPLE_IP) {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<html><body>example.com</body></html>");
      return;
    }
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("not found");
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.unref();
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("failed to start ssrf helper"));
        return;
      }
      resolve({ port: address.port });
    });
  });
}

function ensureHelper(): Promise<{ port: number }> {
  helperPromise ??= startHelper();
  return helperPromise;
}

interface HelperResponse {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
}

async function fetchViaHelper(target: URL, resolvedIp: string): Promise<HelperResponse> {
  const helper = await ensureHelper();
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: helper.port,
        method: "GET",
        path: `${target.pathname}${target.search}`,
        headers: { Host: target.host, "x-hacklab-resolved-ip": resolvedIp },
        timeout: 3000,
      },
      (res) => {
        let body = "";
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > 16 * 1024) {
            req.destroy(new Error("response too large"));
            return;
          }
          body += chunk.toString("utf8");
        });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      },
    );
    req.on("timeout", () => req.destroy(new Error("request timed out")));
    req.on("error", reject);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Per-level validation policy and the real fetch/redirect loop
// ---------------------------------------------------------------------------

interface Hop {
  url: URL;
  resolvedIp?: string;
  status?: number;
  headers?: IncomingHttpHeaders;
  blockedReason?: string;
  error?: string;
}

interface Policy {
  /** Checked before resolving a hop's hostname. */
  checkHost(hostname: string): string | undefined;
  /** Checked after resolving a hop's hostname to an IP. */
  checkIp(ip: string): string | undefined;
  followRedirects: boolean;
  /** Re-run checkHost/checkIp on redirect targets, not just the first hop. */
  revalidateRedirects: boolean;
}

const never = (): undefined => undefined;

const policies: Record<Level, Policy> = {
  1: { checkHost: never, checkIp: never, followRedirects: false, revalidateRedirects: false },
  2: {
    checkHost: (h) => (h.toLowerCase() === "localhost" ? "localhost は拒否されました。" : undefined),
    checkIp: never,
    followRedirects: false,
    revalidateRedirects: false,
  },
  3: {
    checkHost: (h) => (isAllowlistedHost(h) ? undefined : "example.com で終わらないホストは許可リスト外です。"),
    checkIp: never,
    followRedirects: false,
    revalidateRedirects: false,
  },
  4: {
    checkHost: (h) => (isAllowlistedHost(h) ? undefined : "初回 URL のホストが許可されていません。"),
    checkIp: (ip) => (isPrivateOrSpecialIp(ip) ? "初回 URL の解決先が許可されていません。" : undefined),
    followRedirects: true,
    revalidateRedirects: false,
  },
  5: {
    checkHost: (h) => (isAllowlistedHost(h) ? undefined : "ホストが許可リスト外です。"),
    checkIp: (ip) => (isPrivateOrSpecialIp(ip) ? "解決先が内部アドレスです。" : undefined),
    followRedirects: true,
    revalidateRedirects: true,
  },
};

async function fetchWithPolicy(startUrl: URL, policy: Policy): Promise<Hop[]> {
  const hops: Hop[] = [];
  let current = startUrl;
  for (let hopIndex = 1; hopIndex <= 5; hopIndex++) {
    if (!["http:", "https:"].includes(current.protocol)) {
      hops.push({ url: current, blockedReason: "許可されていないスキームです。" });
      break;
    }
    const revalidate = hopIndex === 1 || policy.revalidateRedirects;
    if (revalidate) {
      const hostBlock = policy.checkHost(current.hostname);
      if (hostBlock) {
        hops.push({ url: current, blockedReason: hostBlock });
        break;
      }
    }
    const resolvedIp = resolveHost(current.hostname);
    if (!resolvedIp) {
      hops.push({ url: current, error: `getaddrinfo ENOTFOUND ${current.hostname}` });
      break;
    }
    if (revalidate) {
      const ipBlock = policy.checkIp(resolvedIp);
      if (ipBlock) {
        hops.push({ url: current, resolvedIp, blockedReason: ipBlock });
        break;
      }
    }
    let res: HelperResponse;
    try {
      res = await fetchViaHelper(current, resolvedIp);
    } catch (err) {
      hops.push({ url: current, resolvedIp, error: err instanceof Error ? err.message : String(err) });
      break;
    }
    hops.push({ url: current, resolvedIp, status: res.status, headers: res.headers });
    const location = res.headers.location;
    const isRedirect = res.status >= 300 && res.status < 400 && typeof location === "string" && location !== "";
    if (!isRedirect || !policy.followRedirects) break;
    try {
      current = new URL(location, current);
    } catch {
      break;
    }
  }
  return hops;
}

function reachedInternal(hops: Hop[]): boolean {
  const last = hops[hops.length - 1];
  return !!last && last.status === 200 && !!last.resolvedIp && isPrivateOrSpecialIp(last.resolvedIp) && !last.blockedReason && !last.error;
}

function noteFor(level: Level, hops: Hop[], internal: boolean): string {
  const last = hops[hops.length - 1];
  if (level === 1) return internal ? "サーバーから内部サービスへリクエストを送信できました。" : "送信先を検証していません。";
  if (level === 2) return last?.blockedReason ?? (internal ? "サーバーから内部サービスへリクエストを送信できました。" : "文字列 localhost だけを拒否しています。");
  if (level === 3) {
    if (last?.blockedReason) return last.blockedReason;
    return internal ? "許可リスト通過後、名前解決が内部 IP を返しました。" : "公開 URL の取得結果に機密情報はありません。";
  }
  if (level === 4) {
    if (last?.blockedReason) return last.blockedReason;
    return internal ? "公開 URL の検証後、未検証のリダイレクト先へ追従しました。" : "公開画像です。応答ヘッダのデバッグリンクを見てください。";
  }
  return "各リダイレクトで名前解決後の IP を検証し、内部アドレスを拒否しました。";
}

function recapFor(level: Level): string[] {
  if (level === 1) return ["URL の宛先を検証していなかった", "localhost 上の内部サービスに到達した", "メタデータのアクセスキーが返った"];
  if (level === 2) return ["文字列 \"localhost\" だけを拒否していた", "127.0.0.1 表記はブロックされなかった", "メタデータのアクセスキーが返った"];
  if (level === 3) return ["ホスト名の末尾一致だけを許可リストにしていた", "127.0.0.1.example.com が内部アドレスに解決された", "メタデータのアクセスキーが返った"];
  return ["初回 URL は許可リストを通った", "302 の Location を再検証しなかった", "メタデータのアクセスキーが返った"];
}

async function run(level: Level, input: LabInput): Promise<AttackResult> {
  const raw = (input.url ?? "").trim();
  let startUrl: URL;
  try {
    startUrl = new URL(raw);
  } catch {
    return { solved: false, output: ["[400] URL の形式が不正です。"], note: "http または https の URL を入力してください。" };
  }

  const hops = await fetchWithPolicy(startUrl, policies[level]);
  const internal = reachedInternal(hops);
  const last = hops[hops.length - 1];

  const output = [`fetch ${startUrl.toString()}`, ...hops.map((h, i) => `hop${i + 1} ${h.url.toString()}`)];
  const debugLinkShown = level === 4 && !internal && last?.headers?.["x-debug-link"] !== undefined;
  if (debugLinkShown) {
    output.push("HTTP/1.1 200 OK", "X-Debug-Link: https://images.example.com/redirect?to=", "<!-- 取得ワーカーは /redirect の Location を追従します -->");
  }
  if (last?.error) output.push(`ERROR: ${last.error}`);
  else if (last?.blockedReason) output.push(`[403] ${last.blockedReason}`);
  else if (internal) output.push(`[200 OK] instance-role=hacklab-prod / access-key=${METADATA_SECRET}`);
  else output.push(`[200 OK] ${last?.status ?? "?"} (公開レスポンス)`);

  const loot: LootItem[] | undefined = internal
    ? [{ id: "ssrf-access-key", label: "メタデータ access-key", value: METADATA_SECRET }]
    : undefined;

  return {
    solved: internal,
    output,
    assembled: hops.map((h) => h.url.toString()).join("\n"),
    progress: debugLinkShown,
    benign: !internal && !last?.blockedReason && !last?.error,
    note: noteFor(level, hops, internal),
    recap: internal ? recapFor(level) : undefined,
    loot,
  };
}

export const ssrfRealLab: RealLab = { id: "ssrf", run };
