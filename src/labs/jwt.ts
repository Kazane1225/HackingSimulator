import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";

export function encodeJwtPart(value: object): string {
  return btoa(JSON.stringify(value)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

export function makeJwt(header: object, payload: object, signature: string): string {
  return `${encodeJwtPart(header)}.${encodeJwtPart(payload)}.${signature}`;
}

export function decodeJwtPart(part: string): Record<string, unknown> | null {
  try {
    const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=")));
  } catch {
    return null;
  }
}

const USER_TOKEN = makeJwt({ alg: "RS256", typ: "JWT", kid: "key-2026" }, { sub: "alice", role: "user" }, "valid-user-signature");
const NONE_TOKEN = makeJwt({ alg: "none", typ: "JWT" }, { sub: "attacker", role: "admin" }, "");
const WEAK_TOKEN = makeJwt({ alg: "HS256", typ: "JWT" }, { sub: "attacker", role: "admin" }, "weak-secret-signature");
const UNVERIFIED_TOKEN = makeJwt({ alg: "RS256", typ: "JWT" }, { sub: "attacker", role: "admin" }, "anything");
const KID_TOKEN = makeJwt(
  { alg: "RS256", typ: "JWT", kid: "../../uploads/attacker.pem" },
  { sub: "attacker", role: "admin" },
  "attacker-key-signature",
);

function run(level: Level, input: LabInput): AttackResult {
  const token = (input.token ?? "").trim();
  const [head = "", body = "", signature = ""] = token.split(".");
  const header = decodeJwtPart(head);
  const payload = decodeJwtPart(body);
  if (!header || !payload) {
    return { solved: false, output: ["[401] JWT の形式が不正です。"], note: "header.payload.signature の形式を確認してください。" };
  }

  const isAdmin = payload.role === "admin";
  let accepted = false;
  let reason = "";
  if (level === 1) {
    accepted = header.alg === "none" && signature === "" && isAdmin;
    reason = "alg をトークンから信用し、none を許可しています。";
  } else if (level === 2) {
    accepted = header.alg === "HS256" && signature === "weak-secret-signature" && isAdmin;
    reason = "署名鍵 `secret` が辞書攻撃で推測されました。";
  } else if (level === 3) {
    accepted = header.alg === "RS256" && signature.length > 0 && isAdmin;
    reason = "署名の存在だけを確認し、暗号学的な検証をしていません。";
  } else if (level === 4) {
    accepted =
      header.alg === "RS256" &&
      header.kid === "../../uploads/attacker.pem" &&
      signature === "attacker-key-signature" &&
      isAdmin;
    reason = "kid のパストラバーサルにより攻撃者の公開鍵を読み込みました。";
  } else {
    reason = "固定アルゴリズム・許可済み kid・信頼済み鍵による署名検証で拒否しました。";
  }

  return {
    solved: accepted,
    output: [
      `header : ${JSON.stringify(header)}`,
      `payload: ${JSON.stringify(payload)}`,
      accepted ? `[200 OK] /admin — ${String(payload.sub)} (admin)` : `[401 INVALID TOKEN] ${reason}`,
    ],
    note: accepted ? "改ざんした JWT で管理者権限を取得しました。" : reason,
  };
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
      "署名があっても、共有秘密鍵が弱ければオフラインで試行できます。",
      "よく使われる鍵 `secret` が辞書から見つかりました。",
      "HS256・role=admin で署名し直した模擬トークンを使います。",
    ],
    solution: `弱い鍵で署名した模擬トークン:\n\`${WEAK_TOKEN}\``,
    code: `jwt.verify(token, "secret", { algorithms: ["HS256"] }); // 推測可能な固定鍵`,
  },
  3: {
    defense: "RS256 に固定したが、署名文字列の存在しか確認しない。",
    hints: [
      "長い署名が付いていることと、正しく検証したことは別です。",
      "payload を変更し、署名欄には任意の文字列を残します。",
      "RS256・role=admin・署名 `anything` のトークンを送ります。",
    ],
    solution: `署名未検証を突く模擬トークン:\n\`${UNVERIFIED_TOKEN}\``,
    code: `const [h, p, sig] = token.split(".");
if (!sig) deny();
return JSON.parse(base64urlDecode(p)); // verify() を呼んでいない`,
  },
  4: {
    defense: "RS256 署名を検証するが、kid を無検証で鍵ファイルのパスに連結する。",
    hints: [
      "header の kid は署名検証に使う鍵を選びます。",
      "kid から任意のファイルを選べると、攻撃者の鍵を参照できます。",
      "`kid=../../uploads/attacker.pem` で攻撃者鍵を選択します。",
    ],
    solution: `攻撃者の公開鍵を選ばせる模擬トークン:\n\`${KID_TOKEN}\``,
    code: `const key = fs.readFileSync("/keys/" + header.kid); // パスを直接連結
jwt.verify(token, key, { algorithms: ["RS256"] });`,
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
    summary: "alg:none、弱い鍵、署名未検証、kid の悪用を段階的に試す。",
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

トークン自身が宣言する alg を無条件に信用せず、none を拒否します。HMAC 鍵には十分なランダム性を持たせ、kid はパスとして連結せず許可済みキー ID から選びます。署名に加えて issuer、audience、期限などのクレームも検証します。`,
  levels,
  run,
  exploits: {
    1: { token: NONE_TOKEN },
    2: { token: WEAK_TOKEN },
    3: { token: UNVERIFIED_TOKEN },
    4: { token: KID_TOKEN },
  },
};
