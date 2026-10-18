import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

/**
 * Cryptographic Failures (A02). A card vault treats encoding and a hardcoded
 * XOR as encryption. The ciphertext is shown to the learner; each level
 * changes the scheme so the previous blob no longer opens.
 */

export const PAN = "4242424242424242";

function xorByte(value: string, key: number): string {
  return [...value].map((c) => String.fromCharCode(c.charCodeAt(0) ^ key)).join("");
}

function xorRepeat(value: string, key: string): string {
  return [...value].map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ key.charCodeAt(i % key.length))).join("");
}

function revBlocks(value: string): string {
  let out = "";
  for (let i = 0; i < value.length; i += 4) out += [...value.slice(i, i + 4)].reverse().join("");
  return out;
}

function checksum(value: string): string {
  let n = 0;
  for (const c of value) n = (n + c.charCodeAt(0)) & 0xff;
  return n.toString(16).padStart(2, "0");
}

function b64e(value: string): string {
  return btoa(value);
}

function b64d(value: string): string | null {
  try {
    return atob(value);
  } catch {
    return null;
  }
}

const VAULT: Record<Level, string> = {
  1: b64e(PAN),
  2: `v2:${b64e(xorByte(PAN, 0x42))}`,
  3: `v3:${b64e(revBlocks(PAN))}`,
  4: (() => {
    const body = b64e(xorRepeat(PAN, "hunter2"));
    return `v4:${body}.${checksum(body)}`;
  })(),
  5: "v5:sealed-key-not-in-this-build",
};

export const CRYPTO_VAULT = VAULT;

function opened(plain: string | null): AttackResult {
  const solved = plain === PAN;
  return traced(
    {
      solved,
      output: solved ? [`card=${PAN}`, "保管庫を開きました。"] : ["復号に失敗しました。"],
      note: solved ? "弱い暗号（または符号化）が解け、カード番号が出ました。" : "このトークンはこのレベルの方式では開きません。",
    },
    plain === null ? "decrypt → invalid" : "decrypt(token)",
    solved ? { recap: ["保管庫のトークンを復号エンドポイントへ送った", "方式が可逆だった", "カード番号が平文で返った"], loot: [{ id: "crypto-pan", label: "カード番号", value: PAN }] } : undefined,
  );
}

function openToken(level: Level, token: string): string | null {
  if (level === 1) return b64d(token);
  if (level === 2) {
    if (!token.startsWith("v2:")) return null;
    const raw = b64d(token.slice(3));
    return raw === null ? null : xorByte(raw, 0x42);
  }
  if (level === 3) {
    if (!token.startsWith("v3:")) return null;
    const raw = b64d(token.slice(3));
    return raw === null ? null : revBlocks(raw);
  }
  if (level === 4) {
    const match = /^v4:(.+)\.([0-9a-f]{2})$/.exec(token);
    if (!match || checksum(match[1]) !== match[2]) return null;
    const raw = b64d(match[1]);
    return raw === null ? null : xorRepeat(raw, "hunter2");
  }
  return null;
}

function run(level: Level, input: LabInput): AttackResult {
  if ((input.action ?? "mine") !== "decrypt") {
    return traced(
      {
        solved: false,
        benign: true,
        output: ["カード（マスク）: ************4242", `vault=${VAULT[level]}`],
        note: "自分のカードの下4桁だけが見えています。",
      },
      "mask(card)",
    );
  }
  if (level === 5) {
    return traced(
      {
        solved: false,
        output: ["復号に失敗しました。", "server key はこのビルドに含まれていません。"],
        note: "認証付き暗号と、アプリに同梱しない鍵では、トークンを見せられても平文は出ません。",
      },
      "AES-GCM open(token, serverKey)",
    );
  }
  return opened(openToken(level, input.token ?? ""));
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。カード番号は Base64 で置いてあるだけ。",
    hints: [
      "画面の vault= は『暗号文』として表示されています。ソースではどう復号していますか？",
      "復号は Base64 を戻しているだけです。action を decrypt にするとその処理が走ります。",
      "表示されているトークンを token に入れ、action を decrypt にしてください。",
    ],
    solution: "action を `decrypt` にし、画面の vault トークン（Base64）を token に入れます。符号化は暗号化ではありません。",
    code: `const card = atob(token); // 「暗号化」と書いているが Base64`,
  },
  2: {
    defense: "v2: プレフィックスと、固定バイト 0x42 の XOR。",
    hints: [
      "Lv1 の Base64 はそのままでは v2 として解釈されません。",
      "ソースの鍵は 1 バイトです。XOR は同じ操作でもう一度かけると元に戻ります。",
      "画面の v2 トークンを、action=decrypt で送ってください。",
    ],
    solution: "画面の `v2:` トークンを decrypt します。鍵 0x42 がソースにあり、XOR は秘密になっていません。",
    code: `if (!token.startsWith("v2:")) reject();
const card = xor(atob(token.slice(3)), 0x42);`,
  },
  3: {
    defense: "v3: 4 文字ずつ反転してから Base64。XOR は廃止。",
    hints: [
      "v2 トークンはプレフィックス検査で落ちます。方式が変わっています。",
      "反転は暗号ではありません。もう一度反転すると元に戻ります。",
      "画面の v3 トークンを decrypt してください。",
    ],
    solution: "画面の `v3:` トークンを decrypt します。ブロック反転は鍵のない並べ替えです。",
    code: `const card = reverseBlocks(atob(token.slice(3)), 4);`,
  },
  4: {
    defense: "v4: パスフレーズ hunter2 の繰り返し XOR と、暗号文のチェックサム。",
    hints: [
      "チェックサムは平文ではなく Base64 本文の足し算です。誰でも再計算できます。",
      "パスフレーズはソースに書かれています。繰り返し XOR も可逆です。",
      "画面の v4 トークンを decrypt してください。",
    ],
    solution: "画面の `v4:` トークンを decrypt します。鍵がソースにあり、チェックサムは改ざん検知になっていません。",
    code: `const [body, sum] = token.slice(3).split(".");
if (checksum(body) !== sum) reject();
const card = xorRepeat(atob(body), "hunter2");`,
  },
  5: {
    defense: "認証付き暗号。鍵はサーバだけが持ち、トークンから復元できない。",
    hints: [
      "トークンをどう書き換えても、復号鍵はレスポンスにもソースの定数にもありません。",
      "これは、秘密データを『符号化』や『ソースに書いた鍵』で守らない、という対策です。",
    ],
    solution: "突破できません。カード番号は認証付き暗号で守られ、鍵はアプリに同梱しません。表示はマスクのままです。",
    code: `open(token, loadKeyFromKms()); // 鍵はこのリポジトリにない`,
  },
};

export const cryptoLab: Lab = {
  meta: {
    id: "crypto",
    title: "暗号の失敗 — カード番号の復元",
    shortTitle: "暗号の失敗",
    category: "暗号",
    objective: "保管庫のトークンから、マスクされていないカード番号を復元する。",
    summary: "Base64 やソースに書いた XOR を暗号化だと誤認している保管庫を開く。",
    standards: {
      owasp: { code: "A02:2021", name: "Cryptographic Failures", url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
      cwe: [
        { id: 327, name: "Use of a Broken or Risky Cryptographic Algorithm" },
        { id: 321, name: "Use of Hard-coded Cryptographic Key" },
      ],
    },
    references: [
      { title: "OWASP Cryptographic Failures", url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
      { title: "OWASP Cryptographic Storage Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html" },
    ],
  },
  fields: [
    { name: "action", label: "操作", default: "mine", mono: true },
    { name: "token", label: "token", default: "", mono: true, hidden: true },
  ],
  explanation: `暗号の失敗は、秘密データを平文や弱い方式で保存し、鍵をソースに書くことで起きます。Base64 は誰でも戻せます。固定バイトの XOR や、ブロックをひっくり返す処理も暗号ではありません。チェックサムを自分で計算できるなら、改ざん検知にもなりません。

このラボの保管庫は、レベルごとに『それっぽい』方式へ変わります。前のトークンは次のレベルでは形式が違うので通りません。ソースに書いた手順は、同じ手順で逆にできます。

根本対策は Lv5 です。認証付き暗号を使い、鍵はアプリに同梱せず、カード番号は画面に必要最小限だけ出します。`,
  levels,
  run,
  exploits: {
    1: { action: "decrypt", token: VAULT[1] },
    2: { action: "decrypt", token: VAULT[2] },
    3: { action: "decrypt", token: VAULT[3] },
    4: { action: "decrypt", token: VAULT[4] },
  },
};
