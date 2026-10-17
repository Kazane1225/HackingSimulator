import type { AttackResult, LabInput, Level, RealLab } from "./runner.js";

/**
 * Real cryptographic-failures target. The vault token is reversible encoding
 * (Base64, a fixed XOR, a block swap, a passphrase that ships in the source).
 * Lv5 keeps the key out of the process and never returns the PAN.
 */

const PAN = "4242424242424242";

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
  return Buffer.from(value, "latin1").toString("base64");
}

function b64d(value: string): string | null {
  if (value.length === 0 || value.length % 4 !== 0 || /[^A-Za-z0-9+/=]/.test(value)) return null;
  return Buffer.from(value, "base64").toString("latin1");
}

export const CRYPTO_VAULT: Record<Level, string> = {
  1: b64e(PAN),
  2: `v2:${b64e(xorByte(PAN, 0x42))}`,
  3: `v3:${b64e(revBlocks(PAN))}`,
  4: (() => {
    const body = b64e(xorRepeat(PAN, "hunter2"));
    return `v4:${body}.${checksum(body)}`;
  })(),
  5: "v5:sealed-key-not-in-this-build",
};

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
    return {
      solved: false,
      benign: true,
      output: ["カード（マスク）: ************4242", `vault=${CRYPTO_VAULT[level]}`],
    };
  }
  if (level === 5) {
    return {
      solved: false,
      output: ["復号に失敗しました。", "server key はこのビルドに含まれていません。"],
    };
  }
  const plain = openToken(level, input.token ?? "");
  const solved = plain === PAN;
  return {
    solved,
    output: solved ? [`card=${PAN}`, "保管庫を開きました。"] : ["復号に失敗しました。"],
  };
}

export const cryptoRealLab: RealLab = { id: "crypto", run };
