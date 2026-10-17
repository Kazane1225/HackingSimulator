import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { hmacSha256Hex, sha256Hex } from "./sha256";
import { traced } from "./trace";

/**
 * Software and Data Integrity Failures (A08). An update manifest is trusted
 * with no signature, then a hash with no key, then an HMAC whose key is in
 * the source, then an HMAC that does not cover `role`.
 */

const FLAG = "FLAG{uns1gn3d_upd4te}";
const KEY = "build";
const USER = '{"name":"app","version":"1","role":"user"}';
const ADMIN = '{"name":"app","version":"1","role":"admin"}';
const PARTIAL = "name=app\nversion=1";

interface Manifest {
  name: string;
  version: string;
  role: string;
}

function parseManifest(raw: string): Manifest | null {
  try {
    const value = JSON.parse(raw) as unknown;
    if (!value || typeof value !== "object") return null;
    const rec = value as Record<string, unknown>;
    if (typeof rec.name !== "string" || typeof rec.version !== "string" || typeof rec.role !== "string") return null;
    return { name: rec.name, version: rec.version, role: rec.role };
  } catch {
    return null;
  }
}

function partial(manifest: Manifest): string {
  return `name=${manifest.name}\nversion=${manifest.version}`;
}

function publishedSig(level: Level): string | null {
  if (level === 1) return null;
  if (level === 2) return sha256Hex(USER);
  if (level === 3) return hmacSha256Hex(KEY, USER);
  if (level === 4) return hmacSha256Hex(KEY, PARTIAL);
  return null;
}

function run(level: Level, input: LabInput): AttackResult {
  const raw = input.manifest ?? "";
  const signature = (input.signature ?? "").trim();
  const manifest = parseManifest(raw);
  const published = publishedSig(level);
  const lines = published ? [`published-sig=${published}`] : level === 5 ? ["server key はこのビルドに含まれていません。"] : ["署名は検査していません。"];

  if (level === 5) {
    return traced(
      {
        solved: false,
        output: ["署名を検証できません。", ...lines],
        note: "更新データ全体を、アプリに同梱しない鍵で検証しています。",
      },
      "HMAC(name, version, role, serverKey)",
    );
  }

  if (!manifest) {
    return traced({ solved: false, output: ["マニフェストを読めません。", ...lines], note: "JSON として読めるマニフェストが必要です。" }, "parse(manifest)");
  }

  let signed = false;
  if (level === 1) signed = true;
  else if (level === 2) signed = signature === sha256Hex(raw);
  else if (level === 3) signed = signature === hmacSha256Hex(KEY, raw);
  else signed = signature === hmacSha256Hex(KEY, partial(manifest));

  if (!signed) {
    return traced({ solved: false, output: ["署名が一致しません。", ...lines], note: "署名が、このレベルの対象と一致しません。" }, "verify(manifest)");
  }

  const solved = manifest.role === "admin";
  return traced(
    {
      solved,
      benign: !solved,
      output: [`name=${manifest.name}`, `version=${manifest.version}`, `role=${manifest.role}`, ...(solved ? [FLAG] : lines)],
      note: solved ? "role=admin の更新を受け入れました。" : "公開ビルドのまま適用しました。",
    },
    "apply(manifest)",
    solved ? { recap: ["マニフェストの完全性検査をすり抜けた", "role=admin が適用された"], loot: [{ id: "integrity-flag", label: "適用された更新", value: FLAG }] } : undefined,
  );
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。role=admin なら署名なしで適用する。",
    hints: [
      "更新マニフェストの role を見てください。署名は空でも処理されます。",
      "ソースは role が admin なら適用します。署名の検査はありません。",
      "manifest の role を `admin` にしてください。",
    ],
    solution: 'manifest を `{"name":"app","version":"1","role":"admin"}` にします。署名は見ていません。',
    code: `if (manifest.role === "admin") apply(manifest); // signature は未使用`,
  },
  2: {
    defense: "マニフェスト文字列の SHA-256 と signature が一致するときだけ適用する。鍵はない。",
    hints: [
      "Lv1 のままでは署名が足りません。本文のハッシュは誰でも計算できます。",
      "鍵はありません。SHA-256 の入力はマニフェスト文字列そのものです。",
      "role を admin にした JSON の SHA-256 を signature に入れてください。",
    ],
    solution: "admin の JSON を SHA-256 した値を signature にします。鍵がないダイジェストは、改ざんした側が計算し直せます。",
    code: `if (signature !== sha256(manifestText)) reject();`,
  },
  3: {
    defense: "HMAC-SHA256。鍵はソースの定数 build。",
    hints: [
      "ハッシュだけだと拒否されます。HMAC の鍵がソースにあります。",
      "鍵は `build` です。本文全体に HMAC-SHA256 をかけてください。",
      "admin のマニフェストを、鍵 build で HMAC した値を signature にしてください。",
    ],
    solution: "鍵 `build` で admin の JSON 全体を HMAC-SHA256 します。鍵がソースにある署名は秘密になっていません。",
    code: `if (signature !== hmacSha256(manifestText, "build")) reject();`,
  },
  4: {
    defense: "HMAC の対象は name と version だけ。role は署名に入っていない。",
    hints: [
      "本文全体の HMAC はもう一致しません。署名対象が狭くなっています。",
      "応答の published-sig は、公開ビルドの name と version だけの署名です。",
      "name と version はそのまま、role を admin にし、published-sig を signature に入れてください。",
    ],
    solution: "公開ビルドの published-sig を使い、role だけ admin に変えます。署名が覆っていない項目は書き換わっても通ります。",
    code: `const covered = "name=" + manifest.name + "\\nversion=" + manifest.version;
if (signature !== hmacSha256(covered, "build")) reject();
apply(manifest.role); // role は署名対象の外`,
  },
  5: {
    defense: "name・version・role 全部を、プロセスだけの鍵で HMAC する。",
    hints: [
      "published-sig を role だけ変えて使い回しても、検証は通りません。",
      "これは、更新データ全体を認証し、鍵をアプリに置かない対策です。",
    ],
    solution: "突破できません。マニフェスト全体を署名し、鍵は応答にもソースの定数にも出しません。",
    code: `if (!hmacSha256(canonical(manifest), loadKeyFromKms())) reject();`,
  },
};

export const integrityLab: Lab = {
  meta: {
    id: "integrity",
    title: "データ完全性の失敗 — 署名のない更新",
    shortTitle: "署名なし更新",
    category: "完全性",
    objective: "更新マニフェストを role=admin として適用させる。",
    summary: "署名なし、鍵のないハッシュ、ソースに書いた HMAC 鍵、署名対象の外にある role を順に使う。",
    standards: {
      owasp: {
        code: "A08:2021",
        name: "Software and Data Integrity Failures",
        url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
      },
      cwe: [
        { id: 345, name: "Insufficient Verification of Data Authenticity" },
        { id: 347, name: "Improper Verification of Cryptographic Signature" },
      ],
    },
    references: [
      { title: "OWASP Software and Data Integrity Failures", url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/" },
      { title: "OWASP Deserialization Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html" },
    ],
  },
  fields: [
    { name: "manifest", label: "manifest", default: USER, mono: true, multiline: true },
    { name: "signature", label: "signature", default: "", mono: true, hidden: true },
  ],
  explanation: `ソフトウェアとデータの完全性の失敗は、更新内容が改ざんされていないことを確認しないまま適用することで起きます。署名が無ければ role は書き換えるだけです。SHA-256 は鍵がないので、改ざんした本文のハッシュを自分で計算できます。HMAC でも鍵がソースにあれば同じです。

署名が name と version だけを覆っていると、role は検査の外です。公開ビルドの署名を、role だけ変えたマニフェストに付け直せます。

根本対策は Lv5 です。name、version、role の全部を署名対象にし、鍵はアプリに同梱しません。`,
  levels,
  run,
  exploits: {
    1: { manifest: ADMIN, signature: "" },
    2: { manifest: ADMIN, signature: sha256Hex(ADMIN) },
    3: { manifest: ADMIN, signature: hmacSha256Hex(KEY, ADMIN) },
    4: { manifest: ADMIN, signature: hmacSha256Hex(KEY, PARTIAL) },
  },
};
