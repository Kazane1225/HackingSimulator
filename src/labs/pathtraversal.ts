import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";

/**
 * Simulated Path Traversal lab (a "view file" endpoint).
 *
 * The app serves files from a base directory: readFile(BASE + "/" + name).
 * We model a virtual filesystem keyed by canonical absolute paths and a path
 * normalizer that understands both "/" and "\\" separators. Objective: escape
 * the base directory and read /etc/passwd.
 */

const BASE = "/var/www/files";
const FLAG = "FLAG{p4th_tr4v3rs4l}";

const FS: Record<string, string> = {
  "/var/www/files/readme.txt": "ようこそ。ここは公開ファイル置き場です。",
  "/var/www/files/notice.txt": "メンテナンスは毎週日曜に実施します。",
  "/var/www/secret/flag.txt": FLAG,
  "/etc/passwd":
    "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nalice:x:1000:1000:Alice:/home/alice:/bin/bash",
};

const TARGET = "/etc/passwd";

function stripRecursive(s: string, re: RegExp): string {
  let prev: string;
  do {
    prev = s;
    s = s.replace(re, "");
  } while (s !== prev);
  return s;
}

/** Decode %XX escapes exactly once, leaving malformed sequences untouched. */
function decodeOnce(s: string): string {
  return s.replace(/%[0-9a-fA-F]{2}/g, (m) =>
    String.fromCharCode(parseInt(m.slice(1), 16)),
  );
}

/** Resolve "." / ".." against both separators into a canonical /-path. */
function normalize(path: string): string {
  const isAbs = /^[\\/]/.test(path);
  const stack: string[] = [];
  for (const part of path.split(/[\\/]+/)) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (stack.length) stack.pop();
      continue;
    }
    stack.push(part);
  }
  return (isAbs ? "/" : "") + stack.join("/");
}

/** Filter the raw (still URL-encoded) name according to the level. */
function filterName(level: Level, s: string): string {
  if (level === 1) return s;
  if (level === 2) return s.replace(/\.\.\//g, ""); // single pass, forward slash
  if (level === 3) return stripRecursive(s, /\.\.\//g); // recursive, forward slash
  if (level === 4) return stripRecursive(s, /\.\.[\\/]/g); // recursive, both slashes
  return s; // level 5 canonicalizes + checks containment (see run)
}

function run(level: Level, input: LabInput): AttackResult {
  const raw = input.name ?? "";
  const output: string[] = [];

  if (level === 5) {
    const decoded = decodeOnce(raw);
    const resolved = normalize(`${BASE}/${decoded}`);
    output.push(`requested : ${raw}`);
    output.push(`canonical : ${resolved}`);
    const inside = resolved === BASE || resolved.startsWith(`${BASE}/`);
    if (!inside) {
      output.push(`DENY: ${resolved} はベースディレクトリ ${BASE} の外です`);
      return {
        solved: false,
        output,
        note: "正規化後のパスがベース配下か検証しているため、脱出できません。",
      };
    }
    output.push("");
    output.push(FS[resolved] ?? `404: ${resolved} not found`);
    return {
      solved: false,
      output,
      note: "ベース配下のファイルのみ提供。トラバーサルは拒否されます。",
    };
  }

  const filtered = filterName(level, raw);
  const decoded = decodeOnce(filtered);
  const resolved = normalize(`${BASE}/${decoded}`);

  output.push(`requested : ${raw}`);
  if (filtered !== raw) output.push(`filtered  : ${filtered}`);
  if (decoded !== filtered) output.push(`decoded   : ${decoded}`);
  output.push(`resolved  : ${resolved}`);
  output.push("");

  const content = FS[resolved];
  if (content === undefined) {
    output.push(`404: ${resolved} not found`);
    return { solved: false, output, note: "そのパスにファイルはありません。" };
  }

  output.push(content);
  const solved = resolved === TARGET;
  return {
    solved,
    output,
    note: solved
      ? "ベースディレクトリを脱出し、/etc/passwd の読み出しに成功しました。"
      : "ファイルは読めましたが、目標 (/etc/passwd) ではありません。",
  };
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。BASE + '/' + 入力 をそのまま読み込む。",
    hint: "読み込みは公開フォルダ基準です。1 つ上の階層へ移動する記法は？",
    solution:
      "name に `../../../etc/passwd` を入力。`..` でベースディレクトリより上に遡れます。",
    code: `const path = BASE + "/" + req.query.name;
res.send(fs.readFileSync(path));`,
  },
  2: {
    defense: "`../` を除去する（ただし 1 回だけ）。",
    hint: "`../` は消されます…が、フィルタは一度しか走りません。除去後に `../` が再生成される入力は？",
    solution:
      "name に `....//....//....//etc/passwd` を入力。`....//` の中央の `../` が 1 回だけ除去され `../` が復活します。",
    code: `let name = req.query.name.replace(/\\.\\.\\//g, ""); // 1回だけ
const path = BASE + "/" + name;`,
  },
  3: {
    defense: "`../` を繰り返し除去する（冪等）。",
    hint: "前方スラッシュの `../` は完全に消えます。でもパスの区切りは `/` だけでしょうか？",
    solution:
      "name に `..\\..\\..\\etc\\passwd` を入力。バックスラッシュ区切りはフィルタ対象外ですが、OS はこれも区切りとして解釈します。",
    code: `const strip = s => { let p; do { p = s;
  s = s.replace(/\\.\\.\\//g, ""); } while (s !== p); return s; };
const path = BASE + "/" + strip(req.query.name);`,
  },
  4: {
    defense: "`../` と `..\\` を繰り返し除去する。ただしフィルタは URL デコード前に走る。",
    hint: "両方のスラッシュが消されます。でもフィルタが見ているのは『デコード前』の文字列。エンコードして隠せませんか？",
    solution:
      "name に `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd` を入力。`%2e%2e%2f` はフィルタをすり抜け、後段のデコードで `../` に戻ります。",
    code: `let name = strip(req.query.name); // ← デコード前に除去
name = decodeURIComponent(name);  // 除去後にデコードしてしまう
const path = BASE + "/" + name;`,
  },
  5: {
    defense: "デコード後に正規化し、最終パスがベース配下か検証する。",
    hint: "正規化してからベース配下かを確認しています。これは正しい対策です。",
    solution:
      "このレベルは意図的に突破不可能です。先にデコード・正規化（canonicalize）してから、解決後の絶対パスがベースディレクトリ配下にあることを検証します。脱出するパスはすべて拒否されます。",
    code: `const name = decodeURIComponent(req.query.name);
const resolved = path.resolve(BASE, name);
if (!resolved.startsWith(BASE + path.sep)) throw new Error("denied");
res.send(fs.readFileSync(resolved));`,
  },
};

export const pathTraversalLab: Lab = {
  meta: {
    id: "path",
    title: "パストラバーサル — ファイル閲覧機能",
    shortTitle: "パストラバーサル",
    category: "不適切なアクセス制御",
    objective: "公開フォルダを脱出し、/etc/passwd を読み出す。",
    summary: "ファイル名パラメータに ../ などを注入し、ベースディレクトリの外を読む。",  },
  fields: [
    {
      name: "name",
      label: "ファイル名",
      placeholder: "readme.txt",
      mono: true,
      default: "readme.txt",
    },
  ],
  explanation: `パストラバーサル（ディレクトリトラバーサル）は、ファイル名やパスをユーザーが指定でき、アプリがそれを検証せずにファイルパスへ連結するときに起こります。\`../\` を使って基準ディレクトリより上の階層へ遡り、本来アクセスできない設定ファイルや認証情報（例: /etc/passwd、秘密鍵、ソースコード）を読み出せてしまいます。

このラボは公開フォルダ \`${BASE}\` を基準にファイルを返します。\`../\` やその亜種を使って基準を脱出し、\`/etc/passwd\` を読み出せればクリアです。

レベルが上がると「\`../\` を消す」といった対策が入りますが、非冪等な除去（\`....//\`）、別の区切り文字（\`..\\\`）、URL エンコード（\`%2e%2e%2f\`）などで次々と回避されます。文字列の除去（ブラックリスト）はパス解釈の多様さに追いつけません。

根本対策は Lv5 です。入力をデコード・正規化して「解決後の絶対パス」を求め、それが許可されたベースディレクトリ配下にあるかを検証します。パスの意味を OS と同じ基準で確定させてから判定するのが正解です。`,
  levels,
  run,
};
