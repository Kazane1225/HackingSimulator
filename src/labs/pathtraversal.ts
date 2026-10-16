import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

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
  "/var/www/files/readme.txt":
    "ようこそ。ここは公開ファイル置き場です。\n機密バックアップは /var/www/secret/flag.txt にあります（このフォルダの外です）。",
  "/var/www/files/notice.txt": "メンテナンスは毎週日曜に実施します。",
  "/var/www/secret/flag.txt": FLAG,
  "/etc/passwd":
    "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nalice:x:1000:1000:Alice:/home/alice:/bin/bash",
};

const TARGET = "/etc/passwd";
const SECRET = "/var/www/secret/flag.txt";

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

/**
 * Node-style join: an absolute second argument discards the base.
 * `path.join("/var/www/files", "/etc/passwd")` → `/etc/passwd`.
 */
function pathJoin(base: string, name: string): string {
  const trimmed = name.replace(/\\/g, "/");
  if (trimmed.startsWith("/")) return normalize(trimmed);
  return normalize(`${base}/${trimmed}`);
}

function truncateNull(s: string): string {
  const i = s.indexOf("\0");
  return i === -1 ? s : s.slice(0, i);
}

function readResult(raw: string, resolved: string, extra: string[] | undefined, target: string): AttackResult {
  const assembled = [...(extra ?? []), `readFile(${resolved})`].join("\n");
  const output = [`requested : ${raw}`, ...(extra ?? []), `resolved  : ${resolved}`, ""];
  const content = FS[resolved];
  if (content === undefined) {
    output.push(`404: ${resolved} not found`);
    return traced({ solved: false, output, note: "そのパスにファイルはありません。" }, assembled);
  }
  output.push(content);
  const loot =
    resolved === SECRET ? [{ id: "path-flag", label: "flag.txt", value: FLAG }] : undefined;
  const solved = resolved === target;
  const progress =
    !solved && (resolved === `${BASE}/readme.txt` || (resolved === TARGET && target === SECRET));
  const note = solved
    ? `ベースディレクトリを脱出し、${target} を読み出しました。`
    : resolved === "/etc/passwd" && target !== TARGET
      ? "passwd は読めました。readme が指していた秘密ファイルはまだです。"
      : "ファイルは読めましたが、目標ではありません。";
  return traced(
    { solved, output, note, progress },
    assembled,
    solved
      ? {
          recap: ["公開フォルダの外を指すパスになった", `path.join / 正規化の結果が ${resolved}`, "秘密ファイルの中身が返った"],
          loot,
        }
      : { loot },
  );
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

  if (level === 4) {
    const decoded = decodeOnce(raw);
    if (decoded.includes("..")) {
      return traced(
        {
          solved: false,
          output: [`requested : ${raw}`, "DENY: path contains '..'"],
          note: "`..` を含むパスは拒否されました。readme.txt が指す場所を、絶対パスで開けますか？",
        },
        `reject: ${raw} contains ..`,
      );
    }
    const resolved = pathJoin(BASE, decoded);
    return readResult(raw, resolved, [`joined    : path.join("${BASE}", ${JSON.stringify(decoded)})`], SECRET);
  }

  if (level === 3) {
    if (!/\.txt$/i.test(raw)) {
      return {
        solved: false,
        output: [`requested : ${raw}`, "DENY: only .txt is allowed"],
        note: "拡張子の許可リストに一致しません。検査はどの文字列に対して行われていますか？",
      };
    }
    const decoded = truncateNull(decodeOnce(raw));
    const resolved = normalize(`${BASE}/${decoded}`);
    return readResult(raw, resolved, decoded !== raw ? [`decoded   : ${decoded}`] : undefined, TARGET);
  }

  const filtered = level === 2 ? raw.replace(/\.\.\//g, "") : raw;
  const decoded = decodeOnce(filtered);
  const resolved = normalize(`${BASE}/${decoded}`);
  const extra: string[] = [];
  if (filtered !== raw) extra.push(`filtered  : ${filtered}`);
  if (decoded !== filtered) extra.push(`decoded   : ${decoded}`);
  return readResult(raw, resolved, extra, TARGET);
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。BASE + '/' + 入力 をそのまま読み込む。",
    hints: [
      "「ソース」を読みましょう。ベースディレクトリと入力はどのように結合されますか？",
      "読み込みは公開フォルダ基準です。1 つ上の階層へ移動する記法は？",
      "`../` を何度か重ねて、ルートまで遡りましょう。目標は `/etc/passwd` です。",
    ],
    solution:
      "name に `../../../etc/passwd` を入力。`..` でベースディレクトリより上に遡れます。",
    code: `const path = BASE + "/" + req.query.name;
res.send(fs.readFileSync(path));`,
  },
  2: {
    defense: "`../` を除去する（ただし 1 回だけ）。",
    hints: [
      "Lv1 の入力は通りません。「ソース」で、除去が『何回』行われるかを確認しましょう。",
      "`../` は消されます…が、フィルタは一度しか走りません。除去後に `../` が再生成される入力は？",
      "`....//` の中央にある `../` が 1 回除去されると、何が残りますか？",
    ],
    solution:
      "name に `....//....//....//etc/passwd` を入力。`....//` の中央の `../` が 1 回だけ除去され `../` が復活します。",
    code: `let name = req.query.name.replace(/\\.\\.\\//g, ""); // 1回だけ
const path = BASE + "/" + name;`,
  },
  3: {
    defense: "拡張子 `.txt` だけを許可する。検査はデコード・ヌルバイト切断の前。",
    hints: [
      "Lv2 の `../` 細工は、末尾が `.txt` でないと拒否されます。許可リストに切り替わっています。",
      "検査に通ったあと、パスはデコードされます。検査用の拡張子と、実際に開く名前を分けられませんか？",
      "ファイル名を途中で切る制御文字（ヌルバイト `%00`）を、`.txt` の直前に置けますか？",
    ],
    solution:
      "name に `../../../etc/passwd%00.txt` を入力。検査は `.txt` で通り、その後 `%00` がヌルになり `../../../etc/passwd` だけが開かれます。",
    code: `if (!name.endsWith(".txt")) deny(); // デコード前
const path = BASE + "/" + decodeURIComponent(name);
// C の API は \\0 以降を無視することがある`,
  },
  4: {
    defense: "`..` を拒否し、残った名前を `path.join(BASE, name)` で結合する。",
    hints: [
      "`../` もヌルバイトも通りません。先に公開の `readme.txt` を開きましょう。",
      "join は第 2 引数が絶対パスだとベースを捨てます。秘密ファイルのフルパスをそのまま渡せますか？",
      "readme に書いてあった `/var/www/secret/flag.txt` を name に入れます。",
    ],
    solution:
      "公開の readme.txt で秘密パスを知り、name に `/var/www/secret/flag.txt` を入力します。`path.join(BASE, \"/var/www/secret/flag.txt\")` は絶対パス側だけ残します。",
    code: `if (name.includes("..")) deny();
const path = path.join(BASE, name);
res.send(fs.readFileSync(path));`,
  },
  5: {
    defense: "デコード後に正規化し、最終パスがベース配下か検証する。",
    hints: [
      "正規化してからベース配下かを確認しています。これは正しい対策です。",
      "「ソース」を読み、『デコード → 正規化 → ベース配下か検証』の順序がなぜ重要かを考えましょう。",
    ],
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
    summary: "ファイル名パラメータに ../ などを注入し、ベースディレクトリの外を読む。",
    standards: {
      owasp: {
        code: "A01:2021",
        name: "Broken Access Control",
        url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control",
      },
      cwe: [{ id: 22, name: "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)" }],
    },
    references: [
      { title: "OWASP Path Traversal", url: "https://community.owasp.org/attacks/Path_Traversal" },
      { title: "PortSwigger Web Security Academy — Path traversal", url: "https://portswigger.net/web-security/file-path-traversal" },
      { title: "IPA 安全なウェブサイトの作り方", url: "https://www.ipa.go.jp/security/vuln/websecurity/" },
    ],
  },
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

このラボは公開フォルダ \`${BASE}\` を基準にファイルを返します。基準を脱出し、\`/etc/passwd\` を読み出せればクリアです。

レベルが上がると、部分文字列の除去、拡張子の許可リスト、\`path.join\` と対策の種類が変わります。許可リストはデコード前だとヌルバイトで切れ、join は絶対パスでベースを捨てます。Lv4 では公開 readme が秘密パスを漏らします。禁止文字列を増やすことでは止まりません。

根本対策は Lv5 です。入力をデコード・正規化して「解決後の絶対パス」を求め、それが許可されたベースディレクトリ配下にあるかを検証します。`,
  levels,
  run,
  exploits: {
    1: { name: "../../../etc/passwd" },
    2: { name: "....//....//....//etc/passwd" },
    3: { name: "../../../etc/passwd%00.txt" },
    4: { name: "/var/www/secret/flag.txt" },
  },
};
