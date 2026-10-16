import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

/**
 * Simulated OS Command Injection lab (a "ping" diagnostics tool).
 *
 * A naive app builds `ping -c 1 <host>` and runs it through a shell. We
 * implement a tiny shell (quoted separators + command substitution) over a tiny
 * virtual filesystem. Objective: read the contents of flag.txt.
 */

const FLAG = "FLAG{c0mmand_1nj3ct10n}";

const FS: Record<string, string> = {
  "flag.txt": FLAG,
  "/etc/passwd":
    "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
};

function stripRecursive(s: string, re: RegExp): string {
  let prev: string;
  do {
    prev = s;
    s = s.replace(re, "");
  } while (s !== prev);
  return s;
}

// --- Tiny shell ------------------------------------------------------------

function runCommand(cmd: string): string {
  const parts = cmd.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "";
  const name = parts[0];
  switch (name) {
    case "ping": {
      const host = parts[parts.length - 1];
      return `PING ${host}: 56 data bytes\n64 bytes from ${host}: icmp_seq=0 time=11.4 ms`;
    }
    case "cat": {
      const file = parts[1] ?? "";
      const key = file.replace(/^\.\//, "");
      if (file in FS) return FS[file];
      if (key in FS) return FS[key];
      return `cat: ${file}: No such file or directory`;
    }
    case "ls":
      return "etc\nflag.txt\nindex.php";
    case "id":
      return "uid=33(www-data) gid=33(www-data) groups=33(www-data)";
    case "whoami":
      return "www-data";
    default:
      return `sh: ${name}: command not found`;
  }
}

type Quote = "'" | '"' | null;

/** Expand `$(...)` and backticks, but not inside single quotes. */
function expandSubstitutions(line: string, exec: (c: string) => string): string {
  let out = "";
  let i = 0;
  let quote: Quote = null;
  while (i < line.length) {
    const c = line[i];
    if (quote === null && (c === "'" || c === '"')) {
      quote = c;
      out += c;
      i++;
      continue;
    }
    if (quote && c === quote) {
      quote = null;
      out += c;
      i++;
      continue;
    }
    if (quote !== "'" && c === "$" && line[i + 1] === "(") {
      let depth = 1;
      let j = i + 2;
      while (j < line.length && depth > 0) {
        if (line[j] === "(") depth++;
        else if (line[j] === ")") depth--;
        j++;
      }
      out += exec(line.slice(i + 2, j - 1)).trim();
      i = j;
      continue;
    }
    if (quote !== "'" && c === "`") {
      const j = line.indexOf("`", i + 1);
      if (j !== -1) {
        out += exec(line.slice(i + 1, j)).trim();
        i = j + 1;
        continue;
      }
    }
    out += c;
    i++;
  }
  return out;
}

const SEPS = ["&&", "||", "\n", "\r", ";", "|", "&"];

function splitUnquoted(line: string): string[] {
  const segs: string[] = [];
  let cur = "";
  let quote: Quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote === null && (c === "'" || c === '"')) {
      quote = c;
      cur += c;
      continue;
    }
    if (quote && c === quote) {
      quote = null;
      cur += c;
      continue;
    }
    if (quote === null) {
      const sep = SEPS.find((s) => line.startsWith(s, i));
      if (sep) {
        if (cur.trim()) segs.push(cur.trim());
        cur = "";
        i += sep.length - 1;
        continue;
      }
    }
    cur += c;
  }
  if (cur.trim()) segs.push(cur.trim());
  return segs;
}

/** Run a full command line (quoted separators + substitution), returning stdout. */
function execLine(line: string, exec: (c: string) => string): string[] {
  return splitUnquoted(expandSubstitutions(line, exec)).map((seg) => exec(seg));
}

function wrapHost(level: Level, host: string): string {
  if (level === 1) return `ping -c 1 ${host}`;
  if (level === 2) return `ping -c 1 ${stripRecursive(host, /;/g)}`;
  if (level === 3) return `ping -c 1 "${host}"`;
  return `ping -c 1 '${host}'`;
}

function run(level: Level, input: LabInput): AttackResult {
  const rawHost = input.host ?? "";
  const output: string[] = [];

  if (level === 5) {
    output.push("// 入力をシェルに渡す前に厳格に検証");
    const valid = /^[A-Za-z0-9.\-]+$/.test(rawHost);
    if (!valid) {
      output.push(`reject: "${rawHost}" はホスト名/IP として不正です`);
      return {
        solved: false,
        output,
        note: "許可文字のみのホスト名だけを受け付け、シェルを経由しません。注入の余地がありません。",
      };
    }
    output.push(`exec(["ping", "-c", "1", ${JSON.stringify(rawHost)}])  // 配列で直接実行`);
    output.push(runCommand(`ping -c 1 ${rawHost}`));
    return {
      solved: false,
      output,
      note: "正当なホスト名のため ping のみ実行。コマンド注入はできません。",
    };
  }

  const fullCommand = wrapHost(level, rawHost);
  output.push("$ " + fullCommand);

  let leaked = false;
  const exec = (cmd: string): string => {
    const out = runCommand(cmd);
    if (out.includes(FLAG)) leaked = true;
    return out;
  };

  const results = execLine(fullCommand, exec);
  for (const r of results) {
    if (r) output.push(r);
  }

  return traced(
    {
      solved: leaked,
      output,
      note: leaked
        ? "注入したコマンドが実行され、flag.txt を読み出しました。"
        : "注入は失敗しました。ping しか実行されていません。",
    },
    fullCommand,
    {
      recap: leaked
        ? ["入力がシェルの構文として解釈された", "ping 以外のコマンドが走った", "flag.txt の中身が出力された"]
        : undefined,
      loot: leaked ? [{ id: "cmdi-flag", label: "flag.txt", value: FLAG }] : undefined,
    },
  );
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。入力をそのままシェルコマンドに連結する。",
    hints: [
      "「ソース」を読みましょう。入力はコマンドのどこに埋め込まれ、シェルはそれをどう解釈しますか？",
      "入力はシェルコマンドに連結されます。1 行で複数コマンドを続けて実行する区切り文字は？",
      "`;` の後ろに `cat flag.txt` を続けましょう。",
    ],
    solution:
      "host に `8.8.8.8; cat flag.txt` を入力。`;` で ping の後に別コマンドを続けて実行できます。",
    code: `exec("ping -c 1 " + host);  // シェル経由`,
  },
  2: {
    defense: "セミコロン ( ; ) を除去する。",
    hints: [
      "Lv1 の手口は通りません。「ソース」で、除去される文字を確認しましょう。",
      "`;` は使えません。でもコマンドを連結する演算子は他にもありますよね？",
      "前のコマンドが成功したら次を実行する `&&` で、`cat flag.txt` を連結しましょう。",
    ],
    solution:
      "host に `8.8.8.8 && cat flag.txt` を入力。`&&`（前が成功したら次を実行）で連結できます。`|` や `||` でも可。",
    code: `let h = host.replace(/;/g, "");
exec("ping -c 1 " + h);`,
  },
  3: {
    defense: "ホスト名をダブルクオートで囲んでシェルに渡す。",
    hints: [
      "Lv2 の `&&` はクオートの内側では連結になりません。防御が『文字を消す』から『クオートで囲む』に変わっています。",
      "ダブルクオートは区切り文字を無効にしますが、一部の展開は止まりません。",
      "クオートの中でも先に実行される、`$()` の形を試しましょう。",
    ],
    solution:
      "host に `8.8.8.8 $(cat flag.txt)` を入力。ダブルクオート内でもコマンド置換 `$()` は評価され、flag が ping の引数に展開されます。",
    code: `exec('ping -c 1 "' + host + '"'); // 囲めば安全、と思っている
// ダブルクオート内の $(...) は展開される`,
  },
  4: {
    defense: "ホスト名をシングルクオートで囲んでシェルに渡す。",
    hints: [
      "Lv3 の `$()` はシングルクオートの中では展開されません。ソースの囲み文字を確認しましょう。",
      "シングルクオートを無効化できる文字は、シングルクオート自身です。",
      "先にクオートを閉じ、`;` で別コマンドを挟み、もう一度開く形を作れますか？",
    ],
    solution:
      "host に `'; cat flag.txt; '` を入力。`'...'` を閉じて `;` で `cat` を挟むと、囲みの外でコマンドが実行されます。",
    code: `exec("ping -c 1 '" + host + "'"); // 単一引用符なら $() も止まる
// 入力に ' が含まれると囲みが壊れる`,
  },
  5: {
    defense: "入力を厳格に検証し、シェルを使わず引数配列で実行する。",
    hints: [
      "許可された文字のホスト名しか通りません。これは正しい対策です。",
      "「ソース」を読み、シェルを介さず引数配列で実行すると、なぜ `;` や `$()` が無害になるのかを考えましょう。",
    ],
    solution:
      "このレベルは意図的に突破不可能です。ホスト名を許可リスト（英数字・ドット・ハイフン）で検証し、シェルを介さず `execFile(\"ping\", [\"-c\",\"1\", host])` のように引数配列で実行すれば、メタ文字は実行されません。",
    code: `if (!/^[A-Za-z0-9.\\-]+$/.test(host)) throw new Error("invalid host");
execFile("ping", ["-c", "1", host]);  // シェルを介さない`,
  },
};

export const cmdiLab: Lab = {
  meta: {
    id: "cmdi",
    title: "OS コマンドインジェクション — ping 診断ツール",
    shortTitle: "コマンドインジェクション",
    category: "インジェクション",
    objective: "ping ツールを悪用して flag.txt の内容を読み出す。",
    summary: "シェルに渡されるホスト名にコマンドを注入し、任意コマンドを実行する。",
    standards: {
      owasp: { code: "A03:2021", name: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection" },
      cwe: [{ id: 78, name: "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)" }],
    },
    references: [
      {
        title: "OWASP OS Command Injection Defense Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
      },
      { title: "PortSwigger Web Security Academy — OS command injection", url: "https://portswigger.net/web-security/os-command-injection" },
      { title: "IPA 安全なウェブサイトの作り方", url: "https://www.ipa.go.jp/security/vuln/websecurity/" },
    ],
  },
  fields: [
    {
      name: "host",
      label: "ホスト名 / IP",
      placeholder: "8.8.8.8",
      multiline: true,
      mono: true,
      default: "8.8.8.8",
    },
  ],
  explanation: `OS コマンドインジェクションは、アプリがユーザー入力を OS のシェルコマンドに連結して実行するときに起こります。シェルは \`;\`、\`&&\`、\`|\`、改行、\`$(...)\` などを特別に解釈するため、入力にこれらを混ぜると、本来の ping とは別の任意コマンドを実行できてしまいます。

このラボは \`ping -c 1 <入力>\` を疑似シェルで実行します。区切り文字やコマンド置換を使って \`cat flag.txt\` を実行し、フラグを読み出せればクリアです。

レベルが上がると、文字の除去、ダブルクオート囲み、シングルクオート囲みと対策の種類が変わります。囲みはシェルを使っている限り、閉じ引用符や \`$(...)\` で壊せます。

根本対策は Lv5 です。入力を許可リストで検証したうえで、シェルを介さず引数配列で実行します（例: Node の \`execFile\`、Python の \`subprocess.run([...], shell=False)\`）。`,
  levels,
  run,
  exploits: {
    1: { host: "8.8.8.8; cat flag.txt" },
    2: { host: "8.8.8.8 && cat flag.txt" },
    3: { host: "8.8.8.8 $(cat flag.txt)" },
    4: { host: "'; cat flag.txt; '" },
  },
};
