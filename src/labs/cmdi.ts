import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";

/**
 * Simulated OS Command Injection lab (a "ping" diagnostics tool).
 *
 * A naive app builds `ping -c 1 <host>` and runs it through a shell. We
 * implement a tiny shell (separators + command substitution) over a tiny
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

/** Apply the defense for `level` to the host field. */
function sanitize(level: Level, s: string): string {
  if (level === 1) return s;
  if (level === 2) return stripRecursive(s, /;/g); // only semicolons
  if (level === 3) return stripRecursive(s, /[;&|]/g); // separators, but not \n or $()
  if (level === 4) return stripRecursive(s, /[;&|\r\n]/g); // + newlines, but not $()
  return s; // level 5 validates instead (see run)
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

/** Expand `$(...)` and backtick substitutions, running the inner command. */
function expandSubstitutions(line: string, exec: (c: string) => string): string {
  let out = line;
  let prev: string;
  do {
    prev = out;
    out = out.replace(/\$\(([^()]*)\)/g, (_m, inner) => exec(inner).trim());
    out = out.replace(/`([^`]*)`/g, (_m, inner) => exec(inner).trim());
  } while (out !== prev);
  return out;
}

/** Run a full command line (separators + substitution), returning stdout. */
function execLine(line: string, exec: (c: string) => string): string[] {
  const expanded = expandSubstitutions(line, exec);
  const segments = expanded
    .split(/&&|\|\||;|\||&|\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  return segments.map((seg) => exec(seg));
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

  const host = sanitize(level, rawHost);
  const fullCommand = `ping -c 1 ${host}`;
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

  return {
    solved: leaked,
    output,
    note: leaked
      ? "注入したコマンドが実行され、flag.txt を読み出しました。"
      : "注入は失敗しました。ping しか実行されていません。",
  };
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。入力をそのままシェルコマンドに連結する。",
    hint: "入力はシェルコマンドに連結されます。1 行で複数コマンドを続けて実行する区切り文字は？",
    solution:
      "host に `8.8.8.8; cat flag.txt` を入力。`;` で ping の後に別コマンドを続けて実行できます。",
    code: `exec("ping -c 1 " + host);  // シェル経由`,
  },
  2: {
    defense: "セミコロン ( ; ) を除去する。",
    hint: "`;` は使えません。でもコマンドを連結する演算子は他にもありますよね？",
    solution:
      "host に `8.8.8.8 && cat flag.txt` を入力。`&&`（前が成功したら次を実行）で連結できます。`|` や `||` でも可。",
    code: `let h = host.replace(/;/g, "");
exec("ping -c 1 " + h);`,
  },
  3: {
    defense: "区切り文字 ; & | を除去する。",
    hint: "セミコロンも && も | も消されます。改行や『コマンド置換』はどうでしょう？",
    solution:
      "host 欄（複数行入力可）で 1 行目に `8.8.8.8`、2 行目に `cat flag.txt` と改行区切りで入力。改行もコマンド区切りです。`$(cat flag.txt)` でも可。",
    code: `let h = host.replace(/[;&|]/g, "");
exec("ping -c 1 " + h);`,
  },
  4: {
    defense: "区切り文字 ; & | と改行を除去する。",
    hint: "区切り文字も改行も消されます。でも『コマンドの出力をその場に埋め込む』構文は残っていませんか？",
    solution:
      "host に `8.8.8.8 $(cat flag.txt)` を入力。コマンド置換 `$(...)` は除去対象外なので、内部の cat が実行されます（バッククォート `` `cat flag.txt` `` でも可）。",
    code: `let h = host.replace(/[;&|\\r\\n]/g, ""); // $(...) を見落としている
exec("ping -c 1 " + h);`,
  },
  5: {
    defense: "入力を厳格に検証し、シェルを使わず引数配列で実行する。",
    hint: "許可された文字のホスト名しか通りません。これは正しい対策です。",
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
    summary: "シェルに渡されるホスト名にコマンドを注入し、任意コマンドを実行する。",  },
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

レベルが上がると危険な文字を 1 つずつブラックリストで消そうとしますが、シェルのメタ文字は非常に多く（区切り、改行、置換…）、消し漏れが必ず生まれます。

根本対策は Lv5 です。入力を許可リストで厳格に検証したうえで、シェルを介さず引数配列で外部コマンドを実行します（例: Node の \`execFile\`、Python の \`subprocess.run([...], shell=False)\`）。シェルを使わなければ、メタ文字は単なる文字列として扱われ、注入は成立しません。`,
  levels,
  run,
};
