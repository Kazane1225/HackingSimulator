import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";

/**
 * Simulated SQL Injection lab (login form).
 *
 * We build the exact SQL string a naive app would build, then evaluate its
 * WHERE clause with a tiny, STRICT boolean-expression engine. "Strict" means a
 * clause that does not fully parse is treated as a syntax error (zero rows),
 * just like a real database — which is what makes the per-level escalation
 * meaningful. Objective: log in as admin without knowing a valid password.
 */

interface UserRow {
  id: number;
  username: string;
  password: string;
  role: string;
}

const USERS: UserRow[] = [
  { id: 1, username: "admin", password: "S3cr3t-Pa55!", role: "administrator" },
  { id: 2, username: "alice", password: "sunshine", role: "user" },
  { id: 3, username: "bob", password: "qwerty123", role: "user" },
];

// --- Tiny WHERE-clause tokenizer -------------------------------------------
// Supports string literals, numbers, column identifiers, `=`, AND / OR (and
// their && / || aliases) and `--` / `#` line comments.

type Token =
  | { t: "str"; v: string }
  | { t: "num"; v: string }
  | { t: "id"; v: string }
  | { t: "op"; v: "=" | "and" | "or" };

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < input.length) {
    const c = input[i];
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === "-" && input[i + 1] === "-") break;
    if (c === "#") break;
    if (c === "'") {
      let j = i + 1;
      let v = "";
      while (j < input.length && input[j] !== "'") v += input[j++];
      tokens.push({ t: "str", v });
      i = j + 1;
      continue;
    }
    if (c === "=") {
      tokens.push({ t: "op", v: "=" });
      i++;
      continue;
    }
    if (c === "|" && input[i + 1] === "|") {
      tokens.push({ t: "op", v: "or" });
      i += 2;
      continue;
    }
    if (c === "&" && input[i + 1] === "&") {
      tokens.push({ t: "op", v: "and" });
      i += 2;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i;
      let v = "";
      while (j < input.length && /[0-9]/.test(input[j])) v += input[j++];
      tokens.push({ t: "num", v });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      let v = "";
      while (j < input.length && /[A-Za-z0-9_]/.test(input[j])) v += input[j++];
      const lower = v.toLowerCase();
      if (lower === "and" || lower === "or") tokens.push({ t: "op", v: lower });
      else tokens.push({ t: "id", v });
      i = j;
      continue;
    }
    // Any other character is a syntax error marker: emit an impossible id so
    // the strict parser fails (mirrors a real DB rejecting the query).
    tokens.push({ t: "id", v: "\u0000" });
    i++;
  }
  return tokens;
}

// --- Strict recursive-descent parser ---------------------------------------
// Grammar:  expr := or ;  or := and (OR and)* ;  and := cmp (AND cmp)* ;
//           cmp  := value '=' value ;  value := str | num | id
// Returns a predicate, or null if the full token stream does not parse.

type Pred = (row: UserRow) => boolean;

function parseWhere(tokens: Token[]): Pred | null {
  let pos = 0;

  const resolve = (tok: Token, row: UserRow): string => {
    if (tok.t === "id") {
      const key = tok.v.toLowerCase();
      if (key === "username") return row.username;
      if (key === "password") return row.password;
      if (key === "role") return row.role;
      if (key === "id") return String(row.id);
      return `\u0000col:${tok.v}`; // unknown column — never equals a literal
    }
    return tok.v;
  };

  function cmp(): Pred | null {
    const left = tokens[pos];
    if (!left || left.t === "op") return null;
    pos++;
    const eq = tokens[pos];
    if (!eq || eq.t !== "op" || eq.v !== "=") return null;
    pos++;
    const right = tokens[pos];
    if (!right || right.t === "op") return null;
    pos++;
    return (row) => resolve(left, row) === resolve(right, row);
  }

  const isOp = (v: "and" | "or"): boolean => {
    const tok = tokens[pos];
    return !!tok && tok.t === "op" && tok.v === v;
  };

  function andExpr(): Pred | null {
    let left: Pred | null = cmp();
    if (!left) return null;
    while (isOp("and")) {
      pos++;
      const right = cmp();
      if (!right) return null;
      const l: Pred = left;
      left = (row) => l(row) && right(row);
    }
    return left;
  }

  function orExpr(): Pred | null {
    let left: Pred | null = andExpr();
    if (!left) return null;
    while (isOp("or")) {
      pos++;
      const right = andExpr();
      if (!right) return null;
      const l: Pred = left;
      left = (row) => l(row) || right(row);
    }
    return left;
  }

  const pred = orExpr();
  if (pred === null) return null;
  if (pos !== tokens.length) return null; // leftover tokens ⇒ syntax error
  return pred;
}

// --- Per-level input filtering ---------------------------------------------

function stripRecursive(s: string, re: RegExp): string {
  let prev: string;
  do {
    prev = s;
    s = s.replace(re, "");
  } while (s !== prev);
  return s;
}

/** Apply the defense for `level` to a single user-supplied field. */
function sanitize(level: Level, s: string): string {
  const comments = /--|#|\/\*|\*\//g;
  const wordKeywords = /\bor\b|\band\b/gi;
  const operators = /\|\||&&/g;
  if (level === 1) return s;
  if (level === 2) return stripRecursive(s, comments);
  if (level === 3) {
    // Only the *word* keywords are blacklisted; the symbolic aliases slip by.
    let out = stripRecursive(s, comments);
    out = stripRecursive(out, wordKeywords);
    return out;
  }
  if (level === 4) {
    // Regression: rewritten as a single pass that also strips *substrings*
    // (to catch things like "oOrr"), but it is no longer idempotent. Removing
    // "or" from "oorr" leaves "or" behind — the classic blacklist bug.
    let out = s.replace(comments, "");
    out = out.replace(/or|and/gi, "");
    out = out.replace(operators, "");
    return out;
  }
  return s; // level 5 does not build strings at all (see run)
}

// --- Lab runner ------------------------------------------------------------

function legitPair(username: string, password: string): boolean {
  return USERS.some((u) => u.username === username && u.password === password);
}

function run(level: Level, input: LabInput): AttackResult {
  const rawUser = input.username ?? "";
  const rawPass = input.password ?? "";
  const output: string[] = [];

  if (level === 5) {
    // Parameterized query: inputs are bound as data, never concatenated.
    output.push("-- 準備済みステートメント (プレースホルダ)");
    output.push("SELECT * FROM users WHERE username = ? AND password = ?;");
    output.push(`-- bind: ? = ${JSON.stringify(rawUser)}, ? = ${JSON.stringify(rawPass)}`);
    const rows = USERS.filter(
      (u) => u.username === rawUser && u.password === rawPass,
    );
    output.push("");
    output.push(`→ ${rows.length} 行ヒット`);
    const bypass = rows.length > 0 && !legitPair(rawUser, rawPass);
    return {
      solved: bypass, // can only be true with real credentials ⇒ never
      output,
      note:
        rows.length > 0
          ? "正規の資格情報でのログインです（インジェクションではありません）。"
          : "入力は値として扱われたため、クエリ構造は一切変化しませんでした。",
    };
  }

  const u = sanitize(level, rawUser);
  const p = sanitize(level, rawPass);
  const query = `SELECT * FROM users WHERE username='${u}' AND password='${p}'`;
  output.push("-- 文字列連結で組み立てられたクエリ");
  output.push(`${query};`);
  output.push("");

  // Everything after WHERE:
  const whereStr = query.slice(query.indexOf("WHERE") + 5);
  const pred = parseWhere(tokenize(whereStr));

  if (pred === null) {
    output.push("SQL ERROR: you have an error in your SQL syntax");
    output.push("→ 0 行ヒット（クエリが構文エラーで失敗）");
    return {
      solved: false,
      output,
      note: "組み立てたクエリが壊れています。構文として成立する注入を考えましょう。",
    };
  }

  const rows = USERS.filter(pred);
  output.push(`→ ${rows.length} 行ヒット`);
  for (const r of rows) {
    output.push(`   #${r.id}  ${r.username}  (${r.role})`);
  }

  const authed = rows.length > 0;
  const injected = authed && !legitPair(rawUser, rawPass);
  const loggedInAsAdmin = rows.some((r) => r.username === "admin");

  return {
    solved: injected && loggedInAsAdmin,
    output,
    note: !authed
      ? "ログイン失敗。該当ユーザーなし。"
      : injected
        ? loggedInAsAdmin
          ? "admin としてログイン成功。認証をバイパスしました。"
          : "ログインはできましたが admin ではありません。admin 行を返させましょう。"
        : "正規の資格情報です（インジェクションではありません）。",
  };
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。入力をそのまま SQL に連結する。",
    hint: "入力はクオートの内側に入ります。クオートを閉じて、後続の条件をコメントアウトできませんか？",
    solution:
      "username に `admin'--` を入力（末尾の半角スペースに注意: `admin'-- `）。クオートを閉じ、`-- ` 以降（AND password=... の部分）をコメントとして無効化します。",
    code: `const q = "SELECT * FROM users WHERE username='" + username
        + "' AND password='" + password + "'";
db.query(q);`,
  },
  2: {
    defense: "コメント記号 (--, #, /* */) を除去する。",
    hint: "コメントは使えません。でも WHERE 全体を常に真にする方法は、コメント以外にもありますよね？",
    solution:
      "username に `admin' OR '1'='1` を入力。`WHERE username='admin' OR '1'='1' AND password='...'` となり、OR により常に真になって admin 行が返ります。",
    code: `let u = username.replace(/--|#|\\/\\*|\\*\\//g, "");
let p = password.replace(/--|#|\\/\\*|\\*\\//g, "");
const q = "...WHERE username='" + u + "' AND password='" + p + "'";`,
  },
  3: {
    defense: "コメントに加え、英単語の OR / AND を（大小文字無視・繰り返し）除去する。",
    hint: "英単語の OR が消されます。OR と同じ意味を持つ『記号』は他にありませんか？",
    solution:
      "username に `admin'||'1'='1` を入力。MySQL などでは `||` が論理和として評価され、OR と同じく常に真になります。ブラックリストが英単語しか見ていない盲点です。",
    code: `const strip = (s) => { let p; do { p = s;
  s = s.replace(/--|#|\\/\\*|\\*\\//g, "")
       .replace(/\\bor\\b|\\band\\b/gi, "");  // 記号の || && は見ていない
} while (s !== p); return s; };`,
  },
  4: {
    defense: "ブラックリストを単一パスの置換に書き換え（部分文字列も除去）。繰り返し適用していない。",
    hint: "フィルタは一度しか走りません。『除去した結果、禁止語が再生成される』ような入力を作れませんか？",
    solution:
      "username に `admin' oorr '1'='1` を入力。`oorr` から真ん中の `or` が一度だけ除去され `or` が復活 → `WHERE username='admin' or '1'='1' ...` となり認証バイパス成立。非冪等なサニタイズの典型バグです。",
    code: `let u = username.replace(/--|#|\\/\\*|\\*\\//g, "")
   .replace(/or|and/gi, "")   // ← 1回しか置換しない
   .replace(/\\|\\||&&/g, "");
// "oorr" -> "or" が残る`,
  },
  5: {
    defense: "プレースホルダ（準備済みステートメント）で入力を値としてバインド。",
    hint: "入力は SQL の構造に影響できません。これは正しい対策です。",
    solution:
      "このレベルは意図的に突破不可能です。パラメータ化クエリでは入力が常に『値』として扱われ、クオートを閉じても構造は変わりません。これが本来あるべき実装です。",
    code: `db.query(
  "SELECT * FROM users WHERE username = ? AND password = ?",
  [username, password]   // 値としてバインド。構造は不変
);`,
  },
};

export const sqliLab: Lab = {
  meta: {
    id: "sqli",
    title: "SQL インジェクション — ログイン認証バイパス",
    shortTitle: "SQL インジェクション",
    category: "インジェクション",
    objective: "正しいパスワードを知らずに admin としてログインする。",
    summary: "文字列連結で組み立てられたログインクエリを悪用し、認証を回避する。",  },
  fields: [
    { name: "username", label: "ユーザー名", placeholder: "admin", mono: true, default: "admin" },
    { name: "password", label: "パスワード", placeholder: "password", mono: true, default: "wrong" },
  ],
  explanation: `SQL インジェクションは、アプリがユーザー入力を SQL 文に文字列連結で埋め込むときに起こります。入力の中のクオートやキーワードが「データ」ではなく「SQL の構文」として解釈され、攻撃者がクエリの意味そのものを書き換えられます。

このラボのログイン処理は \`WHERE username='<入力>' AND password='<入力>'\` を組み立てます。クオートを閉じて \`OR '1'='1'\` のような常に真の条件を注入したり、\`-- \` で以降をコメントアウトすると、パスワード検証を素通りできます。

レベルが上がるとブラックリスト（禁止語の除去）で防ごうとしますが、ブラックリストは「記号による等価表現」「大小文字」「非冪等な置換」などで次々と回避されます。これがブラックリスト方式の本質的な弱さです。

根本対策は Lv5 のプレースホルダ（準備済みステートメント）です。入力は必ず「値」としてバインドされ、クオートを含んでいてもクエリの構造は一切変わりません。入力のエスケープに頼るのではなく、構造とデータを分離するのが正解です。`,
  levels,
  run,
  exploits: {
    1: { username: "admin'-- ", password: "x" },
    2: { username: "admin' OR '1'='1", password: "x" },
    3: { username: "admin'||'1'='1", password: "x" },
    4: { username: "admin' oorr '1'='1", password: "x" },
  },
};
