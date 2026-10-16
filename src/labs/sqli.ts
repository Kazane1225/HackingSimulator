import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

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

function stripRecursive(s: string, re: RegExp): string {
  let prev: string;
  do {
    prev = s;
    s = s.replace(re, "");
  } while (s !== prev);
  return s;
}

/** SQL standard quote doubling — a real mitigation, not a keyword blacklist. */
function escapeSql(s: string): string {
  return s.replace(/'/g, "''");
}

function legitPair(username: string, password: string): boolean {
  return USERS.some((u) => u.username === username && u.password === password);
}

function finish(
  query: string,
  headline: string,
  rawUser: string,
  rawPass: string,
  mode: "login" | "dump" = "login",
): AttackResult {
  const assembled = `${query};`;
  const output: string[] = [headline, assembled, ""];

  if (mode === "dump" && /union\s+select/i.test(query)) {
    output.push("UNION により users テーブルを取得:");
    for (const r of USERS) {
      output.push(`   #${r.id}  ${r.username}  password=${r.password}  (${r.role})`);
    }
    return traced(
      {
        solved: true,
        output,
        note: "UNION SELECT でパスワード列を奪いました。",
      },
      assembled,
      {
        recap: [
          "ログイン欄はプレースホルダだった",
          "role フィルタだけ文字列連結が残っていた",
          "UNION で users.password が応答に乗った",
        ],
        loot: USERS.map((u) => ({
          id: `sqli-pass-${u.username}`,
          label: `${u.username} のパスワード`,
          value: u.password,
        })),
      },
    );
  }

  const whereStr = query.slice(query.indexOf("WHERE") + 5).replace(/\s+union\s+[\s\S]*$/i, "");
  const pred = parseWhere(tokenize(whereStr));

  if (pred === null) {
    output.push("SQL ERROR: you have an error in your SQL syntax");
    output.push("→ 0 行ヒット（クエリが構文エラーで失敗）");
    return traced(
      {
        solved: false,
        output,
        note: "組み立てたクエリが壊れています。構文として成立する注入を考えましょう。",
      },
      assembled,
    );
  }

  const rows = USERS.filter(pred);
  output.push(`→ ${rows.length} 行ヒット`);
  for (const r of rows) {
    output.push(`   #${r.id}  ${r.username}  (${r.role})`);
  }

  const authed = rows.length > 0;
  const injected = authed && !legitPair(rawUser, rawPass);
  const loggedInAsAdmin = rows.some((r) => r.username === "admin");
  const solved = mode === "login" && injected && loggedInAsAdmin;

  return traced(
    {
      solved,
      output,
      progress:
        (mode === "dump" && authed && !solved) || (mode === "login" && injected && !loggedInAsAdmin),
      benign: mode === "login" && authed && !injected,
      note:
        mode === "dump"
          ? authed
            ? "ログインは通りましたが、Lv4 の目標はテーブルの中身です。"
            : "role の条件に合う行がありません。"
          : !authed
            ? "ログイン失敗。該当ユーザーなし。"
            : injected
              ? loggedInAsAdmin
                ? "admin としてログイン成功。認証をバイパスしました。"
                : "ログインはできましたが admin ではありません。admin 行を返させましょう。"
              : "正規の資格情報です（インジェクションではありません）。",
    },
    assembled,
    solved
      ? {
          recap: ["入力が SQL の構文として解釈された", "WHERE が意図せず真になった", "admin 行が返った"],
        }
      : undefined,
  );
}

function run(level: Level, input: LabInput): AttackResult {
  const rawUser = input.username ?? "";
  const rawPass = input.password ?? "";
  const rawId = (input.id ?? "").trim();
  const rawRole = input.role ?? "user";

  if (level === 5) {
    const output: string[] = [];
    output.push("-- 準備済みステートメント (プレースホルダ)");
    output.push("SELECT * FROM users WHERE username = ? AND password = ? AND role = ?;");
    output.push(
      `-- bind: username=${JSON.stringify(rawUser)}, password=${JSON.stringify(rawPass)}, role=${JSON.stringify(rawRole)}`,
    );
    const rows = USERS.filter(
      (u) => u.username === rawUser && u.password === rawPass && u.role === rawRole,
    );
    output.push("");
    output.push(`→ ${rows.length} 行ヒット`);
    return traced(
      {
        solved: false,
        output,
        note:
          rows.length > 0
            ? "正規の資格情報でのログインです（インジェクションではありません）。"
            : "入力は値として扱われたため、クエリ構造は一切変化しませんでした。",
      },
      "SELECT * FROM users WHERE username = ? AND password = ? AND role = ?;",
    );
  }

  if (level === 4) {
    const query =
      `SELECT * FROM users WHERE username='${escapeSql(rawUser)}'` +
      ` AND password='${escapeSql(rawPass)}'` +
      ` AND role='${rawRole}'`;
    return finish(query, "-- username / password はプレースホルダ。role だけ文字列連結", rawUser, rawPass, "dump");
  }

  if (level === 3) {
    const u = escapeSql(rawUser);
    const p = escapeSql(rawPass);
    const query = rawId
      ? `SELECT * FROM users WHERE username='${u}' AND password='${p}' AND id=${rawId}`
      : `SELECT * FROM users WHERE username='${u}' AND password='${p}'`;
    return finish(query, "-- 文字列はクオートを二重化して連結。id は数値として連結", rawUser, rawPass);
  }

  const u = level === 2 ? stripRecursive(rawUser, /--|#|\/\*|\*\//g) : rawUser;
  const p = level === 2 ? stripRecursive(rawPass, /--|#|\/\*|\*\//g) : rawPass;
  const query = `SELECT * FROM users WHERE username='${u}' AND password='${p}'`;
  return finish(query, "-- 文字列連結で組み立てられたクエリ", rawUser, rawPass);
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。入力をそのまま SQL に連結する。",
    hints: [
      "「ソース」タブを読みましょう。入力は SQL 文のどこに、どのように埋め込まれていますか？",
      "入力はクオートの内側に入ります。クオートを閉じて、後続の条件をコメントアウトできませんか？",
      "SQL のコメント記号 `--` が使えます（直後に半角スペースが必要です）。パスワードの条件を無効化しましょう。",
    ],
    solution:
      "username に `admin'--` を入力（末尾の半角スペースに注意: `admin'-- `）。クオートを閉じ、`-- ` 以降（AND password=... の部分）をコメントとして無効化します。",
    code: `const q = "SELECT * FROM users WHERE username='" + username
        + "' AND password='" + password + "'";
db.query(q);`,
  },
  2: {
    defense: "コメント記号 (--, #, /* */) を除去する。",
    hints: [
      "Lv1 の入力は通りません。「ソース」で、除去される記号を確認しましょう。",
      "コメントは使えません。でも WHERE 全体を常に真にする方法は、コメント以外にもありますよね？",
      "論理演算子 `OR` で、`'1'='1'` のような常に真になる式をつなぎましょう。",
    ],
    solution:
      "username に `admin' OR '1'='1` を入力。`WHERE username='admin' OR '1'='1' AND password='...'` となり、OR により常に真になって admin 行が返ります。",
    code: `let u = username.replace(/--|#|\\/\\*|\\*\\//g, "");
let p = password.replace(/--|#|\\/\\*|\\*\\//g, "");
const q = "...WHERE username='" + u + "' AND password='" + p + "'";`,
  },
  3: {
    defense: "ログイン欄のクオートを SQL 方式でエスケープする。ただし隠しパラメータ id は数値として連結する。",
    hints: [
      "Lv2 の `' OR '1'='1` は、`'` が `''` に変換されてただの検索文字列になります。防御の種類が変わっています。",
      "ソースを読むと、username / password 以外にもクエリへ入る値があります。数値だと思っている欄はクオートで囲まれていますか？",
      "Proxy の `id` は `AND id=` の後ろにそのまま繋がります。OR で条件を足せませんか？",
    ],
    solution:
      "username / password はそのままで、Proxy の `id` に `1 OR 1=1` を入れます。数値列はクオートもエスケープもないため、`AND id=1 OR 1=1` が追加され admin 行を含む全行が返ります。",
    code: `const u = username.replace(/'/g, "''"); // 教科書的なエスケープ
const p = password.replace(/'/g, "''");
let q = "SELECT * FROM users WHERE username='" + u + "' AND password='" + p + "'";
if (req.body.id) q += " AND id=" + req.body.id; // 数値だから安全、と思っている`,
  },
  4: {
    defense: "username / password はプレースホルダ。表示用フィルタ role だけ文字列連結が残っている。",
    hints: [
      "ログイン欄への注入は効きません。OR で入れてもパスワードは出ません。",
      "Interceptor で `role` パラメータを追加できます。ソースの連結箇所です。",
      "`' UNION SELECT username, password FROM users-- ` で別の SELECT を足せます。",
    ],
    solution:
      "Proxy に `role` を追加し、`' UNION SELECT username, password FROM users-- ` を入れます。認証をバイパスするのではなく、users 表のパスワード列を奪います。",
    code: `db.query(
  "SELECT * FROM users WHERE username=? AND password=? AND role='" + role + "'",
  [username, password] // ログイン欄だけ対策済み。role は連結のまま
);`,
  },
  5: {
    defense: "すべての入力をプレースホルダでバインドする。",
    hints: [
      "入力は SQL 構造に影響できません。これは正しい対策です。",
      "「ソース」を読み、入力が SQL の『構文』ではなく『値』として扱われる理由を考えましょう。",
    ],
    solution:
      "このレベルは意図的に突破不可能です。パラメータ化クエリでは入力が常に『値』として扱われ、クオートを閉じても構造は変わりません。これが本来あるべき実装です。",
    code: `db.query(
  "SELECT * FROM users WHERE username=? AND password=? AND role=?",
  [username, password, role]
);`,
  },
};

export const sqliLab: Lab = {
  meta: {
    id: "sqli",
    title: "SQL インジェクション — ログイン認証バイパス",
    shortTitle: "SQL インジェクション",
    category: "インジェクション",
    objective: "正しいパスワードを知らずに admin になるか、ユーザー表の認証情報を奪う。",
    summary: "文字列連結で組み立てられたログインクエリを悪用し、認証回避や UNION によるダンプを行う。",
    standards: {
      owasp: { code: "A03:2021", name: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection" },
      cwe: [{ id: 89, name: "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)" }],
    },
    references: [
      {
        title: "OWASP SQL Injection Prevention Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
      },
      { title: "PortSwigger Web Security Academy — SQL injection", url: "https://portswigger.net/web-security/sql-injection" },
      { title: "IPA 安全なウェブサイトの作り方", url: "https://www.ipa.go.jp/security/vuln/websecurity/" },
    ],
  },
  fields: [
    { name: "username", label: "ユーザー名", placeholder: "admin", mono: true, default: "admin" },
    { name: "password", label: "パスワード", placeholder: "password", mono: true, default: "wrong" },
    { name: "id", label: "id", placeholder: "", mono: true, default: "", hidden: true },
    { name: "role", label: "role", placeholder: "user", mono: true, default: "user", hidden: true },
  ],
  explanation: `SQL インジェクションは、アプリがユーザー入力を SQL 文に文字列連結で埋め込むときに起こります。入力の中のクオートやキーワードが「データ」ではなく「SQL の構文」として解釈され、攻撃者がクエリの意味そのものを書き換えられます。

このラボのログイン処理は \`WHERE username='<入力>' AND password='<入力>'\` を組み立てます。クオートを閉じてコメントアウトしたり、常に真の条件を足すと、パスワード検証を素通りできます。

レベルが上がると対策の**種類**が変わります。コメント除去、クオートのエスケープ、プレースホルダです。エスケープはログイン欄を止めても、クオートで囲んでいない数値パラメータや、後から足した role フィルタのような別の連結箇所が残れば成立します。禁止語を増やすことでは止まりません。

根本対策は Lv5 です。ユーザーが触れる値はすべてプレースホルダでバインドし、構造とデータを分離します。`,
  levels,
  run,
  exploits: {
    1: { username: "admin'-- ", password: "x", id: "", role: "user" },
    2: { username: "admin' OR '1'='1", password: "x", id: "", role: "user" },
    3: { username: "admin", password: "wrong", id: "1 OR 1=1", role: "user" },
    4: { username: "admin", password: "wrong", id: "", role: "' UNION SELECT username, password FROM users-- " },
  },
};
