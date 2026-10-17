import { DatabaseSync } from "node:sqlite";
import type { AttackResult, LabInput, Level, LootItem, RealLab } from "./runner.js";

/**
 * Real SQL injection lab: queries run against an actual SQLite engine, so
 * syntax errors, operator precedence and UNION column-count rules are the
 * database's own. Each request gets a fresh in-memory database.
 * Objective: log in as admin without the password, or steal the users table.
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

const SELECT = "SELECT username, role FROM users";

function openDb(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)");
  const insert = db.prepare("INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)");
  for (const u of USERS) insert.run(u.id, u.username, u.password, u.role);
  return db;
}

function stripRecursive(s: string, re: RegExp): string {
  let prev: string;
  do {
    prev = s;
    s = s.replace(re, "");
  } while (s !== prev);
  return s;
}

/** SQL standard quote doubling: a real mitigation, not a keyword blacklist. */
function escapeSql(s: string): string {
  return s.replace(/'/g, "''");
}

function legitPair(username: string, password: string): boolean {
  return USERS.some((u) => u.username === username && u.password === password);
}

interface Built {
  headline: string;
  sql: string;
  params: string[];
}

function build(level: Level, input: LabInput): Built {
  const rawUser = input.username ?? "";
  const rawPass = input.password ?? "";
  const rawId = (input.id ?? "").trim();
  const rawRole = input.role ?? "user";

  if (level === 5) {
    return {
      headline: "-- 準備済みステートメント (プレースホルダ)",
      sql: `${SELECT} WHERE username = ? AND password = ? AND role = ?`,
      params: [rawUser, rawPass, rawRole],
    };
  }

  if (level === 4) {
    return {
      headline: "-- username / password はプレースホルダ。role だけ文字列連結",
      sql: `${SELECT} WHERE username = ? AND password = ? AND role = '${rawRole}'`,
      params: [rawUser, rawPass],
    };
  }

  if (level === 3) {
    const u = escapeSql(rawUser);
    const p = escapeSql(rawPass);
    const base = `${SELECT} WHERE username='${u}' AND password='${p}'`;
    return {
      headline: "-- 文字列はクオートを二重化して連結。id は数値として連結",
      sql: rawId ? `${base} AND id=${rawId}` : base,
      params: [],
    };
  }

  const strip = (s: string) => (level === 2 ? stripRecursive(s, /--|#|\/\*|\*\//g) : s);
  return {
    headline: "-- 文字列連結で組み立てられたクエリ",
    sql: `${SELECT} WHERE username='${strip(rawUser)}' AND password='${strip(rawPass)}'`,
    params: [],
  };
}

function formatParams(params: string[], level: Level): string {
  const names = level === 5 ? ["username", "password", "role"] : ["username", "password"];
  return (
    "-- bind: " +
    params.map((v, i) => (names[i] === "password" ? `password="******"` : `${names[i]}=${JSON.stringify(v)}`)).join(", ")
  );
}

function run(level: Level, input: LabInput): AttackResult {
  const rawUser = input.username ?? "";
  const rawPass = input.password ?? "";
  const built = build(level, input);
  const assembled = `${built.sql};`;
  const output: string[] = [built.headline];
  if (built.params.length > 0) output.push(formatParams(built.params, level));
  output.push(assembled, "");

  let rows: { username: string; role: string }[];
  const db = openDb();
  try {
    rows = db.prepare(built.sql).all(...built.params) as { username: string; role: string }[];
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    output.push(`SQL ERROR: ${message}`);
    output.push("→ 0 行ヒット（クエリが失敗）");
    return {
      solved: false,
      output,
      assembled,
      note: "組み立てたクエリが DB に拒否されました。構文として成立する注入を考えましょう。",
    };
  } finally {
    db.close();
  }

  output.push(`→ ${rows.length} 行ヒット`);
  for (const r of rows) output.push(`   ${r.username}  (${r.role})`);

  const authed = rows.length > 0;
  const legit = legitPair(rawUser, rawPass);

  if (level === 5) {
    return {
      solved: false,
      output,
      assembled,
      benign: authed,
      note: authed
        ? "正規の資格情報でのログインです（インジェクションではありません）。"
        : "入力は値として扱われたため、クエリ構造は一切変化しませんでした。",
    };
  }

  if (level === 4) {
    const leaked: LootItem[] = rows
      .map((r) => ({ r, owner: USERS.find((u) => u.username === r.username && u.password === r.role) }))
      .filter((x): x is { r: { username: string; role: string }; owner: UserRow } => x.owner !== undefined)
      .map(({ owner }) => ({
        id: `sqli-pass-${owner.username}`,
        label: `${owner.username} のパスワード`,
        value: owner.password,
      }));
    const solved = leaked.length > 0;
    return {
      solved,
      output,
      assembled,
      progress: authed && !solved && !legit,
      benign: authed && !solved && legit,
      note: solved
        ? "UNION SELECT でパスワード列を奪いました。"
        : authed
          ? legit
            ? "正規の資格情報でのログインです（インジェクションではありません）。"
            : "ログインは通りましたが、Lv4 の目標はテーブルの中身です。"
          : "role の条件に合う行がありません。",
      recap: solved
        ? [
            "ログイン欄はプレースホルダだった",
            "role フィルタだけ文字列連結が残っていた",
            "UNION で users.password が応答に乗った",
          ]
        : undefined,
      loot: solved ? leaked : undefined,
    };
  }

  const injected = authed && !legit;
  const asAdmin = rows.some((r) => r.username === "admin");
  const solved = injected && asAdmin;
  return {
    solved,
    output,
    assembled,
    progress: injected && !asAdmin,
    benign: authed && !injected,
    note: !authed
      ? "ログイン失敗。該当ユーザーなし。"
      : injected
        ? asAdmin
          ? "admin としてログイン成功。認証をバイパスしました。"
          : "ログインはできましたが admin ではありません。admin 行を返させましょう。"
        : "正規の資格情報です（インジェクションではありません）。",
    recap: solved ? ["入力が SQL の構文として解釈された", "WHERE が意図せず真になった", "admin 行が返った"] : undefined,
  };
}

export const sqliRealLab: RealLab = { id: "sqli", run };
