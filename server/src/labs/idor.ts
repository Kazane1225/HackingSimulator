import { DatabaseSync } from "node:sqlite";
import type { AttackResult, LabInput, Level, LootItem, RealLab } from "./runner.js";

/**
 * Real IDOR lab: a fresh in-memory SQLite database (users/orders/legacy id
 * aliases) backs every request, and object-level authorization is real
 * application logic layered on top of real SQL lookups rather than a lookup
 * table of pre-baked answers. The `/graphql` endpoint is served by a small
 * but genuine recursive-descent parser for a GraphQL-like query language
 * (tokenizer + parser, not a regex), so the accepted syntax is real.
 * Objective: while "logged in" as alice, read Bob's order.
 */

const ALICE_ID = 1;
const ALICE = "alice";
const BOB = "bob";
const BOB_ORDER = "ORD-B0B-42";

interface OrderRow {
  id: string;
  owner_username: string;
  item: string;
  price_yen: number;
  related_order_id: string | null;
}

function openDb(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL);
    CREATE TABLE orders (
      id TEXT PRIMARY KEY,
      owner_id INTEGER NOT NULL REFERENCES users(id),
      item TEXT NOT NULL,
      price_yen INTEGER NOT NULL,
      related_order_id TEXT REFERENCES orders(id)
    );
    -- The original API used guessable sequential ids; it was replaced by the
    -- opaque ids in "orders" but the old numbers are kept here for Lv1.
    CREATE TABLE legacy_order_ids (legacy_id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id));
  `);
  db.prepare("INSERT INTO users (id, username) VALUES (?, ?)").run(ALICE_ID, ALICE);
  db.prepare("INSERT INTO users (id, username) VALUES (?, ?)").run(2, BOB);
  const insertOrder = db.prepare(
    "INSERT INTO orders (id, owner_id, item, price_yen, related_order_id) VALUES (?, ?, ?, ?, ?)",
  );
  // Bob's row is inserted first: Alice's row has a real foreign key pointing
  // at it (the "related order" suggestion feature that leaks it, see below).
  insertOrder.run(BOB_ORDER, 2, "法人向けセキュリティキー", 89800, null);
  insertOrder.run("1001", ALICE_ID, "USB-C ケーブル", 2480, BOB_ORDER);
  const insertLegacy = db.prepare("INSERT INTO legacy_order_ids (legacy_id, order_id) VALUES (?, ?)");
  insertLegacy.run("1001", "1001");
  insertLegacy.run("1002", BOB_ORDER);
  return db;
}

function findById(db: DatabaseSync, id: string): OrderRow | undefined {
  if (!id) return undefined;
  const row = db
    .prepare(
      `SELECT o.id, u.username AS owner_username, o.item, o.price_yen, o.related_order_id
       FROM orders o JOIN users u ON u.id = o.owner_id WHERE o.id = ?`,
    )
    .get(id) as OrderRow | undefined;
  return row;
}

function findByLegacyOrId(db: DatabaseSync, key: string): OrderRow | undefined {
  if (!key) return undefined;
  const row = db
    .prepare(
      `SELECT o.id, u.username AS owner_username, o.item, o.price_yen, o.related_order_id
       FROM legacy_order_ids l JOIN orders o ON o.id = l.order_id JOIN users u ON u.id = o.owner_id
       WHERE l.legacy_id = ?`,
    )
    .get(key) as OrderRow | undefined;
  return row ?? findById(db, key);
}

// ---------------------------------------------------------------------------
// Minimal real GraphQL-like parser: tokenizer + recursive-descent parser for
// `[query] { field(arg: "v", arg2: 1) { sub sub2 { nested } } }`. Real enough
// to reject genuinely malformed queries and to extract field names/arguments
// the way an actual GraphQL server would, without being a full spec parser.
// ---------------------------------------------------------------------------

interface GqlField {
  name: string;
  args: Record<string, string | number | boolean | null>;
  selection: GqlField[];
}

type Token = { kind: "punct" | "name" | "string" | "number"; value: string };

function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) {
      i++;
    } else if ("{}():,".includes(c)) {
      tokens.push({ kind: "punct", value: c });
      i++;
    } else if (c === '"') {
      let j = i + 1;
      let value = "";
      while (j < src.length && src[j] !== '"') {
        if (src[j] === "\\" && j + 1 < src.length) {
          value += src[j + 1];
          j += 2;
        } else {
          value += src[j];
          j++;
        }
      }
      if (j >= src.length) throw new Error("unterminated string literal");
      tokens.push({ kind: "string", value });
      i = j + 1;
    } else if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
      tokens.push({ kind: "name", value: src.slice(i, j) });
      i = j;
    } else if (/[-0-9]/.test(c)) {
      let j = i;
      while (j < src.length && /[-0-9.]/.test(src[j])) j++;
      tokens.push({ kind: "number", value: src.slice(i, j) });
      i = j;
    } else {
      throw new Error(`unexpected character ${JSON.stringify(c)}`);
    }
  }
  return tokens;
}

class TokenStream {
  constructor(
    private readonly tokens: Token[],
    private pos = 0,
  ) {}
  peek(): Token | undefined {
    return this.tokens[this.pos];
  }
  next(): Token {
    const t = this.tokens[this.pos++];
    if (!t) throw new Error("unexpected end of query");
    return t;
  }
  expectPunct(value: string): void {
    const t = this.next();
    if (t.kind !== "punct" || t.value !== value) throw new Error(`expected "${value}"`);
  }
  atEnd(): boolean {
    return this.pos >= this.tokens.length;
  }
}

function parseValue(ts: TokenStream): string | number | boolean | null {
  const t = ts.next();
  if (t.kind === "string") return t.value;
  if (t.kind === "number") return Number(t.value);
  if (t.kind === "name") {
    if (t.value === "true") return true;
    if (t.value === "false") return false;
    if (t.value === "null") return null;
    return t.value;
  }
  throw new Error("expected a value");
}

function parseArgs(ts: TokenStream): Record<string, string | number | boolean | null> {
  const args: Record<string, string | number | boolean | null> = {};
  ts.expectPunct("(");
  while (ts.peek()?.value !== ")") {
    const name = ts.next();
    if (name.kind !== "name") throw new Error("expected argument name");
    ts.expectPunct(":");
    args[name.value] = parseValue(ts);
    if (ts.peek()?.value === ",") ts.next();
  }
  ts.expectPunct(")");
  return args;
}

function parseSelectionSet(ts: TokenStream): GqlField[] {
  ts.expectPunct("{");
  const fields: GqlField[] = [];
  while (ts.peek()?.value !== "}") {
    const name = ts.next();
    if (name.kind !== "name") throw new Error("expected a field name");
    const args = ts.peek()?.value === "(" ? parseArgs(ts) : {};
    const selection = ts.peek()?.value === "{" ? parseSelectionSet(ts) : [];
    fields.push({ name: name.value, args, selection });
  }
  ts.expectPunct("}");
  return fields;
}

function parseGraphQL(src: string): { fields: GqlField[] } | { error: string } {
  try {
    const ts = new TokenStream(tokenize(src));
    if (ts.peek()?.kind === "name" && (ts.peek()?.value === "query" || ts.peek()?.value === "mutation")) {
      ts.next();
      if (ts.peek()?.kind === "name") ts.next(); // optional operation name
    }
    const fields = parseSelectionSet(ts);
    if (!ts.atEnd()) throw new Error("unexpected trailing input");
    return { fields };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

const INTROSPECTION_SCHEMA = "type Query { order(id: ID!): Order }\ntype Order { id owner item price related_order }";

// ---------------------------------------------------------------------------

function formatYen(n: number): string {
  return `¥${n.toLocaleString("ja-JP")}`;
}

function formatOrder(order: OrderRow, leakRelated: boolean): string {
  const who = order.owner_username === ALICE ? "Alice" : "Bob";
  const related = leakRelated && order.related_order_id ? `\nrelated_order: ${order.related_order_id}` : "";
  return `[200 OK] ${who} / ${order.id} / ${order.item} / ${formatYen(order.price_yen)}${related}`;
}

interface Resolved {
  shown?: OrderRow;
  leaked: boolean;
  reason: string;
  introspection?: string;
}

/**
 * Decides what a /graphql request asks for. An explicit query goes through the
 * real parser (introspection, `order(id: ...)`). The "GraphQL (dev)" tab's
 * default call is `order(id: <orderId>)`, so when the query is empty -- or is
 * valid but selects neither `__schema` nor `order` -- and an `orderId` is
 * supplied, that default resolver call is assumed. Syntax errors are never
 * papered over.
 */
function planGraphql(query: string, orderId: string): { orderId: string } | { early: Resolved } {
  if (query.trim() === "") {
    return orderId
      ? { orderId }
      : { early: { leaked: false, reason: "対応していないクエリです。" } };
  }
  const parsed = parseGraphQL(query);
  if ("error" in parsed) return { early: { leaked: false, reason: `GraphQL 構文エラー: ${parsed.error}` } };
  if (parsed.fields.some((f) => f.name === "__schema")) {
    return { early: { leaked: false, reason: "introspection で Order 型が見つかりました。", introspection: INTROSPECTION_SCHEMA } };
  }
  const orderField = parsed.fields.find((f) => f.name === "order");
  if (orderField) return { orderId: String(orderField.args.id ?? "") };
  return orderId ? { orderId } : { early: { leaked: false, reason: "対応していないクエリです。" } };
}

function resolveOrder(level: Level, db: DatabaseSync, input: LabInput): Resolved {
  const orderIdRaw = (input.orderId ?? "").trim();
  const ownerRaw = (input.owner ?? ALICE).trim().toLowerCase();
  const endpoint = (input.endpoint ?? "/api/orders").trim();
  const query = input.query ?? "";
  const isExport = /\/api\/export/i.test(endpoint);
  const isGraphql = /\/graphql/i.test(endpoint);

  const ownOrDeny = (row: OrderRow | undefined, deniedReason: string): Resolved => {
    if (row && row.owner_username === ALICE) return { shown: row, leaked: false, reason: "自分の注文を表示しました。" };
    if (row) return { leaked: false, reason: deniedReason };
    return { leaked: false, reason: "注文が見つからないか、権限がありません。" };
  };

  if (level === 1) {
    const row = findByLegacyOrId(db, orderIdRaw);
    if (!row) return { leaked: false, reason: "注文が見つかりません。" };
    if (row.owner_username !== ALICE) return { shown: row, leaked: true, reason: "連番 ID だけで注文を取得しました。" };
    return { shown: row, leaked: false, reason: "自分の注文を表示しました。" };
  }

  if (level === 2) {
    const row = findById(db, orderIdRaw);
    if (!row) return { leaked: false, reason: "不正な注文 ID、または所有者です。" };
    if (ownerRaw !== row.owner_username) return { leaked: false, reason: "不正な注文 ID、または所有者です。" };
    if (row.owner_username !== ALICE) return { shown: row, leaked: true, reason: "owner パラメータを信用して Bob の注文を取得しました。" };
    return { shown: row, leaked: false, reason: "自分の注文を表示しました。" };
  }

  if (level === 3) {
    const row = findById(db, orderIdRaw);
    if (isExport) {
      if (!row) return { leaked: false, reason: "注文が見つかりません。" };
      if (row.owner_username !== ALICE) return { shown: row, leaked: true, reason: "CSV エクスポート API に所有者チェックがありません。" };
      return { shown: row, leaked: false, reason: "自分の注文を表示しました。" };
    }
    return ownOrDeny(row, "注文 API はセッションユーザーと所有者を照合しました。");
  }

  if (level === 4) {
    if (isGraphql) {
      const plan = planGraphql(query, orderIdRaw);
      if ("early" in plan) return plan.early;
      const row = findById(db, plan.orderId);
      if (!row) return { leaked: false, reason: "該当する注文がありません。" };
      if (row.owner_username !== ALICE) return { shown: row, leaked: true, reason: "GraphQL の order クエリにオブジェクト単位の認可がありません。" };
      return { shown: row, leaked: false, reason: "自分の注文を表示しました。" };
    }
    const row = findById(db, orderIdRaw);
    return ownOrDeny(row, isExport ? "エクスポート API もセッションユーザーと所有者を照合しています。" : "REST・エクスポートは所有者を確認しています。");
  }

  // Level 5: every route checks the authenticated subject's ownership.
  if (isGraphql) {
    const plan = planGraphql(query, orderIdRaw);
    if ("early" in plan) return plan.early;
    const row = findById(db, plan.orderId);
    return ownOrDeny(row, "GraphQL リゾルバがセッションユーザーと所有者を照合しました。");
  }
  const row = findById(db, orderIdRaw);
  return ownOrDeny(row, "認証済みユーザー alice と注文の所有者が一致しないため拒否しました。");
}

function run(level: Level, input: LabInput): AttackResult {
  const db = openDb();
  try {
    const orderIdRaw = (input.orderId ?? "").trim();
    const ownerRaw = (input.owner ?? ALICE).trim();
    const roleRaw = (input.role ?? "user").trim().toLowerCase();
    const endpoint = (input.endpoint ?? "/api/orders").trim();
    const isGraphql = /\/graphql/i.test(endpoint);

    const resolved = resolveOrder(level, db, input);
    const { shown, leaked, reason, introspection } = resolved;
    const leakRelated = !!shown && shown.owner_username === ALICE && level >= 3 && !!shown.related_order_id;

    const path = endpoint.includes(BOB_ORDER) ? endpoint : `${endpoint}/${orderIdRaw}`;
    const body = introspection ?? (shown ? formatOrder(shown, leakRelated) : `[403 FORBIDDEN] ${reason}`);
    const output = [isGraphql ? `POST ${endpoint}` : `GET ${path}`, `認証ユーザー: alice / owner=${ownerRaw} / role=${roleRaw}`, body];

    const loot: LootItem[] = leakRelated && shown?.related_order_id ? [{ id: "idor-related", label: "Bob の注文 ID", value: shown.related_order_id }] : [];

    return {
      solved: leaked,
      output,
      progress: !leaked && (leakRelated || introspection !== undefined),
      benign: !!shown && !leaked && !leakRelated,
      note: leaked ? "他人の注文情報へアクセスできました。" : leakRelated ? "自分の注文です。応答の関連フィールドを確認してください。" : reason,
      assembled: isGraphql ? `resolver order(${orderIdRaw || "…"})` : `GET ${path}  authorize(alice, owner=${ownerRaw})`,
      recap: leaked
        ? level >= 3
          ? ["自分の注文から related_order が漏れた", `${endpoint} に所有者チェックがなかった`, "Bob の注文が返った"]
          : ["注文 ID の所有者を確認していなかった", "他人の注文が返った"]
        : undefined,
      loot: loot.length ? loot : undefined,
    };
  } finally {
    db.close();
  }
}

export const idorRealLab: RealLab = { id: "idor", run };
