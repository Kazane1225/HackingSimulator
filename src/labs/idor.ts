import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

const BOB_ORDER = "ORD-B0B-42";

interface Order {
  id: string;
  owner: string;
  item: string;
  price: string;
}

const ALICE: Order = {
  id: "1001",
  owner: "alice",
  item: "USB-C ケーブル",
  price: "¥2,480",
};

const BOB: Order = {
  id: BOB_ORDER,
  owner: "bob",
  item: "法人向けセキュリティキー",
  price: "¥89,800",
};

function format(order: Order, leakRelated = false): string {
  const who = order.owner === "alice" ? "Alice" : "Bob";
  const related = leakRelated ? `\nrelated_order: ${BOB_ORDER}` : "";
  return `[200 OK] ${who} / ${order.id} / ${order.item} / ${order.price}${related}`;
}

function isAliceOrder(orderId: string, endpoint: string): boolean {
  return orderId === ALICE.id && !endpoint.includes(BOB_ORDER);
}

function run(level: Level, input: LabInput): AttackResult {
  const query = input.query ?? "";
  const orderId = (input.orderId ?? "").trim();
  const owner = (input.owner ?? "alice").trim();
  const role = (input.role ?? "user").trim().toLowerCase();
  const endpoint = (input.endpoint ?? "/api/orders").trim();
  const blob = `${endpoint} ${orderId} ${query}`;
  const askedBob = orderId === BOB_ORDER || blob.includes(BOB_ORDER);

  let shown: Order | null = null;
  let leaked = false;
  let reason = "注文が見つからないか、権限がありません。";

  if (level === 1) {
    if (orderId === "1002" || orderId === BOB_ORDER) {
      shown = BOB;
      leaked = true;
      reason = "連番 ID だけで注文を取得しました。";
    } else if (isAliceOrder(orderId, endpoint)) {
      shown = ALICE;
      reason = "自分の注文を表示しました。";
    }
  } else if (level === 2) {
    if (orderId === BOB_ORDER && owner === "bob") {
      shown = BOB;
      leaked = true;
      reason = "owner パラメータを信用して Bob の注文を取得しました。";
    } else if (isAliceOrder(orderId, endpoint) && owner === "alice") {
      shown = ALICE;
      reason = "自分の注文を表示しました。";
    } else {
      reason = "不正な注文 ID、または所有者です。";
    }
  } else if (level === 3) {
    if (/\/api\/export/i.test(endpoint) && orderId === BOB_ORDER) {
      shown = BOB;
      leaked = true;
      reason = "CSV エクスポート API に所有者チェックがありません。";
    } else if (orderId === BOB_ORDER) {
      reason = "注文 API はセッションユーザーと所有者を照合しました。";
    } else if (isAliceOrder(orderId, endpoint)) {
      shown = ALICE;
      reason = "自分の注文を表示しました。";
    }
  } else if (level === 4) {
    if (/\/graphql/i.test(endpoint) && /__schema/i.test(query) && !askedBob) {
      reason = "introspection で Order 型が見つかりました。";
    } else if (/\/graphql/i.test(endpoint) && askedBob) {
      shown = BOB;
      leaked = true;
      reason = "GraphQL の order クエリにオブジェクト単位の認可がありません。";
    } else if (isAliceOrder(orderId, endpoint)) {
      shown = ALICE;
      reason = "自分の注文を表示しました。";
    } else {
      reason = "REST・エクスポートは所有者を確認しています。";
    }
  } else if (isAliceOrder(orderId, endpoint)) {
    shown = ALICE;
    reason = "自分の注文を表示しました。";
  } else {
    reason = "認証済みユーザー alice と注文の所有者が一致しないため拒否しました。";
  }

  const path = endpoint.includes(BOB_ORDER) ? endpoint : `${endpoint}/${orderId || ""}`;
  const leakRelated = shown === ALICE && level >= 3;
  const introspect = /\/graphql/i.test(endpoint) && /__schema/i.test(query) && !leaked;
  const loot = leakRelated ? [{ id: "idor-related", label: "Bob の注文 ID", value: BOB_ORDER }] : [];
  const output = [
    /\/graphql/i.test(endpoint) ? `POST ${endpoint}` : `GET ${path}`,
    `認証ユーザー: alice / owner=${owner} / role=${role}`,
    introspect
      ? `type Query { order(id: ID!): Order }\ntype Order { id owner item price related_order }`
      : shown
        ? format(shown, leakRelated)
        : `[403 FORBIDDEN] ${reason}`,
  ];
  return traced(
    {
      solved: leaked,
      progress: !leaked && (leakRelated || introspect),
      benign: !!shown && !leaked && !leakRelated && !introspect,
      output,
      note: leaked
        ? "他人の注文情報へアクセスできました。"
        : leakRelated
          ? "自分の注文です。応答の関連フィールドを確認してください。"
          : introspect
            ? reason
            : reason,
    },
    /\/graphql/i.test(endpoint)
      ? `resolver order(${orderId || query || "…"})  // 認可なし`
      : `GET ${path}  authorize(alice, owner=${owner})`,
    {
      recap: leaked
        ? level >= 3
          ? ["自分の注文から related_order が漏れた", `${endpoint} に所有者チェックがなかった`, "Bob の注文が返った"]
          : ["注文 ID の所有者を確認していなかった", "他人の注文が返った"]
        : undefined,
      loot: loot.length ? loot : undefined,
    },
  );
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "認証のみ。注文 ID とログインユーザーの所有関係を確認しない。",
    hints: [
      "画面に出ているのは自分の注文だけです。URL の注文番号は誰が決めていますか？",
      "自分の注文 1001 の隣には、別ユーザーの注文がありそうです。",
      "Proxy で `orderId` を `1002` に書き換えて送信します。",
    ],
    solution: "Proxy で注文 ID を `1002` に変更すると、Bob の注文が表示されます。",
    code: `const order = db.orders.find(req.params.id);
return res.json(order); // 所有者を確認していない`,
  },
  2: {
    defense: "推測しにくい注文 ID を使うが、owner パラメータを信用する。",
    hints: [
      "ランダムな ID は認可の代わりにはなりません。",
      "リクエスト内の owner はサーバーが確定した値でしょうか？",
      "`orderId=ORD-B0B-42` と `owner=bob` を送ります。",
    ],
    solution: "注文 ID を `ORD-B0B-42`、owner を `bob` に改ざんします。",
    code: `const order = db.orders.find(req.params.id);
if (order.owner !== req.query.owner) deny(); // 攻撃者が owner を指定できる`,
  },
  3: {
    defense: "注文 GET は所有者を検証する。一括エクスポート API には認可がない。",
    hints: [
      "owner や role の改ざんは、注文 API では効かなくなりました。連番 `1002` ももう使えません。",
      "自分の注文 1001 を表示すると、応答に related_order が付きませんか？",
      "endpoint を `/api/export` にし、漏れた related_order を付けます。",
    ],
    solution:
      "自分の注文応答の `related_order`（`ORD-B0B-42`）を `/api/export` に付けます。CSV 出力用 API が認可をスキップしています。",
    code: `app.get("/api/orders/:id", requireOwner, getOrder);
app.get("/api/export", (req, res) => {
  return csv(db.orders.find(req.query.id)); // 認可なし
});`,
  },
  4: {
    defense: "REST とエクスポートは所有者を検証する。GraphQL リゾルバだけ認可がない。",
    hints: [
      "エクスポートも塞がれました。店の画面に『GraphQL (dev)』タブはありませんか？",
      "`{ __schema { types { name } } }` で型を見られます。REST の認可はここを通りません。",
      "Lv3 で見た related_order を GraphQL の order に載せます。連番 ID は通りません。",
    ],
    solution: "`POST /graphql` 相当として endpoint `/graphql`、`orderId=ORD-B0B-42` を送ります。order リゾルバが所有者を見ていません。",
    code: `app.use("/api", requireOwner);
const resolvers = {
  order: (_, { id }) => db.orders.find(id), // 認可なし
};`,
  },
  5: {
    defense: "すべての経路で、サーバー側のユーザー ID と所有者を検証する。",
    hints: [
      "識別子の秘密性ではなく、オブジェクト単位の認可が必要です。",
      "別経路も含め共通の認可ミドルウェアを適用するため、突破できません。",
    ],
    solution: "突破不可能です。全エンドポイントがセッション由来の主体で所有権を検証します。",
    code: `const order = await db.orders.find(req.params.id);
if (order.ownerId !== req.user.id && !req.user.isAdmin) deny();
return res.json(order);`,
  },
};

export const idorLab: Lab = {
  meta: {
    id: "idor",
    title: "IDOR — 注文情報の越権閲覧",
    shortTitle: "IDOR",
    category: "アクセス制御",
    objective: "alice としてログインしたまま、Bob の注文情報を取得する。",
    summary: "識別子やパラメータを書き換え、オブジェクト単位の認可不備を見つける。",
    standards: {
      owasp: {
        code: "A01:2021",
        name: "Broken Access Control",
        url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
      },
      cwe: [{ id: 639, name: "Authorization Bypass Through User-Controlled Key" }],
    },
    references: [
      { title: "OWASP IDOR Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html" },
      { title: "PortSwigger — Access control vulnerabilities and privilege escalation", url: "https://portswigger.net/web-security/access-control" },
    ],
  },
  fields: [
    { name: "orderId", label: "注文 ID", default: "1001", mono: true },
    { name: "endpoint", label: "endpoint", default: "/api/orders", mono: true, hidden: true },
    { name: "owner", label: "owner", default: "alice", mono: true, hidden: true },
    { name: "role", label: "role", default: "user", mono: true, hidden: true },
    { name: "query", label: "GraphQL query", default: "", multiline: true, mono: true, hidden: true },
  ],
  explanation: `IDOR（Insecure Direct Object Reference）は、URL や API の ID を変更した利用者に対し、サーバーが対象データへの権限を確認しない脆弱性です。連番を UUID に変えても、ID が漏れた場合の越権アクセスは防げません。

認可判断には、リクエストで自由に変更できる owner や role ではなく、検証済みセッションのユーザー情報を使います。自分の注文応答に他人の ID を混ぜるのも漏洩です。画面用 REST を直しても、エクスポートや GraphQL など同じデータへ到達する経路が残れば越権は成立します。すべての経路で共通の認可を適用します。`,
  levels,
  run,
  exploits: {
    1: { endpoint: "/api/orders", orderId: "1002", owner: "alice", role: "user" },
    2: { endpoint: "/api/orders", orderId: BOB_ORDER, owner: "bob", role: "user" },
    3: { endpoint: "/api/export", orderId: BOB_ORDER, owner: "alice", role: "user" },
    4: { endpoint: "/graphql", orderId: BOB_ORDER, owner: "alice", role: "user" },
  },
};
