import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

/**
 * Security Misconfiguration (A05). A debug endpoint, an actuator, and a
 * downloaded .env are left on. Each level closes the previous door and
 * leaves a different one.
 */

const FLAG = "FLAG{m1sc0nf1g}";

function hit(path: string, note: string): AttackResult {
  return traced(
    {
      solved: true,
      output: [`GET ${path}`, FLAG, "設定情報が見えています。"],
      note,
    },
    `GET ${path}`,
    { recap: ["本番に残った入口を開いた", "秘密が応答に含まれた"], loot: [{ id: "misconf-flag", label: "設定の秘密", value: FLAG }] },
  );
}

function miss(path: string, note: string): AttackResult {
  const home = path === "/" || path === "/health";
  return traced(
    {
      solved: false,
      benign: home,
      output: home ? [`GET ${path}`, "Welcome"] : [`GET ${path}`, "404"],
      note,
    },
    `GET ${path}`,
  );
}

function run(level: Level, input: LabInput): AttackResult {
  const path = input.path ?? "/";
  if (level === 5) {
    if (path === "/" || path === "/health") return miss(path, "公開してよいパスだけを許可しています。");
    return miss(path, "デバッグもドットファイルも配信していません。");
  }
  if (level === 1) {
    if (path === "/debug") return hit(path, "デバッグモードが本番で有効です。");
    return miss(path, "公開ページです。デバッグ入口は別にあります。");
  }
  if (level === 2) {
    if (path === "/debug") return miss(path, "パス文字列 /debug だけを拒否しています。");
    if (path === "/debug/") return hit(path, "末尾スラッシュを付けただけでデバッグが開きました。");
    return miss(path, "そのパスは配信していません。");
  }
  if (level === 3) {
    const trimmed = path.replace(/\/+$/, "") || "/";
    if (trimmed === "/debug") return miss(path, "正規化後の /debug は閉じています。別の管理ポートが残っています。");
    if (path === "/actuator/env") return hit(path, "Spring Actuator の env が認証なしで開いています。");
    return miss(path, "そのパスは配信していません。");
  }
  if (path === "/debug" || path === "/debug/" || path === "/actuator/env") {
    return miss(path, "デバッグと Actuator は停止しています。静的ファイルの置き方を見てください。");
  }
  if (path === "/.env") return hit(path, "環境ファイルが公開ディレクトリに残っています。");
  return miss(path, "そのパスは配信していません。");
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。本番でも /debug が開いている。",
    hints: [
      "トップページ以外に、開発用のパスが残っていませんか？",
      "ソースは GET /debug を無条件で返しています。",
      "path を `/debug` にしてください。",
    ],
    solution: "path に `/debug` を指定します。デバッグ画面が本番で有効なままです。",
    code: `app.get("/debug", (req, res) => res.send(secrets)); // NODE_ENV を見ていない`,
  },
  2: {
    defense: "パスが文字列 /debug と完全一致するときだけ拒否する。",
    hints: [
      "完全一致の拒否は、少し違う書き方を通しがちです。",
      "同じハンドラへ届く、末尾が違うパスがソースにあります。",
      "path を `/debug/` にしてください。",
    ],
    solution: "path を `/debug/` にします。拒否は `/debug` と等しいときだけです。",
    code: `if (req.path === "/debug") return res.status(404).end();
app.get("/debug/", leak);`,
  },
  3: {
    defense: "末尾スラッシュを落として /debug を拒否する。Actuator は別。",
    hints: [
      "デバッグの表記ゆれは塞がっています。フレームワーク付属の管理 URL は別です。",
      "ソースに /actuator/env が残っています。",
      "path を `/actuator/env` にしてください。",
    ],
    solution: "path を `/actuator/env` にします。アプリ本体を直しても、有効なままの Actuator が秘密を返します。",
    code: `if (normalize(req.path) === "/debug") return deny();
app.get("/actuator/env", leak); // 依存のデフォルトを止めていない`,
  },
  4: {
    defense: "デバッグと Actuator は停止。公開フォルダに .env が残っている。",
    hints: [
      "管理 URL はもう返りません。設定ファイルそのものが置かれていないか見てください。",
      "ドットで始まるファイルは、静的配信の対象から外し忘れがちです。",
      "path を `/.env` にしてください。",
    ],
    solution: "path を `/.env` にします。秘密が公開ディレクトリへコピーされたままです。",
    code: `app.use(express.static("public")); // public/.env がデプロイに含まれている`,
  },
  5: {
    defense: "公開パスは / と /health だけ。デバッグもドットファイルも無い。",
    hints: [
      "知らないパスは 404 です。許可リストに秘密の入口はありません。",
      "本番設定ではデバッグ機能と環境ファイルの配信を両方止める、という対策です。",
    ],
    solution: "突破できません。管理エンドポイントを無効にし、公開ディレクトリに秘密を置かず、許可したパスだけ返します。",
    code: `if (req.path !== "/" && req.path !== "/health") return res.status(404).end();`,
  },
};

export const misconfLab: Lab = {
  meta: {
    id: "misconf",
    title: "セキュリティ設定ミス — 残った管理口",
    shortTitle: "設定ミス",
    category: "設定",
    objective: "本番に残った入口から、設定に含まれる秘密を読む。",
    summary: "デバッグ、Actuator、公開された .env など、止め忘れた入口を順に探す。",
    standards: {
      owasp: { code: "A05:2021", name: "Security Misconfiguration", url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
      cwe: [{ id: 16, name: "Configuration" }],
    },
    references: [
      { title: "OWASP Security Misconfiguration", url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
      { title: "OWASP Configuration Cheat Sheet (Error Handling, debugging)", url: "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html" },
    ],
  },
  fields: [{ name: "path", label: "path", default: "/", mono: true }],
  explanation: `セキュリティ設定ミスは、本番でデバッグを有効にしたままにする、フレームワークの管理エンドポイントを止めない、秘密ファイルを公開ディレクトリに含める、といった『止め忘れ』です。文字列が完全一致する拒否は、末尾のスラッシュだけで外れます。

レベルが上がると、前の入口は本当に閉じ、別の止め忘れが残ります。禁止パスを増やすだけでは、次のデフォルト設定は塞げません。

根本対策は Lv5 です。公開してよいパスだけを許可し、デバッグ機能と環境ファイルを配信しないことです。`,
  levels,
  run,
  exploits: {
    1: { path: "/debug" },
    2: { path: "/debug/" },
    3: { path: "/actuator/env" },
    4: { path: "/.env" },
  },
};
