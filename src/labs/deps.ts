import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

/**
 * Vulnerable and Outdated Components (A06). A thumbnail library decodes the
 * file parameter itself, so the app's check and the library disagree. The
 * fixed release still leaves the old engine switch on.
 */

const FLAG = "FLAG{old_component}";
const SECRET = "etc/thumbx/secret";

function decodePct(value: string): string {
  return value.replace(/%([0-9a-fA-F]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
}

function hits(file: string): boolean {
  const norm = file.replace(/\\/g, "/");
  return norm === `/${SECRET}` || norm.endsWith(`/${SECRET}`) || norm.endsWith(SECRET);
}

function leak(file: string, note: string): AttackResult {
  return traced(
    {
      solved: true,
      output: [`ThumbX file=${file}`, FLAG],
      note,
    },
    `thumbx.read(${file})`,
    { recap: ["古いコンポーネントの解釈でパスが通った", "秘密ファイルが返った"], loot: [{ id: "deps-flag", label: "コンポーネントの秘密", value: FLAG }] },
  );
}

function blocked(file: string, note: string): AttackResult {
  const benign = file === "logo.png";
  return traced(
    {
      solved: false,
      benign,
      output: benign ? [`ThumbX file=${file}`, "PNG logo"] : [`ThumbX file=${file}`, "rejected"],
      note,
    },
    `thumbx.read(${file})`,
  );
}

function run(level: Level, input: LabInput): AttackResult {
  const file = input.file ?? "logo.png";
  const engine = input.engine ?? "current";

  if (level === 5) {
    if (engine === "legacy") return blocked(file, "旧エンジンは削除されています。");
    if (!/^[A-Za-z0-9._-]+$/.test(file)) return blocked(file, "ファイル名は公開ディレクトリ内の一語だけです。");
    return blocked(file, "ThumbX 2.0 は指定ファイルを公開ディレクトリの外から読みません。");
  }

  if (level === 4) {
    if (engine === "legacy") {
      return hits(file) ? leak(file, "engine=legacy が ThumbX 1.2 をまだ呼び出します。") : blocked(file, "旧エンジンでも、そのファイルはありません。");
    }
    const decoded = decodePct(decodePct(file));
    if (decoded.includes("..") || decoded.startsWith("/")) return blocked(file, "現行エンジンはトラバーサルを拒否します。古いエンジンが残っています。");
    return blocked(file === "logo.png" ? file : decoded, "現行バージョンはこのファイルを返しません。");
  }

  if (level === 1) {
    return hits(file) ? leak(file, "ThumbX 1.2 が file をそのまま開きました。") : blocked(file, "公開画像です。");
  }

  if (level === 2) {
    if (file.includes("..")) return blocked(file, "アプリは '..' を拒否しています。ライブラリは百分率符号化を自分で解きます。");
    const decoded = decodePct(file);
    return hits(decoded) ? leak(file, "検査のあと ThumbX が %2e%2e を '..' に戻しました。") : blocked(file, "そのファイルはありません。");
  }

  const once = decodePct(file);
  if (once.includes("..")) return blocked(file, "1 回復号したあとの '..' は拒否しています。コンポーネントはもう一度復号します。");
  const twice = decodePct(once);
  return hits(twice) ? leak(file, "二重に符号化された '..' が、検査のあとで展開されました。") : blocked(file, "そのファイルはありません。");
}

const lv2 = "%2e%2e/%2e%2e/etc/thumbx/secret";
const lv3 = encodeURIComponent(lv2);

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。ThumbX 1.2 が file をそのまま開く。",
    hints: [
      "ソースのライブラリは、渡されたパスを検証せずに読みます。",
      "公開画像 logo.png 以外に、コンポーネント用の秘密ファイルがあります。",
      "file を `../../etc/thumbx/secret` にしてください。",
    ],
    solution: "file に `../../etc/thumbx/secret` を渡します。既知の弱いバージョンがパスをそのまま開きます。",
    code: `// thumbx@1.2.0 — CVE 例: file を検証しない
fs.readFileSync(req.query.file);`,
  },
  2: {
    defense: "アプリが '..' を拒否。ライブラリは拒否のあとで %2e を復号する。",
    hints: [
      "Lv1 の '..' はアプリ側で止まります。止めたあと誰が復号するかを見てください。",
      "ドットを百分率符号化すると、検査時点では '..' に見えません。",
      "file を `%2e%2e/%2e%2e/etc/thumbx/secret` にしてください。",
    ],
    solution: "`%2e%2e/%2e%2e/etc/thumbx/secret` を渡します。アプリの検査を抜けたあと、古い ThumbX が復号します。",
    code: `if (file.includes("..")) return reject();
thumbx.open(file); // 内部で decodeURIComponent`,
  },
  3: {
    defense: "1 回復号してから '..' を拒否。ライブラリはさらにもう 1 回復号する。",
    hints: [
      "1 回だけの復号では、%2e%2e はもう通りません。",
      "百分率記号そのものを符号化すると、1 回目の復号で %2e に戻ります。",
      "Lv2 の文字列全体を、もう一度百分率符号化してください。",
    ],
    solution: "`%252e%252e%252f...` のように二重符号化します。検査は 1 回目だけ、ライブラリは 2 回目も復号します。",
    code: `const once = decodeURIComponent(file);
if (once.includes("..")) return reject();
thumbx.open(once); // ThumbX 1.3 は内部でもう一度復号する`,
  },
  4: {
    defense: "現行エンジンはトラバーサルを拒否。engine=legacy だと 1.2 に戻る。",
    hints: [
      "現行の file 解釈はもう秘密を読みません。ソースに旧実装への切替があります。",
      "Proxy で engine を足せます。",
      "engine を `legacy` にし、Lv1 のパスを再度渡してください。",
    ],
    solution: "engine を `legacy`、file を `../../etc/thumbx/secret` にします。修正版へ上げても旧エンドポイントが残っています。",
    code: `const lib = req.query.engine === "legacy" ? thumbx12 : thumbx20;
lib.open(file);`,
  },
  5: {
    defense: "ThumbX 2.0 のみ。ファイル名は公開ディレクトリ内の安全な一語。",
    hints: [
      "legacy は存在せず、`..` も `%` もファイル名として拒否されます。",
      "依存を上げるだけでなく、古い入口を消し、渡す値をファイル名だけに限定する対策です。",
    ],
    solution: "突破できません。脆弱なバージョンを残さず、ライブラリへは公開ディレクトリ内のファイル名だけを渡します。",
    code: `if (engine !== "current") return reject();
if (!/^[A-Za-z0-9._-]+$/.test(file)) return reject();
thumbx20.open(path.join(PUBLIC, file));`,
  },
};

export const depsLab: Lab = {
  meta: {
    id: "deps",
    title: "脆弱なコンポーネント — 古いサムネイルライブラリ",
    shortTitle: "古いコンポーネント",
    category: "依存関係",
    objective: "既知の弱い ThumbX 経由で、コンポーネント用の秘密ファイルを読む。",
    summary: "検査とライブラリの復号順のずれ、二重符号化、残った旧エンジンを使う。",
    standards: {
      owasp: {
        code: "A06:2021",
        name: "Vulnerable and Outdated Components",
        url: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
      },
      cwe: [{ id: 1104, name: "Use of Unmaintained Third Party Components" }],
    },
    references: [
      { title: "OWASP Vulnerable and Outdated Components", url: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/" },
      { title: "OWASP Vulnerable Dependency Management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html" },
    ],
  },
  fields: [
    { name: "file", label: "file", default: "logo.png", mono: true },
    { name: "engine", label: "engine", default: "current", mono: true, hidden: true },
  ],
  explanation: `脆弱なコンポーネントは、アプリ本体を直してもライブラリが古いと残ります。このラボの ThumbX は file を自分で百分率復号します。アプリが先に '..' を拒んでも、復号が検査のあとなら \`%2e%2e\` が通ります。1 回復号してから拒んでも、二重符号化は 2 回目で '..' に戻ります。

バージョンを上げても、\`engine=legacy\` が旧実装を呼ぶなら修正は届きません。前のレベルの書き方は、次のレベルでは別の理由で止まります。

根本対策は Lv5 です。脆弱な版を残さず、ライブラリへ渡すのは公開ディレクトリ内のファイル名だけにします。`,
  levels,
  run,
  exploits: {
    1: { file: "../../etc/thumbx/secret", engine: "current" },
    2: { file: lv2, engine: "current" },
    3: { file: lv3, engine: "current" },
    4: { file: "../../etc/thumbx/secret", engine: "legacy" },
  },
};
