import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

/**
 * Security Logging and Monitoring Failures (A09). The account is always
 * guest. Early levels forge a log line. Lv4 runs a hidden operation while
 * the log records a different action.
 */

const FLAG = "FLAG{l0g_1nj3ct}";
const FORGED = "user=admin action=export";

function stripNl(value: string): string {
  return value.replace(/\n/g, "");
}

function stripCrLf(value: string): string {
  return value.replace(/[\r\n]/g, "");
}

/** A one-line field cannot hold a raw CR. `\n` and `\r` in the text become the control characters. */
function controls(value: string): string {
  return value.replace(/\\r/g, "\r").replace(/\\n/g, "\n");
}

function forgedLines(log: string, splitCr: boolean): boolean {
  const lines = splitCr ? log.split(/\r|\n/) : log.split("\n");
  return lines.some((line) => line === FORGED);
}

function done(solved: boolean, log: string, note: string): AttackResult {
  return traced(
    {
      solved,
      benign: !solved && (log.includes("action=view") || log.includes('"action":"view"')),
      output: ["log:", log, ...(solved ? [FLAG] : [])],
      note,
    },
    "audit.log",
    solved ? { recap: ["監視が見る記録と、実際の操作がずれた", "admin の export として扱われた"], loot: [{ id: "logging-flag", label: "記録の穴", value: FLAG }] } : undefined,
  );
}

function run(level: Level, input: LabInput): AttackResult {
  const note = controls(input.user ?? "");
  const action = controls(input.action ?? "view");

  if (level === 1) {
    const log = `user=guest action=${action} note=${note}`;
    const solved = forgedLines(log, false);
    return done(solved, log, solved ? "改行で、admin の export という別の行が記録されました。" : "guest の操作として 1 行記録しました。");
  }

  if (level === 2) {
    const log = `user=guest action=${stripNl(action)} note=${stripNl(note)}`;
    const solved = forgedLines(log, true);
    return done(solved, log, solved ? "復帰文字が行区切りになり、偽のイベントが残りました。" : "改行は取り除きました。");
  }

  if (level === 3) {
    const log = `{"user":"guest","action":"${stripCrLf(action)}","note":"${stripCrLf(note)}"}`;
    let solved = false;
    try {
      const parsed = JSON.parse(log) as { user?: string; action?: string };
      solved = parsed.user === "admin" && parsed.action === "export";
    } catch {
      solved = false;
    }
    return done(solved, log, solved ? "JSON の文字列を閉じて、別の user と action を足しました。" : "改行は取り除きました。ログは JSON です。");
  }

  if (level === 4) {
    const recorded = stripCrLf(action);
    const performed = stripCrLf(input.op ?? "") || recorded;
    const log = JSON.stringify({ user: "guest", action: recorded, note: stripCrLf(note) });
    const solved = performed === "export" && recorded !== "export";
    return done(solved, log, solved ? "実行したのは export ですが、ログの action は別の値です。" : "ログに残る action と、実行した操作は同じです。");
  }

  const recorded = /^[a-z]{1,16}$/.test(action) ? action : "view";
  const log = JSON.stringify({
    user: "guest",
    action: recorded,
    note: stripCrLf(note),
    result: recorded === "export" ? "denied" : "ok",
  });
  return traced(
    {
      solved: false,
      benign: recorded === "view",
      output: ["log:", log],
      note: "記録は実行した操作そのものです。guest の export は拒否されます。",
    },
    "audit.write(structured)",
  );
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。メモをログ行へそのまま連結する。",
    hints: [
      "ログイン中のユーザーは guest のままです。メモはログの末尾に連結されます。",
      "ログは 1 行が 1 イベントです。メモに書いた `\\n` は改行になります。",
      "user を `\\nuser=admin action=export` にしてください。",
    ],
    solution: "user に `\\nuser=admin action=export` を入れます。監視はその行を admin の export として読みます。",
    code: `log(\`user=guest action=\${action} note=\${user}\`); // user の改行を残している`,
  },
  2: {
    defense: "メモと action から改行 \\n だけを除く。\\r は残る。",
    hints: [
      "Lv1 の `\\n` は取り除かれ、1 行のままです。",
      "復帰 `\\r` は残っています。監視側は `\\r` も行の区切りとして読みます。",
      "user を `\\ruser=admin action=export` にしてください。",
    ],
    solution: "`\\n` の代わりに `\\r` を使います。アプリは改行だけを除き、監視は復帰でも行を分けます。",
    code: `note = note.replace(/\\n/g, "");
log(note); // \\r は残る。監視は \\r でも改行する`,
  },
  3: {
    defense: "\\r と \\n を除き、ログは 1 個の JSON。メモは文字列として埋め込んでいる。",
    hints: [
      "改行では行を増やせません。ログは JSON オブジェクトです。",
      "メモは引用符の中に、エスケープせず入っています。",
      "user で note の文字列を閉じ、`\"user\":\"admin\",\"action\":\"export\"` を足してください。",
    ],
    solution: 'user を `","user":"admin","action":"export","x":"` にします。引用符を閉じると、後のキーが user と action を上書きします。',
    code: `log('{"user":"guest","action":"' + action + '","note":"' + note + '"}');`,
  },
  4: {
    defense: "JSON としてエスケープして記録する。実行する操作は隠しパラメータ op。",
    hints: [
      "引用符は文字列の中に残り、JSON の構造は壊れません。",
      "ログに残るのは action です。実行が参照する別のパラメータがソースにあります。",
      "action は `view` のまま、op を `export` にしてください。",
    ],
    solution: "action を view、op を export にします。ログは閲覧のまま、実行は export です。",
    code: `audit({ action });          // 監視が見る値
perform(op || action);       // 実際に動く値`,
  },
  5: {
    defense: "op は無く、実行した action だけを構造化ログに残す。guest の export は拒否。",
    hints: [
      "隠し操作は呼ばれません。ログの action は、実際に扱った値です。",
      "これは、記録と実行を同じ値にし、外から行を足せないようにする対策です。",
    ],
    solution: "突破できません。ログは実行した操作そのもので、guest による export は拒否してその旨を記録します。",
    code: `if (action === "export") return deny();
audit({ user: "guest", action, result: "ok" });`,
  },
};

export const loggingLab: Lab = {
  meta: {
    id: "logging",
    title: "ログと監視の失敗 — 記録と操作のずれ",
    shortTitle: "ログの穴",
    category: "ログ",
    objective: "監視が admin の export だと読む記録を残すか、ログに残らない export を実行する。",
    summary: "ログ行への改行注入、復帰文字、JSON の破壊、記録されない隠し操作を順に使う。",
    standards: {
      owasp: {
        code: "A09:2021",
        name: "Security Logging and Monitoring Failures",
        url: "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
      },
      cwe: [
        { id: 117, name: "Improper Output Neutralization for Logs" },
        { id: 778, name: "Insufficient Logging" },
      ],
    },
    references: [
      { title: "OWASP Security Logging and Monitoring Failures", url: "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/" },
      { title: "OWASP Logging Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html" },
    ],
  },
  fields: [
    { name: "user", label: "メモ", default: "", mono: true },
    { name: "action", label: "action", default: "view", mono: true },
    { name: "op", label: "op", default: "", mono: true, hidden: true },
  ],
  explanation: `ログと監視の失敗は、攻撃が記録されないことと、記録そのものを偽れることの両方です。このラボのアカウントは常に guest です。メモをログへそのまま連結すると、改行で admin の export という別行を足せます。\`\\n\` だけ除いても \`\\r\` が残れば、監視側の行分割で同じことができます。JSON でも、引用符を閉じると後続のキーが user と action を上書きします。

記録を正しくエスケープしても、実行が別パラメータ \`op\` を見るなら、ログは view のまま export が動きます。監視は記録を信じます。

根本対策は Lv5 です。実行した操作だけを構造化して記録し、guest の export は拒否してその結果も残します。`,
  levels,
  run,
  exploits: {
    1: { user: "\\nuser=admin action=export", action: "view" },
    2: { user: "\\ruser=admin action=export", action: "view" },
    3: { user: '","user":"admin","action":"export","x":"', action: "view" },
    4: { user: "", action: "view", op: "export" },
  },
};
