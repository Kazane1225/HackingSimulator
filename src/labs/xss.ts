import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";

/**
 * Simulated Reflected XSS lab (guestbook / comment box).
 *
 * The attacker-controlled comment is sanitized according to the level and the
 * result is mounted inside a *sandboxed* iframe (sandbox="allow-scripts", no
 * same-origin) by the UI. The iframe's `alert`/`prompt`/`confirm` are hooked to
 * postMessage back to the parent, so a payload that actually executes is the
 * real source of truth. `run()` additionally detects a surviving vector so the
 * automated lab tests (which have no DOM) can verify each level.
 */

function stripRecursive(s: string, re: RegExp): string {
  let prev: string;
  do {
    prev = s;
    s = s.replace(re, "");
  } while (s !== prev);
  return s;
}

function htmlEncode(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const SCRIPT_TAGS = /<\/?script[^>]*>/gi;
// Level 3 blacklists only the *common* handlers (recursively).
const COMMON_HANDLERS = /onerror|onload|onclick|onmouseover/gi;
// Level 4 blacklists more handlers but in a single, non-idempotent pass.
const MANY_HANDLERS = /onerror|onload|onclick|onmouseover|onfocus|ontoggle/gi;

/** Apply the defense for `level` to the comment, returning HTML to render. */
function sanitize(level: Level, s: string): string {
  if (level === 1) return s;
  if (level === 2) return stripRecursive(s, SCRIPT_TAGS);
  if (level === 3) {
    let out = stripRecursive(s, SCRIPT_TAGS);
    out = stripRecursive(out, COMMON_HANDLERS);
    return out;
  }
  if (level === 4) {
    // Regression: more handlers blacklisted, but as a single pass. Removing
    // "onerror" from "ononerrorerror" splices "on" + "error" back into
    // "onerror" — the classic non-idempotent filter bug.
    let out = stripRecursive(s, SCRIPT_TAGS);
    out = stripRecursive(out, /javascript:/gi);
    out = out.replace(MANY_HANDLERS, "");
    return out;
  }
  return htmlEncode(s); // level 5: output encoding — inert text
}

/** Heuristic: does an executable vector survive in the sanitized HTML? */
function hasActiveVector(html: string): boolean {
  if (/<script\b[^>]*>[\s\S]*?\S[\s\S]*?<\/script>/i.test(html)) return true;
  // Handlers / javascript: URIs only matter inside a real tag, not in text.
  if (/<[a-z][^>]*\son\w+\s*=\s*["']?\s*[^\s>]/i.test(html)) return true;
  if (/<[a-z][^>]*(?:href|src|xlink:href)\s*=\s*["']?\s*javascript:/i.test(html)) return true;
  return false;
}

function run(level: Level, input: LabInput): AttackResult {
  const comment = input.comment ?? "";
  const sanitized = sanitize(level, comment);
  const renderHtml = `<div class="guest-comment">${sanitized}</div>`;
  const solved = hasActiveVector(sanitized);

  const output: string[] = [];
  output.push("-- サーバーが生成した HTML（コメント部分）");
  output.push(renderHtml);
  output.push("");
  output.push(
    solved
      ? "→ 実行可能なベクターが残っています。右のプレビューで alert が発火すればクリアです。"
      : "→ 実行可能なベクターは検出されませんでした。",
  );

  return {
    solved,
    output,
    renderHtml,
    note:
      level === 5
        ? "すべての特殊文字がエンティティに変換され、ただのテキストとして表示されました。"
        : solved
          ? "実行可能なベクターが残っています。プレビューで実際に alert が発火するとクリアです。"
          : "注入は無害化されました。別のベクターを試しましょう。",
  };
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。コメントをそのまま HTML に埋め込む。",
    hint: "入力はページの HTML にそのまま差し込まれます。最も素直なスクリプト注入は？",
    solution: "`<script>alert(1)</script>` を入力。そのままスクリプトとして実行されます。",
    code: `res.send('<div class="comment">' + comment + '</div>');`,
  },
  2: {
    defense: "<script> タグを（繰り返し）除去する。",
    hint: "script タグは消されます。でも JavaScript を動かす方法はタグだけではありません。イベントハンドラは？",
    solution:
      "`<img src=x onerror=alert(1)>` を入力。存在しない画像の読み込み失敗で onerror が発火します。",
    code: `let safe = comment.replace(/<\\/?script[^>]*>/gi, "");
res.send('<div class="comment">' + safe + '</div>');`,
  },
  3: {
    defense: "script タグに加え、代表的なハンドラ (onerror/onload/onclick/onmouseover) を除去する。",
    hint: "よく使うハンドラはブロックされています。ブラックリストに『載っていない』ハンドラは？",
    solution:
      "`<details open ontoggle=alert(1)>` を入力。open 状態の details は描画時に toggle イベントを発火し、ontoggle はブラックリスト外なので生き残ります（`<input autofocus onfocus=alert(1)>` も同じ理屈ですが、クロスオリジン iframe では autofocus がブロックされることがあります）。",
    code: `let safe = comment.replace(/<\\/?script[^>]*>/gi, "")
  .replace(/onerror|onload|onclick|onmouseover/gi, "");`,
  },
  4: {
    defense: "ハンドラのブラックリストを拡充。ただし単一パス（非冪等）で適用。",
    hint: "フィルタは一度しか走りません。除去された結果、ハンドラ名が『再生成』される入力は作れますか？",
    solution:
      "`<img src=x ononerrorerror=alert(1)>` を入力。`ononerrorerror` から真ん中の `onerror` が一度だけ除去され `onerror` が復活します。",
    code: `let safe = comment.replace(/<\\/?script[^>]*>/gi, "")
  .replace(/javascript:/gi, "")
  .replace(/onerror|onload|onclick|onmouseover|onfocus|ontoggle/gi, ""); // 1回だけ`,
  },
  5: {
    defense: "出力時に HTML エンティティへエスケープ（コンテキストに応じた出力エンコード）。",
    hint: "特殊文字がすべて実体参照に変換されます。これは正しい対策です。",
    solution:
      "このレベルは意図的に突破不可能です。`<` や `>` が `&lt;` `&gt;` に変換され、入力はコードではなく常にテキストとして表示されます。ブラックリストではなく『出力エンコード』が本来の対策です。",
    code: `const enc = s => s.replace(/&/g,"&amp;").replace(/</g,"&lt;")
  .replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
res.send('<div class="comment">' + enc(comment) + '</div>');`,
  },
};

export const xssLab: Lab = {
  meta: {
    id: "xss",
    title: "クロスサイトスクリプティング (XSS) — コメント欄",
    shortTitle: "XSS",
    category: "インジェクション",
    objective: "コメント欄を悪用し、ページ上で alert() を実行させる。",
    summary: "反射されたコメントにスクリプトを注入し、サンドボックス内で任意 JS を実行する。",  },
  fields: [
    {
      name: "comment",
      label: "コメント",
      placeholder: "<script>alert(1)</script>",
      multiline: true,
      mono: true,
      default: "こんにちは！",
    },
  ],
  explanation: `XSS（クロスサイトスクリプティング）は、アプリがユーザー入力をエスケープせずに HTML として出力するときに起こります。入力に含まれる \`<script>\` やイベントハンドラ、\`javascript:\` URI がブラウザ上でスクリプトとして実行され、Cookie やセッションの窃取、画面改ざん、なりすまし操作などが可能になります。

このラボでは、投稿したコメントがページの HTML に差し込まれ、右側のサンドボックス化された iframe でレンダリングされます。注入したスクリプトが実際に \`alert()\` を呼べればクリアです（安全のため iframe は allow-scripts のみで隔離されています）。

レベルが上がると「<script> を消す」「ハンドラを消す」といったブラックリストで防ごうとしますが、イベントハンドラの多様さ、ブラックリストの抜け、非冪等な置換により回避されていきます。

根本対策は Lv5 の出力エンコードです。表示するコンテキスト（HTML本文／属性値／JS／URL）に応じて特殊文字をエスケープすれば、入力は常に「データ」として表示され、スクリプトにはなりません。入力のブラックリストではなく、出力時のエンコード（およびテンプレートエンジンの自動エスケープや CSP）が正解です。`,
  levels,
  run,
  exploits: {
    1: { comment: "<script>alert(1)</script>" },
    2: { comment: "<img src=x onerror=alert(1)>" },
    3: { comment: "<details open ontoggle=alert(1)>" },
    4: { comment: "<img src=x ononerrorerror=alert(1)>" },
  },
};
