import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

/**
 * Simulated Reflected XSS lab (guestbook / comment box).
 *
 * The attacker-controlled comment is placed in a *different sink* per level
 * and mounted inside a sandboxed iframe (sandbox="allow-scripts", no
 * same-origin) by the UI. The iframe's `alert`/`prompt`/`confirm` are hooked to
 * postMessage back to the parent, so a payload that actually executes is the
 * real source of truth. `run()` additionally detects a surviving vector so the
 * automated lab tests (which have no DOM) can verify each level.
 */

function htmlEncode(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function stripRecursive(s: string, re: RegExp): string {
  let prev: string;
  do {
    prev = s;
    s = s.replace(re, "");
  } while (s !== prev);
  return s;
}

const SCRIPT_TAGS = /<\/?script[^>]*>/gi;

/** Wrap the comment in the HTML the (flawed) app would emit at this level. */
function render(level: Level, comment: string): string {
  if (level === 1) return `<div class="guest-comment">${comment}</div>`;
  if (level === 2) {
    return `<div class="guest-comment">${stripRecursive(comment, SCRIPT_TAGS)}</div>`;
  }
  if (level === 3) {
    // Encodes `<` and `>` so new tags cannot be opened. The same value is
    // copied into an attribute without encoding quotes — a different sink.
    const body = comment.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    return `<img class="sticker" src="https://sticker.invalid/note.png" alt="${body}">`;
  }
  if (level === 4) {
    // HTML body is unused. The value is interpolated into a JS string with
    // quote escaping, but `</script>` still terminates the HTML parser.
    const js = comment.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
    return `<script>var comment = '${js}';</script><div class="guest-comment"></div>`;
  }
  return `<div class="guest-comment">${htmlEncode(comment)}</div>`;
}

/**
 * Heuristic: does an executable vector survive in the sanitized HTML?
 * For the Lv4 script wrapper, only markup *after* the first `</script>` counts
 * — that is what the HTML parser would actually render.
 */
export function htmlFires(html: string): boolean {
  let scan = html;
  if (html.includes("<script>var comment")) {
    const end = html.toLowerCase().indexOf("</script>");
    scan = end === -1 ? html : html.slice(end + "</script>".length);
  }
  if (/<script\b[^>]*>[\s\S]*?\S[\s\S]*?<\/script>/i.test(scan)) return true;
  const tags = scan.match(/<[a-z][^>]*>/gi) ?? [];
  for (const tag of tags) {
    // Ignore handler-looking text that lives inside a quoted attribute value.
    const stripped = tag.replace(/"[^"]*"/g, '""').replace(/'[^']*'/g, "''");
    if (/\son\w+\s*=\s*["']?\s*[^\s>]/i.test(stripped)) return true;
    if (/(?:href|src|xlink:href)\s*=\s*["']?\s*javascript:/i.test(tag)) return true;
  }
  return false;
}

function run(level: Level, input: LabInput): AttackResult {
  const comment = input.comment ?? "";
  const renderHtml = render(level, comment);
  const solved = htmlFires(renderHtml);

  const output: string[] = [];
  output.push("-- サーバーが生成した HTML（コメント部分）");
  output.push(renderHtml);
  output.push("");
  output.push(solved ? "→ プレビューで実際の実行を確認してください。" : "→ スクリプトとしては検出されませんでした。");

  const recap =
    level === 1
      ? ["コメントが HTML の要素内容にそのまま入った", "<script> がページの一部として実行された"]
      : level === 2
        ? ["<script> タグは除去された", "img の onerror が HTML に残って実行された"]
        : level === 3
          ? ["タグの < > はエンコードされた", "属性の引用符を閉じてイベントハンドラを足した"]
          : ["値は JavaScript 文字列の中に入った", "</script> が HTML パーサで script 要素を閉じた", "抜けた先のマークアップが実行された"];

  return traced(
    {
      solved,
      output,
      renderHtml,
      note:
        level === 5
          ? "すべての特殊文字がエンティティに変換され、ただのテキストとして表示されました。"
          : solved
            ? "プレビューでスクリプトが動くか確認してください。"
            : "注入は無害化されました。別のコンテキストを探しましょう。",
    },
    renderHtml,
    solved ? { recap } : undefined,
  );
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。コメントをそのまま HTML に埋め込む。",
    hints: [
      "「ソース」タブを読みましょう。コメントは加工されずに HTML へ入ります。ブラウザは HTML のどの部分を『実行』しますか？",
      "入力はページの HTML にそのまま差し込まれます。最も素直なスクリプト注入は？",
      "`<script>` タグの中で `alert(1)` を呼びましょう。",
    ],
    solution: "`<script>alert(1)</script>` を入力。そのままスクリプトとして実行されます。",
    code: `res.send('<div class="comment">' + comment + '</div>');`,
  },
  2: {
    defense: "<script> タグを（繰り返し）除去する。",
    hints: [
      "Lv1 の入力は通りません。「ソース」で、何が除去されるのかを確認しましょう。",
      "script タグは消されます。でも JavaScript を動かす方法はタグだけではありません。イベントハンドラは？",
      "画像の読み込みに失敗すると発火するイベントがあります。`<img>` と `onerror` の組み合わせを試しましょう。",
    ],
    solution:
      "`<img src=x onerror=alert(1)>` を入力。存在しない画像の読み込み失敗で onerror が発火します。",
    code: `let safe = comment.replace(/<\\/?script[^>]*>/gi, "");
res.send('<div class="comment">' + safe + '</div>');`,
  },
  3: {
    defense: "`<` をエンコードしてタグ注入を防ぐ。同じ値を属性へ入れるとき、引用符はエンコードしない。",
    hints: [
      "Lv2 の `<img>` は、`<` が `&lt;` になるので新しいタグになりません。出力先をソースで確認しましょう。",
      "コメントは `alt=\"...\"` の中にも入ります。属性値を閉じる文字は何ですか？",
      "`alt` を `\"` で閉じ、既存の `<img>` に `onerror` を足せませんか？ src は存在しない URL です。",
    ],
    solution:
      "`\" onerror=alert(1) x=\"` を入力。`alt` が閉じて既存画像に onerror が付き、読み込み失敗で alert します。タグを新しく作る必要はありません。",
    code: `const body = comment.replace(/</g, "&lt;").replace(/>/g, "&gt;");
res.send('<img src="/sticker.png" alt="' + body + '">'); // " をエンコードしていない`,
  },
  4: {
    defense: "HTML 本文へは出さず、JS 文字列へクオートをエスケープして埋め込む。",
    hints: [
      "属性のブレイクアウトは効きません。ソースの出力コンテキストは HTML ではなく `<script>` の中です。",
      "JS の引用符はエスケープされます。でも HTML パーサは JS の文法を知りません。",
      "HTML にとってのスクリプト終了タグは、JS 文字列の中でも終わりとして扱われます。",
    ],
    solution:
      "`</script><img src=x onerror=alert(1)>` を入力。クオートの外に出る前に `</script>` がスクリプト要素を閉じ、後続の img が HTML として実行されます。",
    code: `const js = comment.replace(/\\\\/g, "\\\\\\\\").replace(/'/g, "\\\\'");
res.send("<script>var comment = '" + js + "';</script>");
// HTML パーサは文字列の中の </script> で要素を閉じる`,
  },
  5: {
    defense: "出力時に HTML エンティティへエスケープ（コンテキストに応じた出力エンコード）。",
    hints: [
      "特殊文字がすべて実体参照に変換されます。これは正しい対策です。",
      "「ソース」と「解説」を読み、なぜ入力が『コード』ではなく『テキスト』のまま表示されるのか説明してみましょう。",
    ],
    solution:
      "このレベルは意図的に突破不可能です。`<` や `>` が `&lt;` `&gt;` に変換され、入力はコードではなく常にテキストとして表示されます。コンテキストに応じた出力エンコードが本来の対策です。",
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
    summary: "反射されたコメントにスクリプトを注入し、サンドボックス内で任意 JS を実行する。",
    standards: {
      owasp: { code: "A03:2021", name: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection" },
      cwe: [{ id: 79, name: "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)" }],
    },
    references: [
      {
        title: "OWASP Cross Site Scripting Prevention Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
      },
      { title: "PortSwigger Web Security Academy — XSS", url: "https://portswigger.net/web-security/cross-site-scripting" },
      { title: "IPA 安全なウェブサイトの作り方", url: "https://www.ipa.go.jp/security/vuln/websecurity/" },
    ],
  },
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

レベルが上がると、タグ除去、属性への出力、JavaScript 文字列への埋め込みと、**出力コンテキスト**が変わります。あるコンテキスト向けのエンコードは、別のコンテキストでは無意味です。禁止タグを増やすことでは止まりません。

根本対策は Lv5 の、出力先（HTML 本文／属性値／JS／URL）に応じたエンコードです。テンプレートの自動エスケープと CSP も併用します。`,
  levels,
  run,
  exploits: {
    1: { comment: "<script>alert(1)</script>" },
    2: { comment: "<img src=x onerror=alert(1)>" },
    3: { comment: '" onerror=alert(1) x="' },
    4: { comment: "</script><img src=x onerror=alert(1)>" },
  },
};
