import type { AttackResult, LabInput, Level, RealLab } from "./runner.js";

/**
 * Real reflected XSS lab (guestbook / comment box).
 *
 * The server builds the exact HTML fragment the front end mounts in a
 * sandboxed iframe (the iframe's real script execution is the UI's source of
 * truth). To decide `solved` here too (for automated tests, which have no
 * DOM), the produced markup is tokenized with a small HTML5-style tokenizer
 * (correct quoted/unquoted attribute parsing, and the spec's "raw text"
 * `<script>` content rule). Surviving `<script>` content is checked for
 * alert/confirm/prompt calls outside string literals, and event-handler
 * attributes (`onerror`, …) are detected structurally from the tokenizer
 * output. Submitted script is never executed on the server.
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

/** Build the HTML the (flawed) app would emit at this level for `comment`. */
function render(level: Level, comment: string): string {
  if (level === 1) return `<div class="guest-comment">${comment}</div>`;
  if (level === 2) {
    return `<div class="guest-comment">${stripRecursive(comment, SCRIPT_TAGS)}</div>`;
  }
  if (level === 3) {
    // Encodes `<` and `>` so new tags cannot be opened. The same value is
    // copied into an attribute without encoding quotes - a different sink.
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

interface ParsedElement {
  tag: string;
  attrs: Map<string, string>;
}

interface ParseResult {
  elements: ParsedElement[];
  /** Raw text content of every `<script>` element (spec "raw text" rule). */
  scripts: string[];
}

const WHITESPACE = /\s/;
const NAME_STOP = /[\s=/>]/;

/**
 * Minimal HTML5-tokenizer-style scan: real quoted/unquoted attribute value
 * parsing and the spec rule that `<script>` content runs verbatim until the
 * first case-insensitive `</script`, regardless of what it contains.
 */
function parseHtml(html: string): ParseResult {
  const elements: ParsedElement[] = [];
  const scripts: string[] = [];
  const n = html.length;
  let i = 0;

  while (i < n) {
    const lt = html.indexOf("<", i);
    if (lt === -1) break;

    if (html.startsWith("<!--", lt)) {
      const end = html.indexOf("-->", lt + 4);
      i = end === -1 ? n : end + 3;
      continue;
    }
    if (html[lt + 1] === "/") {
      const gt = html.indexOf(">", lt + 2);
      i = gt === -1 ? n : gt + 1;
      continue;
    }
    if (!/[a-zA-Z]/.test(html[lt + 1] ?? "")) {
      // A lone `<` with no valid tag name is just text to the real parser.
      i = lt + 1;
      continue;
    }

    let j = lt + 1;
    let tagName = "";
    while (j < n && /[a-zA-Z0-9]/.test(html[j])) {
      tagName += html[j];
      j++;
    }
    tagName = tagName.toLowerCase();

    const attrs = new Map<string, string>();
    let selfClosing = false;
    while (j < n) {
      while (j < n && WHITESPACE.test(html[j])) j++;
      if (html[j] === ">") {
        j++;
        break;
      }
      if (html[j] === "/" && html[j + 1] === ">") {
        selfClosing = true;
        j += 2;
        break;
      }
      if (j >= n) break;

      let name = "";
      while (j < n && !NAME_STOP.test(html[j])) {
        name += html[j];
        j++;
      }
      if (name === "") {
        // Stray character (e.g. a bare `=`); skip it to guarantee progress.
        j++;
        continue;
      }
      while (j < n && WHITESPACE.test(html[j])) j++;

      let value = "";
      if (html[j] === "=") {
        j++;
        while (j < n && WHITESPACE.test(html[j])) j++;
        const quote = html[j];
        if (quote === '"' || quote === "'") {
          j++;
          const start = j;
          const end = html.indexOf(quote, j);
          value = end === -1 ? html.slice(start) : html.slice(start, end);
          j = end === -1 ? n : end + 1;
        } else {
          const start = j;
          while (j < n && !/[\s>]/.test(html[j])) j++;
          value = html.slice(start, j);
        }
      }
      attrs.set(name.toLowerCase(), value);
    }

    elements.push({ tag: tagName, attrs });

    if (tagName === "script" && !selfClosing) {
      const closeIdx = html.toLowerCase().indexOf("</script", j);
      scripts.push(closeIdx === -1 ? html.slice(j) : html.slice(j, closeIdx));
      if (closeIdx === -1) {
        i = n;
      } else {
        const gt2 = html.indexOf(">", closeIdx);
        i = gt2 === -1 ? n : gt2 + 1;
      }
    } else {
      i = j;
    }
  }

  return { elements, scripts };
}

/** Drops JS string literals so `var c = 'alert(1)'` is not mistaken for a call. */
function stripStringLiterals(code: string): string {
  let out = "";
  let quote = "";
  for (let i = 0; i < code.length; i++) {
    const c = code[i];
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
    } else if (c === "'" || c === '"' || c === "`") {
      quote = c;
    } else {
      out += c;
    }
  }
  return out;
}

// The server never executes submitted script: node:vm is not a security
// boundary. The browser iframe remains the source of truth for execution.
function scriptFires(code: string): boolean {
  return /\b(alert|confirm|prompt)\s*\(/.test(stripStringLiterals(code));
}

const EVENT_HANDLER_ATTR = /^on[a-z]+$/;
const JS_URI = /^\s*javascript:/i;
const NAV_ATTR_TAGS: Record<string, string> = { a: "href", area: "href", iframe: "src", form: "action" };

/** True when the markup still contains a script or event-handler vector. */
export function markupFires(html: string): boolean {
  const { elements, scripts } = parseHtml(html);
  for (const script of scripts) {
    if (scriptFires(script)) return true;
  }
  for (const el of elements) {
    for (const [name, value] of el.attrs) {
      if (EVENT_HANDLER_ATTR.test(name) && value.trim() !== "") return true;
    }
    const navAttr = NAV_ATTR_TAGS[el.tag];
    if (navAttr && JS_URI.test(el.attrs.get(navAttr) ?? "")) return true;
  }
  return false;
}

function run(level: Level, input: LabInput): AttackResult {
  const comment = input.comment ?? "";
  const renderHtml = render(level, comment);
  const solved = markupFires(renderHtml);

  const output: string[] = [
    "-- サーバーが生成した HTML（コメント部分）",
    renderHtml,
    "",
    solved ? "→ プレビューで実際の実行を確認してください。" : "→ スクリプトとしては検出されませんでした。",
  ];

  const recap =
    level === 1
      ? ["コメントが HTML の要素内容にそのまま入った", "<script> がページの一部として実行された"]
      : level === 2
        ? ["<script> タグは除去された", "img の onerror が HTML に残って実行された"]
        : level === 3
          ? ["タグの < > はエンコードされた", "属性の引用符を閉じてイベントハンドラを足した"]
          : [
              "値は JavaScript 文字列の中に入った",
              "</script> が HTML パーサで script 要素を閉じた",
              "抜けた先のマークアップが実行された",
            ];

  return {
    solved,
    output,
    renderHtml,
    assembled: renderHtml,
    note:
      level === 5
        ? "すべての特殊文字がエンティティに変換され、ただのテキストとして表示されました。"
        : solved
          ? "プレビューでスクリプトが動くか確認してください。"
          : "注入は無害化されました。別のコンテキストを探しましょう。",
    recap: solved ? recap : undefined,
  };
}

export const xssRealLab: RealLab = { id: "xss", run };
