import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";

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
// A per-session secret the attacker's page can never contain.
const SESSION_CSRF_TOKEN = "a9f3c1d7-7e21-4b8c-9f02-sErVeRsEcReT";

interface SimRequest {
  method: "GET" | "POST";
  params: Record<string, string>;
  /** Empty string models a suppressed Referer (no-referrer). */
  referer: string;
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

/** Parse the attacker's HTML into the cross-site request it would trigger. */
function parseAttack(html: string): SimRequest | null {
  const noReferrer = /no-referrer|noreferrer/i.test(html);
  const referer = noReferrer ? "" : ATTACKER_REFERER;

  const form = html.match(/<form\b([^>]*)>([\s\S]*?)<\/form>/i);
  if (form && /transfer/i.test(attr(form[1], "action") ?? "")) {
    const method = (attr(form[1], "method") ?? "get").toLowerCase() === "post" ? "POST" : "GET";
    const params: Record<string, string> = {};
    const inputRe = /<input\b([^>]*)>/gi;
    let m: RegExpExecArray | null;
    while ((m = inputRe.exec(form[2]))) {
      const name = attr(m[1], "name");
      if (name) params[name] = attr(m[1], "value") ?? "";
    }
    return { method, params, referer };
  }

  const src = html.match(
    /<(?:img|iframe|script)\b[^>]*\bsrc\s*=\s*["']?([^"' >]*transfer[^"' >]*)/i,
  );
  if (src) {
    return { method: "GET", params: parseQuery(src[1]), referer };
  }
  return null;
}

interface BankResult {
  ok: boolean;
  reason: string;
}

function bank(level: Level, req: SimRequest | null): BankResult {
  if (!req) return { ok: false, reason: "送金リクエストが見つかりません。" };

  // Level 5 sets SameSite=Strict, so the session cookie is NOT sent on a
  // cross-site request — the bank sees an unauthenticated call.
  if (level === 5) {
    // token would also be required and must equal the server secret.
    if (req.params.csrf_token !== SESSION_CSRF_TOKEN) {
      return {
        ok: false,
        reason:
          "SameSite=Strict により Cookie が送られず未認証。かつ正しい CSRF トークンもありません。",
      };
    }
    return { ok: false, reason: "未認証リクエストとして拒否。" };
  }

  if (level >= 2 && req.method !== "POST") {
    return { ok: false, reason: "GET による状態変更は拒否されました（POST 必須）。" };
  }

  if (level >= 3) {
    // Lenient (buggy) check: an empty Referer is allowed.
    const ok = req.referer === "" || req.referer.includes(BANK_ORIGIN);
    if (!ok) {
      return { ok: false, reason: `Referer が許可されていません (${req.referer})。` };
    }
  }

  if (level >= 4) {
    // Lv4 bug: only checks that the token is present, never its value.
    if (!req.params.csrf_token) {
      return { ok: false, reason: "CSRF トークンがありません。" };
    }
  }

  const to = req.params.to;
  const amount = Number(req.params.amount);
  if (!to || !(amount > 0)) {
    return { ok: false, reason: "送金先または金額が不正です。" };
  }
  return { ok: true, reason: `${to} へ ${amount} 円を送金しました。` };
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

  output.push(`→ ${req.method} https://${BANK_ORIGIN}/transfer`);
  output.push(`   params : ${JSON.stringify(req.params)}`);
  output.push(`   Referer: ${req.referer || "(なし)"}`);
  const cookie = level === 5 ? "(SameSite=Strict により送信されない)" : "session=<victim>";
  output.push(`   Cookie : ${cookie}`);
  output.push("");

  const result = bank(level, req);
  output.push(result.ok ? `✅ ${result.reason}` : `❌ ${result.reason}`);

  return {
    solved: result.ok,
    output,
    note: result.ok
      ? "被害者の権限で不正送金が成立しました。"
      : "送金はブロックされました。防御を回避する手口を考えましょう。",
  };
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "防御なし。/transfer は GET でも実行される。",
    hint: "被害者のブラウザが『自動で』銀行へリクエストを送る HTML は？ 画像の読み込みはクリック不要で発火します。",
    solution:
      '`<img src="https://bank.example/transfer?to=attacker&amount=10000">` を入力。画像読み込みで GET が自動送信され、被害者の Cookie が付与されます。',
    code: `app.get("/transfer", (req, res) => {
  transfer(session.user, req.query.to, req.query.amount); // 無防備
});`,
  },
  2: {
    defense: "状態変更は POST のみ許可（GET を拒否）。",
    hint: "GET は拒否されます。クリックなしで POST を送るには、自動送信するフォームを使います。",
    solution:
      '自動送信フォームを入力:\n`<form action="https://bank.example/transfer" method="post"><input name="to" value="attacker"><input name="amount" value="10000"></form><script>document.forms[0].submit()</script>`',
    code: `app.post("/transfer", (req, res) => {
  transfer(session.user, req.body.to, req.body.amount); // POST だが CSRF 対策なし
});`,
  },
  3: {
    defense: "Referer を検証（ただし空の Referer は許可してしまう）。",
    hint: "Referer が evil.example だと弾かれます。でも『Referer を送らない』ようにできれば…？",
    solution:
      'ページ先頭に `<meta name="referrer" content="no-referrer">` を追加してから、Lv2 の自動送信フォームを置く。Referer が空になり、ゆるい検証を通過します。',
    code: `const ref = req.headers.referer || "";
if (ref !== "" && !ref.includes("bank.example")) return res.status(403);
// 空 Referer を許可してしまう罠`,
  },
  4: {
    defense: "CSRF トークンを要求（ただし存在チェックのみで値を検証しない）。",
    hint: "トークンが必要ですが…サーバは『あるかどうか』しか見ていないとしたら？",
    solution:
      '`<meta name="referrer" content="no-referrer">` ＋ 自動送信フォームに `<input name="csrf_token" value="x">` を追加。値は何でもよく、存在するだけで通ります。',
    code: `if (!req.body.csrf_token) return res.status(403); // 値を検証していない
transfer(session.user, req.body.to, req.body.amount);`,
  },
  5: {
    defense: "ランダムな同期トークンを検証し、Cookie を SameSite=Strict にする。",
    hint: "正しいトークンはサーバだけが知っており、Cookie はクロスサイトでは送られません。これは正しい対策です。",
    solution:
      "このレベルは意図的に突破不可能です。攻撃者はセッション固有のランダムトークンを知り得ず、SameSite=Strict の Cookie もクロスサイトでは送信されないため、送金は認証されません。",
    code: `// 1) セッション毎のランダムトークンを発行し、値を厳密比較
if (req.body.csrf_token !== session.csrfToken) return res.status(403);
// 2) Cookie は SameSite=Strict（クロスサイトで送信されない）
res.cookie("session", id, { sameSite: "strict", httpOnly: true });`,
  },
};

export const csrfLab: Lab = {
  meta: {
    id: "csrf",
    title: "CSRF — 不正送金",
    shortTitle: "CSRF",
    category: "セッション / リクエスト偽造",
    objective: "ログイン中の被害者に、攻撃者宛ての送金を気づかせず実行させる。",
    summary: "悪性ページから被害者のセッションで銀行の送金リクエストを強制する。",
    icon: "🏦",
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

レベルが上がると「POST 必須」「Referer 検証」「CSRF トークン」で防ごうとしますが、自動送信フォーム、no-referrer、値を検証しないトークンなど、実装の抜けを突いて回避できます。

根本対策は Lv5 です。セッションごとのランダムな同期トークン（synchronizer token）を発行して値を厳密に検証し、さらに Cookie を SameSite=Strict にします。攻撃者はトークンを知り得ず、クロスサイトでは Cookie も送られないため、偽造リクエストは認証されません。`,
  levels,
  run,
};
