import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

const isPrivateLiteral = (host: string) =>
  host === "localhost" ||
  host === "127.0.0.1" ||
  host.startsWith("127.") ||
  host === "169.254.169.254" ||
  host === "::1";

function isAllowlisted(host: string): boolean {
  return host === "example.com" || host.endsWith(".example.com");
}

/** Hostnames the allowlisted DNS zone would resolve to an internal address. */
function resolvesInternal(host: string): boolean {
  if (isPrivateLiteral(host)) return true;
  return (
    host.startsWith("127.0.0.1.") ||
    host.startsWith("localhost.") ||
    host.startsWith("169.254.169.254.")
  );
}

function isRedirectEndpoint(url: URL): boolean {
  return url.hostname === "images.example.com" && /^\/redirect\/?$/.test(url.pathname);
}

/** Decimal forms of 127.0.0.1 and 169.254.169.254, plus literals already covered. */
function isInternalRedirectTarget(to: string | null): boolean {
  if (!to) return false;
  let target: URL;
  try {
    target = new URL(to);
  } catch {
    return false;
  }
  if (!["http:", "https:"].includes(target.protocol)) return false;
  const host = target.hostname.replace(/^\[|\]$/g, "");
  return isPrivateLiteral(host) || host === "2130706433" || host === "2852039166";
}

function run(level: Level, input: LabInput): AttackResult {
  const raw = (input.url ?? "").trim();
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { solved: false, output: ["[400] URL の形式が不正です。"], note: "http または https の URL を入力してください。" };
  }

  let reachedInternal = false;
  let reason = "";
  if (!["http:", "https:"].includes(url.protocol)) {
    reason = "許可されていないスキームです。";
  } else if (level === 1) {
    reachedInternal = isPrivateLiteral(url.hostname);
    reason = "送信先を検証していません。";
  } else if (level === 2) {
    if (url.hostname === "localhost") reason = "localhost は拒否されました。";
    else {
      reachedInternal = url.hostname === "127.0.0.1";
      reason = "文字列 localhost だけを拒否しています。";
    }
  } else if (level === 3) {
    if (!isAllowlisted(url.hostname)) {
      reason = "example.com で終わらないホストは許可リスト外です。";
    } else if (resolvesInternal(url.hostname)) {
      reachedInternal = true;
      reason = "許可リスト通過後、名前解決が内部 IP を返しました。";
    } else {
      reason = "公開 URL の取得結果に機密情報はありません。";
    }
  } else if (level === 4) {
    if (!isAllowlisted(url.hostname) || resolvesInternal(url.hostname)) {
      reason = "初回 URL のホストまたは解決先が許可されていません。";
    } else if (isRedirectEndpoint(url) && isInternalRedirectTarget(url.searchParams.get("to"))) {
      reachedInternal = true;
      reason = "公開 URL の検証後、未検証のリダイレクト先へ追従しました。";
    } else {
      reason = "公開画像です。応答ヘッダのデバッグリンクを見てください。";
    }
  } else {
    reason = "各リダイレクトで名前解決後の IP を検証し、内部アドレスを拒否しました。";
  }

  const hops = reachedInternal
    ? [`hop1 ${url.origin}${url.pathname}`, `hop2 ${url.searchParams.get("to") ?? "(internal)"}`]
    : [`hop1 ${url.toString()}`];
  const debugLink =
    level === 4 && !reachedInternal && isAllowlisted(url.hostname) && !resolvesInternal(url.hostname)
      ? [
          "HTTP/1.1 200 OK",
          "X-Debug-Link: https://images.example.com/redirect?to=",
          "<!-- 取得ワーカーは /redirect の Location を追従します -->",
        ]
      : [];
  const loot = reachedInternal
    ? [{ id: "ssrf-access-key", label: "メタデータ access-key", value: "SIMULATED_SECRET" }]
    : undefined;
  return traced(
    {
      solved: reachedInternal,
      output: [
        `fetch ${url.toString()}`,
        ...debugLink,
        reachedInternal
          ? "[200 OK] instance-role=hacklab-prod / access-key=SIMULATED_SECRET"
          : `[403/200] ${reason}`,
      ],
      progress: debugLink.length > 0,
      note: reachedInternal ? "サーバーから内部サービスへリクエストを送信できました。" : reason,
    },
    hops.join("\n"),
    {
      recap: reachedInternal
        ? ["初回 URL は許可リストを通った", "302 の Location を再検証しなかった", "メタデータのアクセスキーが返った"]
        : undefined,
      loot,
    },
  );
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "URL を無検証でサーバーから取得する。",
    hints: [
      "外部 URL 取得機能は、サーバー自身から見える宛先にも届きます。",
      "localhost 上の管理 API は外部から見えなくても、サーバーからは見えます。",
      "`http://localhost/admin` を指定します。",
    ],
    solution: "`http://localhost/admin` を取得させ、内部管理サービスへ到達します。",
    code: `const response = await fetch(req.body.url);
return response.text(); // 宛先制限なし`,
  },
  2: {
    defense: "URL 文字列に `localhost` が含まれる場合だけ拒否する。",
    hints: [
      "同じホストを表す別の書き方があります。",
      "localhost の IPv4 ループバックアドレスは何でしょうか？",
      "`http://127.0.0.1/admin` を使います。",
    ],
    solution: "`localhost` を `127.0.0.1` に置き換えて文字列ブラックリストを回避します。",
    code: `if (url.includes("localhost")) deny();
return fetch(url);`,
  },
  3: {
    defense: "ホスト名が `example.com` で終わることだけを許可する（名前解決後の IP は見ない）。",
    hints: [
      "`127.0.0.1` は許可リスト外です。防御が拒否リストから許可リストに変わっています。",
      "許可されたゾーンのサブドメインは、攻撃者が名前解決を握れることがあります。",
      "`http://127.0.0.1.example.com/admin` は suffix 検査を通り、内部へ解決されます。",
    ],
    solution:
      "`http://127.0.0.1.example.com/admin` を取得させます。ホスト名は許可リストを通り、解決結果はループバックです。",
    code: `if (!url.hostname.endsWith("example.com")) deny();
return fetch(url); // 解決後の IP を見ていない`,
  },
  4: {
    defense: "許可リストに加え、初回 URL の解決先 IP を検証する。リダイレクト先は再検証しない。",
    hints: [
      "サブドメインでの内部解決は初回検査で落ちます。ソースの redirect 処理を読みましょう。",
      "許可された公開ホストが、別 URL へ 302 を返すと？",
      "まずデフォルトの banner を取得すると、応答に `/redirect?to=` が出ます。その先を内部 IP にしてみます。",
    ],
    solution:
      "許可された `images.example.com/redirect` から内部 IP へのリダイレクトを返させます。末尾スラッシュや `http://127.0.0.1/`、十進 IP でも通ります。",
    code: `assertAllowlisted(url.hostname);
assertPublicIp(await resolve(url.hostname));
return fetch(url, { redirect: "follow" }); // 遷移先を再検証しない`,
  },
  5: {
    defense: "許可先を限定し、各 hop で名前解決後の全 IP とプロトコルを検証する。",
    hints: [
      "DNS 応答の全アドレスとリダイレクト先を毎回検証します。",
      "内部ネットワークへの経路がない専用取得サービスも使うため、突破できません。",
    ],
    solution: "突破不可能です。許可リスト、名前解決後の IP 検証、リダイレクト再検証、ネットワーク分離を適用します。",
    code: `for (const hop of redirects) {
  const ips = await resolveAll(hop.hostname);
  if (!ALLOWLIST.has(hop.hostname) || ips.some(isPrivateOrSpecial)) deny();
}`,
  },
};

export const ssrfLab: Lab = {
  meta: {
    id: "ssrf",
    title: "SSRF — 内部メタデータへのアクセス",
    shortTitle: "SSRF",
    category: "サーバーサイドリクエスト",
    objective: "URL 取得機能を悪用し、外部公開されていない内部情報を取得する。",
    summary: "localhost、ホスト許可リストの suffix、リダイレクトを使って不完全な URL 検証を回避する。",
    standards: {
      owasp: {
        code: "A10:2021",
        name: "Server-Side Request Forgery",
        url: "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
      },
      cwe: [{ id: 918, name: "Server-Side Request Forgery (SSRF)" }],
    },
    references: [
      { title: "OWASP SSRF Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
      { title: "PortSwigger — Server-side request forgery", url: "https://portswigger.net/web-security/ssrf" },
    ],
  },
  fields: [{ name: "url", label: "取得する URL", default: "https://images.example.com/banner.png", mono: true }],
  explanation: `SSRF は、サーバーの URL 取得機能を攻撃者が操作し、本来外部から到達できない内部 API、クラウドメタデータ、localhost 上の管理画面などへリクエストさせる脆弱性です。

文字列の拒否リストは別表記で回避されます。ホスト名の許可リストも、解決後の IP を見なければサブドメイン経由で内部へ届きます。可能なら送信先を業務上必要な許可リストに限定し、名前解決したすべての IP がプライベート・ループバック・リンクローカル等でないことを接続直前と各リダイレクトで確認します。取得処理をネットワーク分離することも重要です。`,
  levels,
  run,
  exploits: {
    1: { url: "http://localhost/admin" },
    2: { url: "http://127.0.0.1/admin" },
    3: { url: "http://127.0.0.1.example.com/admin" },
    4: { url: "https://images.example.com/redirect?to=http://169.254.169.254/latest/meta-data" },
  },
};
