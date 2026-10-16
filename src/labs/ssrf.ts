import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";

const isDecimalLoopback = (host: string) => host === "2130706433";
const isPrivateLiteral = (host: string) =>
  host === "localhost" ||
  host === "127.0.0.1" ||
  host.startsWith("127.") ||
  host === "169.254.169.254" ||
  host === "::1";

function run(level: Level, input: LabInput): AttackResult {
  const raw = (input.url ?? "").trim();
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { solved: false, output: ["[400] URL の形式が不正です。"], note: "http または https の URL を入力してください。" };
  }
  // Preserve the spelling the application validates before the URL parser
  // canonicalizes integer IPv4 forms such as 2130706433 to 127.0.0.1.
  const rawHost = raw.match(/^[a-z]+:\/\/([^/:?#]+)/i)?.[1]?.toLowerCase() ?? url.hostname;

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
    if (isDecimalLoopback(rawHost)) {
      reachedInternal = true;
      reason = "10 進整数表記が名前解決後に 127.0.0.1 になりました。";
    } else if (isPrivateLiteral(url.hostname)) reason = "プライベート IP は拒否されました。";
    else {
      reason = "公開 URL の取得結果に機密情報はありません。";
    }
  } else if (level === 4) {
    const redirectTarget = url.hostname === "public.example" && url.pathname === "/redirect"
      ? url.searchParams.get("to")
      : null;
    if (isPrivateLiteral(url.hostname) || isDecimalLoopback(rawHost)) {
      reason = "初回 URL の解決先が内部 IP のため拒否されました。";
    } else if (redirectTarget === "http://169.254.169.254/latest/meta-data") {
      reachedInternal = true;
      reason = "公開 URL の検証後、未検証のリダイレクト先へ追従しました。";
    } else {
      reason = "公開 URL の取得結果に機密情報はありません。";
    }
  } else {
    reason = "各リダイレクトで名前解決後の IP を検証し、内部アドレスを拒否しました。";
  }

  return {
    solved: reachedInternal,
    output: [
      `fetch ${url.toString()}`,
      reachedInternal
        ? "[200 OK] instance-role=hacklab-prod / access-key=SIMULATED_SECRET"
        : `[403/200] ${reason}`,
    ],
    note: reachedInternal ? "サーバーから内部サービスへリクエストを送信できました。" : reason,
  };
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
    defense: "既知のプライベート IP 文字列を拒否するが、IP の表記を正規化しない。",
    hints: [
      "IPv4 アドレスにはドット区切り以外の表記があります。",
      "127.0.0.1 を 32 bit の 10 進整数として表せます。",
      "`http://2130706433/admin` を指定します。",
    ],
    solution: "`2130706433` は URL パーサーにより 127.0.0.1 として扱われ、検証を迂回します。",
    code: `const host = new URL(input).hostname;
if (BLOCKED_STRINGS.includes(host)) deny(); // 正規化・名前解決前の比較`,
  },
  4: {
    defense: "初回 URL は名前解決後の IP を検証するが、リダイレクト先を再検証しない。",
    hints: [
      "最初の接続先が安全でも、その応答が別 URL を返すことがあります。",
      "リダイレクトの各 hop で同じ検証が必要です。",
      "`https://public.example/redirect?to=http://169.254.169.254/latest/meta-data` を使います。",
    ],
    solution: "許可された公開サイトからメタデータ IP へのリダイレクトを返させます。",
    code: `assertPublicIp(await resolve(url.hostname));
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
    summary: "localhost、IP 表記ゆれ、リダイレクトを使って不完全な URL 検証を回避する。",
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
  fields: [{ name: "url", label: "取得する URL", default: "https://images.example/banner.png", mono: true }],
  explanation: `SSRF は、サーバーの URL 取得機能を攻撃者が操作し、本来外部から到達できない内部 API、クラウドメタデータ、localhost 上の管理画面などへリクエストさせる脆弱性です。

文字列ブラックリストは IP の別表記、DNS、リダイレクトで回避されます。可能なら送信先を業務上必要な許可リストに限定し、名前解決したすべての IP がプライベート・ループバック・リンクローカル等でないことを接続直前と各リダイレクトで確認します。取得処理をネットワーク分離することも重要です。`,
  levels,
  run,
  exploits: {
    1: { url: "http://localhost/admin" },
    2: { url: "http://127.0.0.1/admin" },
    3: { url: "http://2130706433/admin" },
    4: { url: "https://public.example/redirect?to=http://169.254.169.254/latest/meta-data" },
  },
};
