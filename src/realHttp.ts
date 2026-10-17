import type { AttackResult, LabInput, Level, LootItem } from "./labs/types";
import { htmlFires } from "./labs/xss";

/**
 * The request the workbench actually sends in real-server mode, and the
 * reading of the response. Success is decided from status, headers and body.
 * The server does not return a `solved` flag.
 */

export interface LabRequest {
  method: "GET" | "POST";
  /** App path, without the gateway's `/api` prefix. */
  path: string;
  headers: Record<string, string>;
  body?: string;
}

export interface HttpResponse {
  status: number;
  headers: [string, string][];
  body: string;
}

const SQLI_ACCOUNTS = [
  { username: "admin", password: "S3cr3t-Pa55!" },
  { username: "alice", password: "sunshine" },
  { username: "bob", password: "qwerty123" },
];

const CMDI_FLAG = "FLAG{c0mmand_1nj3ct10n}";
const PATH_FLAG = "FLAG{p4th_tr4v3rs4l}";
const PASSWD_MARK = "root:x:0:0";
const PAN = "4242424242424242";
const MISCONF_FLAG = "FLAG{m1sc0nf1g}";
const DEPS_FLAG = "FLAG{old_component}";
const INTEGRITY_FLAG = "FLAG{uns1gn3d_upd4te}";
const LOGGING_FLAG = "FLAG{l0g_1nj3ct}";

function exactLine(body: string, line: string): boolean {
  return body.split("\n").includes(line);
}

function form(fields: Record<string, string | undefined>): Pick<LabRequest, "headers" | "body"> {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined) params.set(key, value);
  }
  return { headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: params.toString() };
}

function post(path: string, fields: Record<string, string | undefined>): LabRequest {
  return { method: "POST", path, ...form(fields) };
}

function multipart(filename: string, contentType: string, content: string): Pick<LabRequest, "headers" | "body"> {
  const boundary = `HackLab${crypto.randomUUID()}`;
  const body = [
    `--${boundary}`,
    `Content-Disposition: form-data; name="file"; filename="${filename.replace(/"/g, "")}"`,
    `Content-Type: ${contentType || "application/octet-stream"}`,
    "",
    content,
    `--${boundary}--`,
    "",
  ].join("\r\n");
  return { headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` }, body };
}

/** Build the HTTP request for one attempt. Level comes from the selector, not the payload. */
export function buildLabRequest(labId: string, level: Level, input: LabInput): LabRequest {
  const lv = `/lv${level}`;
  switch (labId) {
    case "sqli":
      return post(`/sqli${lv}/login`, {
        username: input.username ?? "",
        password: input.password ?? "",
        ...(input.id !== undefined ? { id: input.id } : {}),
        ...(input.role !== undefined ? { role: input.role } : {}),
      });
    case "xss":
      return post(`/xss${lv}/comment`, { comment: input.comment ?? "" });
    case "cmdi":
      return post(`/cmdi${lv}/ping`, { host: input.host ?? "" });
    case "path":
      return { method: "GET", path: `/path${lv}/files?path=${encodeURIComponent(input.name ?? "")}`, headers: {} };
    case "csrf":
      return post(`/csrf${lv}/page`, { html: input.html ?? "" });
    case "auth":
      return post(`/auth${lv}/login`, {
        username: input.username ?? "",
        password: input.password ?? "",
        sessionId: input.sessionId ?? "",
        mfaCode: input.mfaCode ?? "",
      });
    case "ssrf":
      return post(`/ssrf${lv}/fetch`, { url: input.url ?? "" });
    case "upload":
      return {
        method: "POST",
        path: `/upload${lv}/avatar`,
        ...multipart(input.filename ?? "upload.bin", input.contentType ?? "application/octet-stream", input.content ?? ""),
      };
    case "crypto":
      return post(`/crypto${lv}/open`, { action: input.action ?? "mine", token: input.token ?? "" });
    case "misconf":
      return { method: "GET", path: `/misconf${lv}/page?path=${encodeURIComponent(input.path ?? "/")}`, headers: {} };
    case "deps":
      return post(`/deps${lv}/thumb`, { file: input.file ?? "logo.png", engine: input.engine ?? "current" });
    case "integrity":
      return post(`/integrity${lv}/apply`, { manifest: input.manifest ?? "", signature: input.signature ?? "" });
    case "logging":
      return post(`/logging${lv}/act`, { user: input.user ?? "", action: input.action ?? "view", op: input.op ?? "" });
    case "jwt":
      return {
        method: "GET",
        path: `/jwt${lv}/admin`,
        headers: { Authorization: `Bearer ${(input.token ?? "").replace(/\s+/g, "")}` },
      };
    case "idor": {
      const endpoint = input.endpoint ?? "/api/orders";
      const owner = input.owner ?? "alice";
      const role = input.role ?? "user";
      const orderId = input.orderId ?? "";
      if (endpoint.includes("graphql")) {
        return post(`/idor${lv}/graphql`, { query: input.query ?? "", orderId, owner, role });
      }
      if (endpoint.includes("export")) {
        const q = new URLSearchParams({ id: orderId, owner, role });
        return { method: "GET", path: `/idor${lv}/api/export?${q}`, headers: {} };
      }
      const q = new URLSearchParams({ owner, role });
      return { method: "GET", path: `/idor${lv}/api/orders/${encodeURIComponent(orderId)}?${q}`, headers: {} };
    }
    default:
      return post(`/${labId}${lv}`, input);
  }
}

export function formatRawRequest(req: LabRequest): string {
  const lines = [`${req.method} ${req.path} HTTP/1.1`, "Host: lab-server"];
  for (const [key, value] of Object.entries(req.headers)) lines.push(`${key}: ${value}`);
  if (req.body !== undefined) lines.push("", req.body);
  return lines.join("\n");
}

export function formatRawResponse(res: HttpResponse): string {
  const lines = [`HTTP/1.1 ${res.status}`];
  for (const [key, value] of res.headers) lines.push(`${key}: ${value}`);
  lines.push("", res.body);
  return lines.join("\n");
}

export async function executeLabRequest(apiBase: string, req: LabRequest): Promise<HttpResponse> {
  const res = await fetch(`${apiBase.replace(/\/$/, "")}${req.path}`, {
    method: req.method,
    headers: req.headers,
    body: req.method === "GET" ? undefined : req.body,
  });
  const headers: [string, string][] = [];
  res.headers.forEach((value, key) => headers.push([key, value]));
  return { status: res.status, headers, body: await res.text() };
}

function header(res: HttpResponse, name: string): string | undefined {
  const found = res.headers.find(([key]) => key.toLowerCase() === name.toLowerCase());
  return found?.[1];
}

function linesOf(body: string): string[] {
  return body.split("\n");
}

function sqliRows(body: string): { username: string; role: string }[] {
  const rows: { username: string; role: string }[] = [];
  for (const line of body.split("\n")) {
    const match = /^\s+(\S+)\s+\((.*)\)\s*$/.exec(line);
    if (match) rows.push({ username: match[1], role: match[2] });
  }
  return rows;
}

function judgeSqli(level: Level, input: LabInput, res: HttpResponse): AttackResult {
  const output = linesOf(res.body);
  const assembled = output.find((line) => line.startsWith("SELECT "));
  if (res.body.includes("SQL ERROR")) {
    return { solved: false, output, assembled, note: "組み立てたクエリが DB に拒否されました。構文として成立する注入を考えましょう。" };
  }
  const rows = sqliRows(res.body);
  const legit = SQLI_ACCOUNTS.some((u) => u.username === (input.username ?? "") && u.password === (input.password ?? ""));
  if (level === 4 || level === 5) {
    const leaked: LootItem[] = rows
      .map((row) => SQLI_ACCOUNTS.find((u) => u.username === row.username && u.password === row.role))
      .filter((u): u is (typeof SQLI_ACCOUNTS)[number] => u !== undefined)
      .map((u) => ({ id: `sqli-pass-${u.username}`, label: `${u.username} のパスワード`, value: u.password }));
    const solved = leaked.length > 0;
    return {
      solved,
      output,
      assembled,
      loot: solved ? leaked : undefined,
      benign: rows.length > 0 && !solved && legit,
      progress: rows.length > 0 && !solved && !legit,
      note: solved
        ? "UNION SELECT でパスワード列を奪いました。"
        : rows.length === 0
          ? level === 5
            ? "入力は値として扱われたため、クエリ構造は一切変化しませんでした。"
            : "role の条件に合う行がありません。"
          : legit
            ? "正規の資格情報でのログインです（インジェクションではありません）。"
            : level === 5
              ? "入力は値として扱われたため、クエリ構造は一切変化しませんでした。"
              : "ログインは通りましたが、Lv4 の目標はテーブルの中身です。",
    };
  }
  const asAdmin = rows.some((row) => row.username === "admin" && row.role === "administrator");
  const solved = asAdmin && !legit;
  return {
    solved,
    output,
    assembled,
    benign: rows.length > 0 && legit,
    progress: rows.length > 0 && !legit && !asAdmin,
    note: rows.length === 0
      ? "ログイン失敗。該当ユーザーなし。"
      : solved
        ? "admin としてログイン成功。認証をバイパスしました。"
        : legit
          ? "正規の資格情報です（インジェクションではありません）。"
          : "ログインはできましたが admin ではありません。admin 行を返させましょう。",
  };
}

function mfaCode(res: HttpResponse): string | undefined {
  const fromHeader = header(res, "x-debug-mail") ?? "";
  const fromBody = res.body.match(/X-Debug-Mail: ([^\n]+)/)?.[1] ?? "";
  return /(?:^|\s)(\d{6})\s*$/.exec(fromHeader)?.[1] ?? /(?:^|\s)(\d{6})\s*$/.exec(fromBody)?.[1];
}

function judgeAuth(res: HttpResponse): AttackResult {
  const output = linesOf(res.body);
  const solved = res.body.includes("管理コンソール / admin");
  const code = solved ? undefined : mfaCode(res);
  return {
    solved,
    output,
    progress: !!code,
    loot: code ? [{ id: "auth-mfa", label: "MFA コード", value: code }] : undefined,
    note: solved ? "admin アカウントのセッションを取得しました。" : code ? "パスワードは正しいですが MFA が必要です。" : "認証に失敗しました。",
  };
}

function b64url(value: string): string {
  try {
    const pad = value.length % 4 === 0 ? "" : "=".repeat(4 - (value.length % 4));
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + pad);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return value;
  }
}

/** Read a real HTTP response back into the workbench's result shape. */
export function judgeLabResponse(labId: string, level: Level, input: LabInput, res: HttpResponse): AttackResult {
  const output = linesOf(res.body);

  if (labId === "sqli") return judgeSqli(level, input, res);

  if (labId === "xss") {
    const solved = htmlFires(res.body);
    return {
      solved,
      output: ["-- サーバーが生成した HTML（コメント部分）", res.body],
      renderHtml: res.body,
      assembled: res.body,
      note: solved ? "プレビューでスクリプトが動くか確認してください。" : "注入は無害化されました。別のコンテキストを探しましょう。",
    };
  }

  if (labId === "cmdi") {
    const solved = res.body.includes(CMDI_FLAG);
    return {
      solved,
      output,
      loot: solved ? [{ id: "cmdi-flag", label: "flag.txt", value: CMDI_FLAG }] : undefined,
      note: solved ? "注入したコマンドが実行され、flag.txt を読み出しました。" : "注入は失敗しました。ping しか実行されていません。",
    };
  }

  if (labId === "path") {
    const hasFlag = res.body.includes(PATH_FLAG);
    const hasPasswd = res.body.includes(PASSWD_MARK);
    const solved = level < 4 ? hasPasswd : hasFlag;
    const progress = !solved && (res.body.includes("機密バックアップ") || (level >= 4 && hasPasswd));
    return {
      solved,
      output,
      progress,
      loot: hasFlag ? [{ id: "path-flag", label: "flag.txt", value: PATH_FLAG }] : undefined,
      note: solved ? "ベースディレクトリを脱出し、秘密ファイルを読み出しました。" : progress ? "ファイルは読めましたが、目標ではありません。" : "そのパスにファイルはありません。",
    };
  }

  if (labId === "csrf") {
    const solved = res.body.includes("円を送金しました");
    return {
      solved,
      output,
      note: solved ? "被害者のブラウザ経由で不正送金が成立しました。" : "送金はブロックされました。防御を回避する手口を考えましょう。",
    };
  }

  if (labId === "idor") {
    const solved = /Bob \//.test(res.body);
    const related = /related_order: (\S+)/.exec(res.body)?.[1];
    const introspection = res.body.includes("type Query");
    return {
      solved,
      output,
      progress: !solved && (!!related || introspection),
      benign: !solved && res.body.includes("Alice /") && !related,
      loot: related ? [{ id: "idor-related", label: "Bob の注文 ID", value: related }] : undefined,
      note: solved ? "他人の注文情報へアクセスできました。" : related ? "自分の注文です。応答の関連フィールドを確認してください。" : "注文が見つからないか、権限がありません。",
    };
  }

  if (labId === "auth") return judgeAuth(res);

  if (labId === "jwt") {
    const solved = res.body.includes("[200 OK] /admin");
    const benign = res.body.includes("[403 FORBIDDEN]");
    const key = /"k"\s*:\s*"([^"]+)"/.exec(res.body)?.[1];
    const decoded = key ? b64url(key) : undefined;
    return {
      solved,
      output,
      benign,
      progress: !solved && !benign && !!decoded,
      loot: decoded ? [{ id: "jwt-oct", label: "JWKS oct 鍵 (decoded)", value: decoded }] : undefined,
      note: solved ? "改ざんした JWT で管理者権限を取得しました。" : benign ? "alice のトークンとして認識しました。この API は管理者専用です。" : "署名を検証できるトークンではありません。",
    };
  }

  if (labId === "ssrf") {
    const key = /access-key=(\S+)/.exec(res.body)?.[1];
    const solved = !!key;
    const progress = !solved && res.body.includes("X-Debug-Link:");
    return {
      solved,
      output,
      progress,
      benign: !solved && !progress && res.status === 200 && !res.body.includes("[403]") && !res.body.includes("ERROR:"),
      loot: key ? [{ id: "ssrf-access-key", label: "メタデータ access-key", value: key }] : undefined,
      note: solved ? "サーバーから内部サービスへリクエストを送信できました。" : "内部メタデータには到達していません。",
    };
  }

  if (labId === "upload") {
    const solved = res.body.includes("X-Handler: php (uid=www-data");
    return {
      solved,
      output,
      note: solved ? "アップロードした内容がサーバー側コードとして実行されました。" : "保存された内容は実行されません。",
    };
  }

  if (labId === "crypto") {
    const solved = exactLine(res.body, `card=${PAN}`);
    return {
      solved,
      output,
      benign: !solved && res.body.includes("************4242"),
      loot: solved ? [{ id: "crypto-pan", label: "カード番号", value: PAN }] : undefined,
      note: solved ? "弱い暗号（または符号化）が解け、カード番号が出ました。" : "このトークンはこのレベルの方式では開きません。",
    };
  }

  if (labId === "misconf") {
    const solved = exactLine(res.body, MISCONF_FLAG);
    return {
      solved,
      output,
      benign: !solved && res.body.includes("Welcome"),
      loot: solved ? [{ id: "misconf-flag", label: "設定の秘密", value: MISCONF_FLAG }] : undefined,
      note: solved ? "本番に残った入口から設定の秘密が返りました。" : "そのパスは秘密を返しません。",
    };
  }

  if (labId === "deps") {
    const solved = exactLine(res.body, DEPS_FLAG);
    return {
      solved,
      output,
      benign: !solved && res.body.includes("PNG logo"),
      loot: solved ? [{ id: "deps-flag", label: "コンポーネントの秘密", value: DEPS_FLAG }] : undefined,
      note: solved ? "古いコンポーネントの解釈で秘密ファイルが返りました。" : "そのファイルは返していません。",
    };
  }

  if (labId === "integrity") {
    const solved = exactLine(res.body, INTEGRITY_FLAG);
    return {
      solved,
      output,
      benign: !solved && exactLine(res.body, "role=user"),
      loot: solved ? [{ id: "integrity-flag", label: "適用された更新", value: INTEGRITY_FLAG }] : undefined,
      note: solved ? "role=admin の更新を受け入れました。" : "admin としての更新は適用されていません。",
    };
  }

  if (labId === "logging") {
    const solved = header(res, "x-export") === "accepted";
    return {
      solved,
      output,
      benign: !solved && (res.body.includes("action=view") || res.body.includes('"action":"view"')),
      loot: solved ? [{ id: "logging-flag", label: "記録の穴", value: LOGGING_FLAG }] : undefined,
      note: solved ? "監視が見る記録と、実際の操作がずれました。" : "監視は実行した操作をそのまま見ています。",
    };
  }

  return { solved: false, output, note: "このラボの応答を判定できません。" };
}
