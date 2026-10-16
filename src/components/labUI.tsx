import { useEffect, useState, type ReactNode } from "react";
import { decodeJwtPart, makeJwt } from "../labs/jwt";
import type { AttackResult, LabInput, Level } from "../labs/types";
import { XssPreview } from "./XssPreview";

/** Context handed to each lab's target-app renderer. */
export interface AppCtx {
  inputs: LabInput;
  setField: (name: string, value: string) => void;
  /** Interact with the app the "normal" way (login, post, ping, …). */
  submit: (patch?: LabInput) => void;
  result: AttackResult | null;
  succeeded: boolean;
  runId: number;
  onFire: (message: string) => void;
  level: Level;
}

export interface LabUI {
  /** Address shown in the fake browser's omnibox. */
  url: string;
  /** Tab/site title. */
  site: string;
  /** Build the raw HTTP request preview lines for the proxy. */
  request: (inputs: LabInput) => string[];
  /** Render the interactive target application inside the browser viewport. */
  renderApp: (ctx: AppCtx) => ReactNode;
}

const money = (n: number) => "¥" + n.toLocaleString("ja-JP");

const sqli: LabUI = {
  url: "https://securebank.example/admin/login",
  site: "SecureBank 管理コンソール",
  request: (i) => [
    "POST /admin/login HTTP/1.1",
    "Host: securebank.example",
    "Content-Type: application/x-www-form-urlencoded",
    "",
    `username=${i.username ?? ""}&password=${i.password ?? ""}`,
  ],
  renderApp: ({ inputs, setField, submit, result, succeeded }) => {
    if (succeeded) {
      return (
        <div className="app-screen">
          <div className="app-badge ok">管理者としてログイン中</div>
          <h2 className="app-h">管理ダッシュボード</h2>
          <p className="app-p">ようこそ、admin さん。全ユーザーの口座を操作できます。</p>
          <table className="app-table">
            <tbody>
              <tr><td>総残高</td><td className="mono">{money(84213900)}</td></tr>
              <tr><td>登録ユーザー</td><td className="mono">3</td></tr>
              <tr><td>権限</td><td className="mono">administrator</td></tr>
            </tbody>
          </table>
        </div>
      );
    }
    return (
      <div className="app-login">
        <div className="app-brand">SecureBank</div>
        <h2 className="app-h">管理者ログイン</h2>
        <form
          className="app-form"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <label>
            ユーザー名
            <input
              className="mono"
              value={inputs.username ?? ""}
              onChange={(e) => setField("username", e.target.value)}
              autoComplete="off"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
            />
          </label>
          <label>
            パスワード
            <input
              className="mono"
              type="text"
              value={inputs.password ?? ""}
              onChange={(e) => setField("password", e.target.value)}
              autoComplete="off"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
            />
          </label>
          <button type="submit" className="app-btn">ログイン</button>
        </form>
        {result && !succeeded && <div className="app-alert">ユーザー名またはパスワードが違います。</div>}
      </div>
    );
  },
};

const xss: LabUI = {
  url: "https://notes.example/guestbook",
  site: "みんなのゲストブック",
  request: (i) => [
    "POST /guestbook HTTP/1.1",
    "Host: notes.example",
    "Content-Type: application/x-www-form-urlencoded",
    "",
    `comment=${i.comment ?? ""}`,
  ],
  renderApp: ({ inputs, setField, submit, result, runId, onFire }) => (
    <div className="app-screen">
      <h2 className="app-h">みんなのゲストブック</h2>
      <form
        className="app-form"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <label>
          コメント
          <textarea
            className="mono"
            rows={3}
            value={inputs.comment ?? ""}
            onChange={(e) => setField("comment", e.target.value)}
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
          />
        </label>
        <button type="submit" className="app-btn">投稿する</button>
      </form>
      <div className="app-sub">投稿結果（このページ内で描画されます）</div>
      {result?.renderHtml !== undefined ? (
        <XssPreview html={result.renderHtml} runId={runId} onFire={onFire} />
      ) : (
        <div className="app-empty">まだ投稿がありません。</div>
      )}
    </div>
  ),
};

const cmdi: LabUI = {
  url: "https://router.example/tools/ping",
  site: "ネットワーク診断ツール",
  request: (i) => [
    "POST /tools/ping HTTP/1.1",
    "Host: router.example",
    "Content-Type: application/x-www-form-urlencoded",
    "",
    `host=${(i.host ?? "").replace(/\n/g, "%0A")}`,
  ],
  renderApp: ({ inputs, setField, submit, result }) => (
    <div className="app-screen">
      <div className="app-brand">RouterOS 診断</div>
      <h2 className="app-h">到達性テスト (ping)</h2>
      <form
        className="app-form"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <label>
          ホスト名 / IP アドレス
          <textarea
            className="mono"
            rows={2}
            value={inputs.host ?? ""}
            onChange={(e) => setField("host", e.target.value)}
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
          />
        </label>
        <button type="submit" className="app-btn">Ping 実行</button>
      </form>
      {result && <pre className="app-term">{result.output.join("\n")}</pre>}
    </div>
  ),
};

const path: LabUI = {
  url: "https://docs.example/view",
  site: "ドキュメントビューア",
  request: (i) => [
    `GET /view?name=${encodeURIComponent(i.name ?? "")} HTTP/1.1`,
    "Host: docs.example",
  ],
  renderApp: ({ inputs, setField, submit, result, succeeded }) => (
    <div className="app-screen">
      <div className="app-brand">社内ドキュメント</div>
      <div className="app-files">
        {["readme.txt", "notice.txt"].map((f) => (
          <button
            key={f}
            type="button"
            className="app-file"
            onClick={() => {
              submit({ name: f });
            }}
          >
            {f}
          </button>
        ))}
      </div>
      <form
        className="app-form row"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <input
          className="mono"
          value={inputs.name ?? ""}
          onChange={(e) => setField("name", e.target.value)}
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          autoComplete="off"
        />
        <button type="submit" className="app-btn">開く</button>
      </form>
      {result && (
        <div className={`app-doc ${succeeded ? "leaked" : ""}`}>
          <div className="app-doc-head mono">{inputs.name}</div>
          <pre>{result.output[result.output.length - 1]}</pre>
        </div>
      )}
    </div>
  ),
};

const csrf: LabUI = {
  url: "https://evil.example/cute-kittens",
  site: "攻撃者のページ",
  request: (i) => {
    const html = i.html ?? "";
    return [
      "<!-- 被害者 (bank.example にログイン済み) が開く罠ページ -->",
      "GET https://evil.example/cute-kittens",
      "",
      ...html.split("\n"),
    ];
  },
  renderApp: ({ inputs, setField, submit, result, succeeded }) => {
    const base = 1_000_000;
    const amount = Number((inputs.html ?? "").match(/amount[^0-9<>]{0,20}(\d+)/)?.[1] ?? 0);
    const balance = succeeded ? base - amount : base;
    return (
      <div className="app-split">
        <div className="app-pane">
          <div className="app-pane-tab">bank.example（被害者のタブ）</div>
          <div className="app-screen tight">
            <div className="app-badge ok">victim としてログイン中</div>
            <div className="app-balance">
              <span>口座残高</span>
              <strong className={succeeded ? "drained" : ""}>{money(balance)}</strong>
            </div>
            {succeeded && <div className="app-alert warn">{money(amount)} が attacker へ送金されました。</div>}
          </div>
        </div>
        <div className="app-pane">
          <div className="app-pane-tab">evil.example（あなたが作る罠ページ）</div>
          <div className="app-screen tight">
            <label className="app-field">
              罠ページの HTML
              <textarea
                className="mono"
                rows={6}
                value={inputs.html ?? ""}
                onChange={(e) => setField("html", e.target.value)}
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
              />
            </label>
            <button type="button" className="app-btn" onClick={() => submit()}>
              被害者がこのページを開く ▶
            </button>
            {result && !succeeded && <div className="app-alert">送金は実行されませんでした。</div>}
          </div>
        </div>
      </div>
    );
  },
};

const idor: LabUI = {
  url: "https://shop.example/orders/1001",
  site: "HackLab Store — 注文履歴",
  request: (i) => [
    `GET ${(i.endpoint ?? "/api/orders")}${(i.endpoint ?? "").includes(i.orderId ?? "___") ? "" : `/${i.orderId ?? ""}`}?owner=${i.owner ?? ""} HTTP/1.1`,
    "Host: shop.example",
    "Cookie: session=alice-session",
    `X-User-Role: ${i.role ?? "user"}`,
  ],
  renderApp: ({ submit, result, succeeded }) => (
    <div className="app-screen">
      <div className="app-badge ok">alice としてログイン中</div>
      <h2 className="app-h">注文履歴</h2>
      <p className="app-p">自分の注文だけが表示されます。owner や role の改ざんは Proxy で行います。</p>
      <table className="app-table">
        <thead>
          <tr>
            <th>注文 ID</th>
            <th>商品</th>
            <th>金額</th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr>
            <td className="mono">1001</td>
            <td>USB-C ケーブル</td>
            <td className="mono">{money(2480)}</td>
            <td>
              <button type="button" className="app-btn" onClick={() => submit({ orderId: "1001" })}>
                表示
              </button>
            </td>
          </tr>
        </tbody>
      </table>
      {result && (
        <div className={`app-doc ${succeeded ? "leaked" : ""}`}>
          <div className="app-doc-head mono">{succeeded ? "取得した注文（越権）" : "取得結果"}</div>
          <pre>{result.output.join("\n")}</pre>
        </div>
      )}
    </div>
  ),
};

function AuthApp({ inputs, setField, submit, result, succeeded, level }: AppCtx) {
  const [tries, setTries] = useState(0);
  const showMfa = level >= 4;
  return (
    <div className="app-login">
      <div className="app-brand">CorpID</div>
      <h2 className="app-h">{succeeded ? "管理コンソール" : "アカウントにログイン"}</h2>
      {succeeded ? (
        <div className="app-badge ok">admin としてログイン中</div>
      ) : (
        <form
          className="app-form"
          onSubmit={(e) => {
            e.preventDefault();
            setTries((n) => n + 1);
            submit();
          }}
        >
          <label>
            ユーザー名
            <input className="mono" value={inputs.username ?? ""} onChange={(e) => setField("username", e.target.value)} autoComplete="off" />
          </label>
          <label>
            パスワード
            <input className="mono" type="text" value={inputs.password ?? ""} onChange={(e) => setField("password", e.target.value)} autoComplete="off" />
          </label>
          {showMfa && (
            <label>
              MFA コード
              <input className="mono" value={inputs.mfaCode ?? ""} onChange={(e) => setField("mfaCode", e.target.value)} autoComplete="off" />
            </label>
          )}
          <button type="submit" className="app-btn">ログイン</button>
        </form>
      )}
      {result && !succeeded && (
        <div className="app-alert">
          {result.note ?? "認証できませんでした。"}
          {level <= 2 && tries >= 3 && (
            <div className="app-alert-extra">この IP からの連続試行です。アカウント単位の制限はありません。</div>
          )}
        </div>
      )}
    </div>
  );
}

const auth: LabUI = {
  url: "https://accounts.example/login",
  site: "CorpID — ログイン",
  request: (i) => [
    "POST /login HTTP/1.1",
    "Host: accounts.example",
    `Cookie: session=${i.sessionId ?? ""}`,
    "Content-Type: application/x-www-form-urlencoded",
    "",
    `username=${i.username ?? ""}&password=${i.password ?? ""}&mfa=${i.mfaCode ?? ""}`,
  ],
  renderApp: (ctx) => <AuthApp {...ctx} />,
};

function prettyJwtPart(part: string): string {
  const decoded = decodeJwtPart(part);
  return decoded ? JSON.stringify(decoded, null, 2) : "";
}

function JwtApp({ inputs, setField, submit, result, succeeded }: AppCtx) {
  const token = inputs.token ?? "";
  const [headerText, setHeaderText] = useState("");
  const [payloadText, setPayloadText] = useState("");
  const [signature, setSignature] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);

  useEffect(() => {
    const [head = "", body = "", sig = ""] = token.split(".");
    setHeaderText(prettyJwtPart(head) || head);
    setPayloadText(prettyJwtPart(body) || body);
    setSignature(sig);
    setParseError(null);
  }, [token]);

  const assemble = (): string | null => {
    try {
      const header = JSON.parse(headerText) as object;
      const payload = JSON.parse(payloadText) as object;
      const next = makeJwt(header, payload, signature);
      setField("token", next);
      setParseError(null);
      return next;
    } catch {
      setParseError("header / payload は JSON で入力してください。");
      return null;
    }
  };

  return (
    <div className="app-screen">
      <div className="app-brand">API Console</div>
      <h2 className="app-h">管理者 API</h2>
      <p className="app-p">JWT は署名付きの JSON です。header と payload は誰でも読めます。組み立ててから送信します。</p>
      <div className="jwt-grid">
        <label className="app-field">
          header
          <textarea className="mono" rows={6} aria-label="JWT header" value={headerText} onChange={(e) => setHeaderText(e.target.value)} spellCheck={false} />
        </label>
        <label className="app-field">
          payload
          <textarea className="mono" rows={6} aria-label="JWT payload" value={payloadText} onChange={(e) => setPayloadText(e.target.value)} spellCheck={false} />
        </label>
      </div>
      <label className="app-field">
        signature
        <input className="mono" aria-label="JWT signature" value={signature} onChange={(e) => setSignature(e.target.value)} autoComplete="off" />
      </label>
      <label className="app-field">
        生トークン
        <textarea
          className="mono"
          rows={3}
          aria-label="raw JWT"
          value={token}
          onChange={(e) => setField("token", e.target.value)}
          spellCheck={false}
        />
      </label>
      <div className="app-actions">
        <button type="button" className="app-btn" onClick={() => assemble()}>
          トークンを組み立てる
        </button>
        <button
          type="button"
          className="app-btn"
          onClick={() => {
            const next = assemble();
            if (next) submit({ token: next });
          }}
        >
          GET /admin
        </button>
      </div>
      {parseError && <div className="app-alert">{parseError}</div>}
      {result && <pre className={`app-term ${succeeded ? "leaked" : ""}`}>{result.output.join("\n")}</pre>}
    </div>
  );
}

const jwt: LabUI = {
  url: "https://api.example/admin",
  site: "API Console — JWT",
  request: (i) => [
    "GET /admin HTTP/1.1",
    "Host: api.example",
    `Authorization: Bearer ${i.token ?? ""}`,
  ],
  renderApp: (ctx) => <JwtApp {...ctx} />,
};

const ssrf: LabUI = {
  url: "https://media.example/fetch",
  site: "Media Fetcher",
  request: (i) => [
    "POST /api/fetch HTTP/1.1",
    "Host: media.example",
    "Content-Type: application/json",
    "",
    JSON.stringify({ url: i.url ?? "" }),
  ],
  renderApp: ({ inputs, setField, submit, result, succeeded }) => (
    <div className="app-screen">
      <div className="app-brand">Media Fetcher</div>
      <h2 className="app-h">URL から画像を取得</h2>
      <form className="app-form row" onSubmit={(e) => { e.preventDefault(); submit(); }}>
        <input className="mono" aria-label="取得する URL" value={inputs.url ?? ""} onChange={(e) => setField("url", e.target.value)} />
        <button type="submit" className="app-btn">取得</button>
      </form>
      {result && (
        <div className={`app-doc ${succeeded ? "leaked" : ""}`}>
          <div className="app-doc-head">{succeeded ? "内部レスポンス" : "取得結果"}</div>
          <pre>{result.output.join("\n")}</pre>
        </div>
      )}
    </div>
  ),
};

const upload: LabUI = {
  url: "https://profile.example/settings/avatar",
  site: "Profile — アバター設定",
  request: (i) => [
    "POST /api/avatar HTTP/1.1",
    "Host: profile.example",
    `Content-Type: multipart/form-data; boundary=hacklab`,
    "",
    `Content-Disposition: form-data; name="avatar"; filename="${i.filename ?? ""}"`,
    `Content-Type: ${i.contentType ?? ""}`,
    "",
    i.content ?? "",
  ],
  renderApp: ({ inputs, setField, submit, result, succeeded }) => (
    <div className="app-screen">
      <div className="app-brand">Profile</div>
      <h2 className="app-h">アバター画像の変更</h2>
      <p className="app-p">画面ではファイル名と内容だけ指定します。Content-Type の改ざんは Proxy で行います。</p>
      <form className="app-form" onSubmit={(e) => { e.preventDefault(); submit(); }}>
        <div className="upload-drop">
          <span className="upload-drop-label">選択中のファイル</span>
          <label>
            ファイル名
            <input className="mono" value={inputs.filename ?? ""} onChange={(e) => setField("filename", e.target.value)} autoComplete="off" />
          </label>
        </div>
        <label>
          ファイル内容
          <textarea className="mono" rows={4} value={inputs.content ?? ""} onChange={(e) => setField("content", e.target.value)} spellCheck={false} />
        </label>
        <button type="submit" className="app-btn">アップロード</button>
      </form>
      {result && (
        <div className={`app-alert ${succeeded ? "warn" : ""}`}>
          {succeeded ? "危険なファイルが実行されました。" : "安全に処理されました。"}
        </div>
      )}
    </div>
  ),
};

export const LAB_UI: Record<string, LabUI> = {
  sqli,
  xss,
  cmdi,
  path,
  csrf,
  idor,
  auth,
  jwt,
  ssrf,
  upload,
};
